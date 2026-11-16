// SobPass — LLVM module pass: string/constant obfuscation.
//
// XOR-encrypts every string-literal global ([N x i8] constant) in place, then
// inserts an unrolled per-byte decode sequence before every use, so the plaintext
// never appears in the output file's read-only data section.
//
// Module pass: string literals are module-scope globals, potentially shared across
// multiple functions.
//
// The XOR key global (@sob.key) is declared non-constant so the compiler's constant
// folder cannot fold a load of it at compile time and simplify the XOR back to the
// plaintext.  Declaring it `constant` would allow InstCombine (and the backend's own
// peephole folder) to prove the loaded byte at compile time and eliminate the decode.
//
// Limitations:
//   - Only ConstantDataArray globals where isString() is true are processed.
//   - A global is skipped if any use is not inside an instruction (e.g. it appears
//     in another global's initializer), since there is no instruction to anchor a
//     decode sequence to.
//   - Every use site gets its own independent decode sequence.
//
// Pass name: "sob"   Unit: Module

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

static const uint8_t kKey[] = {0x5A, 0xC3, 0x18, 0x7E};

// True if G is a clang-style string-literal global: a constant [N x i8] with
// string data.
bool isStringLiteralGlobal(GlobalVariable &G) {
    if (!G.hasInitializer() || !G.isConstant())
        return false;
    auto *data = dyn_cast<ConstantDataArray>(G.getInitializer());
    return data && data->isString();
}

// True only if every use of G sits inside an instruction (not in another
// global's initializer), so a decode sequence can be inserted before each use.
bool allUsesAreInstructions(GlobalVariable &G) {
    for (Use &U : G.uses()) {
        if (!isa<Instruction>(U.getUser()))
            return false;
    }
    return true;
}

// Creates @sob.key once per module.  NOT `constant` — see file header.
GlobalVariable *getOrCreateKey(Module &M) {
    if (auto *existing = M.getGlobalVariable("sob.key"))
        return existing;

    LLVMContext &ctx = M.getContext();
    auto *init = ConstantDataArray::get(ctx, ArrayRef<uint8_t>(kKey, sizeof(kKey)));
    return new GlobalVariable(M, init->getType(), /*isConstant=*/false, GlobalValue::PrivateLinkage,
                               init, "sob.key");
}

// Encrypts G's initializer in place, then inserts a decode sequence before
// every instruction that uses G.
void obfuscateGlobal(Module &M, GlobalVariable &G, GlobalVariable *keyGV) {
    auto *data = cast<ConstantDataArray>(G.getInitializer());
    unsigned n = data->getNumElements();
    LLVMContext &ctx = M.getContext();
    Type *i8Ty = Type::getInt8Ty(ctx);
    ArrayType *bufTy = ArrayType::get(i8Ty, n);

    // 1. XOR every byte of G's initializer; write the ciphertext back in place.
    SmallVector<uint8_t, 32> cipher(n);
    for (unsigned i = 0; i < n; i++)
        cipher[i] = static_cast<uint8_t>(data->getElementAsInteger(i)) ^ kKey[i % sizeof(kKey)];
    G.setInitializer(ConstantDataArray::get(ctx, cipher));

    // 2. Insert an independent decode sequence before each use.
    //    make_early_inc_range: U.set() below relinks U away from G's use-list.
    for (Use &U : make_early_inc_range(G.uses())) {
        auto *user = cast<Instruction>(U.getUser());
        IRBuilder<> builder(user);

        auto *buf = builder.CreateAlloca(bufTy, nullptr, "sob.buf");
        for (unsigned i = 0; i < n; i++) {
            auto *encPtr = builder.CreateConstInBoundsGEP2_32(bufTy, &G, 0, i, "sob.enc.ptr");
            auto *encByte = builder.CreateLoad(i8Ty, encPtr, "sob.enc.byte");
            auto *keyPtr = builder.CreateConstInBoundsGEP2_32(keyGV->getValueType(), keyGV, 0,
                                                               i % sizeof(kKey), "sob.key.ptr");
            auto *keyByte = builder.CreateLoad(i8Ty, keyPtr, "sob.key.byte");
            auto *plainByte = builder.CreateXor(encByte, keyByte, "sob.plain.byte");
            auto *dstPtr = builder.CreateConstInBoundsGEP2_32(bufTy, buf, 0, i, "sob.buf.ptr");
            builder.CreateStore(plainByte, dstPtr);
        }

        // 3. Redirect this one use to the decoded buffer.
        U.set(buf);
    }
}

// unit: the whole Module
struct SobPass : PassInfoMixin<SobPass> {
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
        // Collect targets before mutating: obfuscateGlobal rewires G's use-list
        // and may create @sob.key.
        SmallVector<GlobalVariable *, 8> targets;
        for (GlobalVariable &G : M.globals()) {
            if (isStringLiteralGlobal(G) && allUsesAreInstructions(G))
                targets.push_back(&G);
        }

        GlobalVariable *keyGV = nullptr;
        for (GlobalVariable *G : targets) {
            if (!keyGV)
                keyGV = getOrCreateKey(M);
            obfuscateGlobal(M, *G, keyGV);
        }

        errs() << "[sob] " << M.getName() << ": obfuscated " << targets.size() << " string literal(s)\n";
        if (targets.empty())
            return PreservedAnalyses::all();

        return PreservedAnalyses::none();
    }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "SobPass", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                PB.registerPipelineParsingCallback(
                    [](StringRef name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
                        if (name == "sob") {
                            MPM.addPass(SobPass());
                            return true;
                        }
                        return false;
                    });
            }};
}
