// BcfPass — LLVM function pass: bogus control-flow obfuscation.
//
// For each eligible basic block, inserts a dead "bogus" block guarded by an
// opaque predicate: x*(x+1) is always even, so (x*(x+1)) & 1 == 0 is always
// true and the bogus path is never taken at runtime.  A static reader sees an
// enlarged CFG; execution behavior is unchanged.
//
// Eligibility: an unconditional branch to a PHI-free, non-self successor.
// Blocks whose successor has PHI nodes require patching the incoming-value
// lists for the new predecessor edge, which is out of scope here.
//
// Pass name: "bcf"   Unit: Function

#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

// Returns a runtime integer value for the opaque predicate: the first integer
// argument of F cast to i32, or the constant 42 as a fallback.
Value *findSeed(Function &F, IRBuilder<> &builder) {
    for (Argument &arg : F.args()) {
        if (arg.getType()->isIntegerTy())
            return builder.CreateIntCast(&arg, builder.getInt32Ty(), /*isSigned=*/false, "bcf.seed");
    }
    return builder.getInt32(42);
}

// Returns BB's unconditional, PHI-free, non-self successor, or nullptr.
BasicBlock *eligibleSuccessor(BasicBlock &BB) {
    auto *br = dyn_cast<BranchInst>(BB.getTerminator());
    if (!br || br->isConditional())
        return nullptr;

    BasicBlock *succ = br->getSuccessor(0);
    if (succ == &BB)
        return nullptr;
    if (isa<PHINode>(succ->front()))
        return nullptr;

    return succ;
}

// Inserts a dead bogus block between BB and its successor.
void diverge(Function &F, BasicBlock &BB) {
    auto *br = cast<BranchInst>(BB.getTerminator());
    BasicBlock *succ = br->getSuccessor(0);

    IRBuilder<> builder(br);

    // Opaque predicate: x*(x+1) & 1 == 0, always true.
    Value *seed = findSeed(F, builder);
    auto *seedPlus1 = builder.CreateAdd(seed, builder.getInt32(1), "bcf.seed.p1");
    auto *product = builder.CreateMul(seed, seedPlus1, "bcf.parity.product");
    auto *lowBit = builder.CreateAnd(product, builder.getInt32(1), "bcf.parity.bit");
    auto *opaqueTrue = builder.CreateICmpEQ(lowBit, builder.getInt32(0), "bcf.opaque.true");

    // Dead block: statically reachable from succ's predecessor list, never taken.
    auto *bogus = BasicBlock::Create(F.getContext(), BB.getName() + ".bogus", &F, succ);
    IRBuilder<> bogusBuilder(bogus);
    bogusBuilder.CreateAdd(seed, bogusBuilder.getInt32(1), "bcf.junk");
    bogusBuilder.CreateBr(succ);

    // Build the new conditional branch before erasing the old unconditional one.
    builder.CreateCondBr(opaqueTrue, succ, bogus);
    br->eraseFromParent();
}

// unit: one Function
struct BcfPass : PassInfoMixin<BcfPass> {
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        // Collect targets before mutating: appending new blocks to F while
        // iterating it is unsafe without a snapshot.
        SmallVector<BasicBlock *, 8> targets;
        for (BasicBlock &BB : F) {
            if (eligibleSuccessor(BB))
                targets.push_back(&BB);
        }

        for (BasicBlock *BB : targets)
            diverge(F, *BB);

        errs() << "[bcf] " << F.getName() << ": " << targets.size() << " blocks diverted through a bogus branch\n";
        if (targets.empty())
            return PreservedAnalyses::all();

        // new blocks and edges added
        return PreservedAnalyses::none();
    }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "BcfPass", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                PB.registerPipelineParsingCallback(
                    [](StringRef name, FunctionPassManager &FPM, ArrayRef<PassBuilder::PipelineElement>) {
                        if (name == "bcf") {
                            FPM.addPass(BcfPass());
                            return true;
                        }
                        return false;
                    });
            }};
}
