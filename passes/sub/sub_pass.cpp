// SubstPass — LLVM function pass: instruction substitution obfuscation.
//
// Replaces each integer arithmetic/logical instruction with an algebraically
// equivalent multi-instruction sequence.  The CFG and read-only data are unchanged.
//
// Five substitution rules (each is an exact algebraic identity):
//
//   a + b  ->  a - (0 - b)
//   a - b  ->  a + (0 - b)
//   a ^ b  ->  (a | b) - (a & b)
//   a & b  ->  ~(~a | ~b)      De Morgan
//   a | b  ->  ~(~a & ~b)      De Morgan
//
// Pass name: "subst"   Unit: Function

#include "llvm/ADT/STLExtras.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

namespace {

// Returns the replacement value for I, or nullptr if no rule applies.
Value *substitute(Instruction &I) {
    // Integer instructions only; fadd/fsub/fxor use different opcodes.
    if (!I.getType()->isIntegerTy())
        return nullptr;

    // Check opcode before accessing operands: not every integer-typed instruction
    // is binary (e.g. ret has only one operand).
    unsigned int opcode = I.getOpcode();
    if (opcode != Instruction::Add && opcode != Instruction::Sub && opcode != Instruction::Xor &&
        opcode != Instruction::And && opcode != Instruction::Or)
        return nullptr;

    auto *a = I.getOperand(0);
    auto *b = I.getOperand(1);
    auto *zero = ConstantInt::get(I.getType(), 0);
    IRBuilder<> builder(&I);

    switch (opcode) {
    case Instruction::Add: {
        // a + b  ->  a - (0 - b)
        auto *negB = builder.CreateSub(zero, b, "neg.b");
        return builder.CreateSub(a, negB, "subst.add");
    }
    case Instruction::Sub: {
        // a - b  ->  a + (0 - b)
        auto *negB = builder.CreateSub(zero, b, "neg.b");
        return builder.CreateAdd(a, negB, "subst.sub");
    }
    case Instruction::Xor: {
        // a ^ b  ->  (a | b) - (a & b)
        auto *orAB = builder.CreateOr(a, b, "or.ab");
        auto *andAB = builder.CreateAnd(a, b, "and.ab");
        return builder.CreateSub(orAB, andAB, "subst.xor");
    }
    case Instruction::And: {
        // a & b  ->  ~(~a | ~b)      De Morgan
        auto *notA = builder.CreateNot(a, "not.a");
        auto *notB = builder.CreateNot(b, "not.b");
        auto *orNotAB = builder.CreateOr(notA, notB, "or.nota.notb");
        return builder.CreateNot(orNotAB, "subst.and");
    }
    case Instruction::Or: {
        // a | b  ->  ~(~a & ~b)      De Morgan
        auto *notA = builder.CreateNot(a, "not.a");
        auto *notB = builder.CreateNot(b, "not.b");
        auto *andNotAB = builder.CreateAnd(notA, notB, "and.nota.notb");
        return builder.CreateNot(andNotAB, "subst.or");
    }
    default:
        return nullptr; // unreachable
    }
}

// unit: one Function
struct SubstPass : PassInfoMixin<SubstPass> {
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        unsigned substituted = 0;

        // make_early_inc_range: safe to erase I while iterating.
        for (BasicBlock &BB : F) {
            for (Instruction &I : make_early_inc_range(BB)) {
                auto *replacement = substitute(I);
                if (!replacement)
                    continue;

                // replaceAllUsesWith before eraseFromParent: never erase a value
                // that still has users.
                I.replaceAllUsesWith(replacement);
                I.eraseFromParent();
                substituted++;
            }
        }

        errs() << "[subst] " << F.getName() << ": " << substituted << " instructions substituted\n";
        if (!substituted)
            return PreservedAnalyses::all();

        // instructions changed, CFG did not
        PreservedAnalyses PA;
        PA.preserveSet<CFGAnalyses>();
        return PA;
    }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "SubstPass", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                PB.registerPipelineParsingCallback(
                    [](StringRef name, FunctionPassManager &FPM, ArrayRef<PassBuilder::PipelineElement>) {
                        if (name == "subst") {
                            FPM.addPass(SubstPass());
                            return true;
                        }
                        return false;
                    });
            }};
}
