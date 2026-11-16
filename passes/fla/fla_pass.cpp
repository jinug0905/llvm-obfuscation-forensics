// FlaPass — LLVM function pass: control-flow flattening obfuscation.
//
// All basic blocks are removed from their natural positions and placed under a
// single dispatcher.  A state variable (alloca'd in a new entry block) records
// which block to execute next; the dispatcher reads it and switches.  Runtime
// behavior is identical; the CFG visible in the binary shows only a hub-and-spoke
// shape with no if/else or loop structure.
//
// Dominance: flattening replaces every block's structured predecessors with a
// single fla.dispatch predecessor.  Any value defined in one original block and
// used in another must be rerouted through a stack slot — otherwise the IR verifier
// rejects the function ("Instruction does not dominate all uses").
// hoistAllocas() moves existing allocas to newEntry; demoteCrossBlockValues()
// handles all other cross-block value uses via store-on-define / load-before-use.
//
// Limitations (function is left unchanged if any of these hold):
//   - Any PHI node in the function.  PHI correctness depends on the structured
//     dominance this pass destroys; run a reg2mem pass first to lower phis.
//   - Any terminator other than br, ret, or unreachable.
//   - Any landingpad instruction.  LLVM requires a landingpad block to be entered
//     only via an invoke's unwind edge; a switch-case edge added by flattening
//     violates this constraint and fails verification.
//   - Functions with only one block.
//
// Pass name: "fla"   Unit: Function

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
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

// Returns true if F contains any construct this pass cannot safely flatten:
// a PHI node, a landingpad, or an unsupported terminator.
bool hasUnsupportedShape(Function &F) {
    for (BasicBlock &BB : F) {
        for (Instruction &I : BB) {
            if (isa<PHINode>(I) || isa<LandingPadInst>(I))
                return true;
        }
        auto *term = BB.getTerminator();
        if (isa<BranchInst>(term) || isa<ReturnInst>(term) || isa<UnreachableInst>(term))
            continue;
        return true; // switch, indirectbr, invoke, resume, callbr, ...
    }
    return false;
}

// Moves every alloca in F (other than those already in newEntry) to the front
// of newEntry, so they dominate every flattened block.
void hoistAllocas(Function &F, BasicBlock *newEntry) {
    SmallVector<AllocaInst *, 8> allocas;
    for (BasicBlock &BB : F) {
        if (&BB == newEntry)
            continue;
        for (Instruction &I : BB) {
            if (auto *alloca = dyn_cast<AllocaInst>(&I))
                allocas.push_back(alloca);
        }
    }
    for (AllocaInst *alloca : allocas)
        alloca->moveBefore(*newEntry, newEntry->begin());
}

// For every value (non-alloca) used outside its defining block, inserts a stack
// slot in newEntry, a store immediately after the definition, and a reload
// immediately before each out-of-block use.
void demoteCrossBlockValues(Function &F, BasicBlock *newEntry) {
    // Collect first: the loop below inserts new loads (new uses of I), so we
    // must not mutate the use-list while deciding what to demote.
    SmallVector<Instruction *, 32> toDemote;
    for (BasicBlock &BB : F) {
        if (&BB == newEntry)
            continue;
        for (Instruction &I : BB) {
            if (isa<AllocaInst>(I))
                continue;
            for (User *user : I.users()) {
                if (cast<Instruction>(user)->getParent() != &BB) {
                    toDemote.push_back(&I);
                    break;
                }
            }
        }
    }

    for (Instruction *I : toDemote) {
        IRBuilder<> entryBuilder(newEntry, newEntry->begin());
        auto *slot = entryBuilder.CreateAlloca(I->getType(), nullptr, I->getName() + ".fla.slot");

        IRBuilder<> afterI(I->getNextNode());
        afterI.CreateStore(I, slot);

        for (Use &U : make_early_inc_range(I->uses())) {
            auto *userInst = cast<Instruction>(U.getUser());
            if (userInst->getParent() == I->getParent())
                continue;
            IRBuilder<> useBuilder(userInst);
            auto *reload = useBuilder.CreateLoad(I->getType(), slot, I->getName() + ".fla.reload");
            U.set(reload);
        }
    }
}

// Rewrites BB's terminator to store the next-block ID into stateSlot and branch
// to dispatch.  Blocks ending in ret or unreachable are left unchanged.
void routeThroughDispatcher(BasicBlock &BB, BasicBlock *dispatch,
                             const DenseMap<BasicBlock *, unsigned> &ids, Value *stateSlot) {
    auto *term = BB.getTerminator();
    if (isa<ReturnInst>(term) || isa<UnreachableInst>(term))
        return;

    auto *br = cast<BranchInst>(term);
    IRBuilder<> builder(br);

    Value *nextState;
    if (br->isConditional()) {
        unsigned trueId = ids.lookup(br->getSuccessor(0));
        unsigned falseId = ids.lookup(br->getSuccessor(1));
        nextState = builder.CreateSelect(br->getCondition(), builder.getInt32(trueId),
                                          builder.getInt32(falseId), "fla.next");
    } else {
        nextState = builder.getInt32(ids.lookup(br->getSuccessor(0)));
    }

    builder.CreateStore(nextState, stateSlot);
    builder.CreateBr(dispatch);
    br->eraseFromParent();
}

// unit: one Function
struct FlaPass : PassInfoMixin<FlaPass> {
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &) {
        if (F.size() < 2 || hasUnsupportedShape(F)) {
            errs() << "[fla] " << F.getName() << ": skipped\n";
            return PreservedAnalyses::all();
        }

        // 1. Number every original block before creating any new ones.
        DenseMap<BasicBlock *, unsigned> ids;
        SmallVector<BasicBlock *, 8> originalBlocks;
        for (BasicBlock &BB : F) {
            ids[&BB] = originalBlocks.size();
            originalBlocks.push_back(&BB);
        }
        BasicBlock *oldEntry = originalBlocks.front();

        // 2. New entry block: owns the state variable, seeds it with oldEntry's ID.
        //    Inserted before the current front so it becomes the new entry.
        auto *newEntry = BasicBlock::Create(F.getContext(), "fla.entry", &F, oldEntry);
        IRBuilder<> entryBuilder(newEntry);
        Value *stateSlot = entryBuilder.CreateAlloca(entryBuilder.getInt32Ty(), nullptr, "fla.state");
        entryBuilder.CreateStore(entryBuilder.getInt32(ids[oldEntry]), stateSlot);

        // 3. Hoist allocas and demote cross-block values to maintain dominance.
        hoistAllocas(F, newEntry);
        demoteCrossBlockValues(F, newEntry);

        // 4. Dispatcher: reads state, switches to the corresponding original block.
        //    The default case is unreachable by construction.
        auto *dispatch = BasicBlock::Create(F.getContext(), "fla.dispatch", &F, oldEntry);
        auto *unreachableBlock = BasicBlock::Create(F.getContext(), "fla.unreachable", &F, oldEntry);
        entryBuilder.CreateBr(dispatch);

        IRBuilder<>(unreachableBlock).CreateUnreachable();

        IRBuilder<> dispatchBuilder(dispatch);
        auto *state = dispatchBuilder.CreateLoad(dispatchBuilder.getInt32Ty(), stateSlot, "fla.cur");
        auto *sw = dispatchBuilder.CreateSwitch(state, unreachableBlock, originalBlocks.size());
        for (BasicBlock *BB : originalBlocks)
            sw->addCase(dispatchBuilder.getInt32(ids[BB]), BB);

        // 5. Reroute every original block's terminator through the dispatcher.
        for (BasicBlock *BB : originalBlocks)
            routeThroughDispatcher(*BB, dispatch, ids, stateSlot);

        errs() << "[fla] " << F.getName() << ": flattened " << originalBlocks.size()
               << " blocks behind one dispatcher\n";
        return PreservedAnalyses::none();
    }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "FlaPass", LLVM_VERSION_STRING,
            [](PassBuilder &PB) {
                PB.registerPipelineParsingCallback(
                    [](StringRef name, FunctionPassManager &FPM, ArrayRef<PassBuilder::PipelineElement>) {
                        if (name == "fla") {
                            FPM.addPass(FlaPass());
                            return true;
                        }
                        return false;
                    });
            }};
}
