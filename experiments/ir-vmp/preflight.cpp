// Restricted L0 input checker. LLVM parses the IR; this is not an equivalence proof.
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IRReader/IRReader.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"
#include <set>
#include <string>

using namespace llvm;

static bool scalar(Type *T) {
  if (T->isVoidTy()) return true;
  if (auto *P = dyn_cast<PointerType>(T)) return P->getAddressSpace() == 0;
  if (auto *I = dyn_cast<IntegerType>(T)) {
    unsigned W = I->getBitWidth();
    return W == 1 || W == 8 || W == 16 || W == 32 || W == 64;
  }
  return false;
}

static bool invalidConstant(Value *V) {
  if (isa<PoisonValue>(V) || isa<UndefValue>(V)) return true;
  if (auto *C = dyn_cast<ConstantExpr>(V))
    for (const Use &U : C->operands()) if (invalidConstant(U.get())) return true;
  return false;
}

int main(int argc, char **argv) {
  if (argc == 2 && StringRef(argv[1]) == "--version") {
    outs() << LLVM_VERSION_STRING << "\n"; return 0;
  }
  if (argc < 3) { errs() << "usage: preflight input.ll target...\n"; return 2; }
  LLVMContext Context;
  SMDiagnostic Error;
  auto M = parseIRFile(argv[1], Error, Context);
  if (!M) { Error.print(argv[0], errs()); return 2; }
  if (verifyModule(*M, &errs())) return 2;
  const DataLayout &DL = M->getDataLayout();
  json::Array Results;
  const bool LayoutValid = !DL.isDefault() && DL.getPointerSizeInBits(0) == 64 && DL.getIndexSizeInBits(0) == 64;
  bool AllValid = LayoutValid;
  std::set<std::string> Seen;
  for (int N = 2; N < argc; ++N) {
    std::string Name = argv[N];
    json::Array Errors;
    json::Object Opcodes;
    std::set<std::string> Calls;
    Function *F = M->getFunction(Name);
    if (!Seen.insert(Name).second) Errors.push_back("duplicate_target");
    if (!LayoutValid) Errors.push_back("requires_nonempty_64bit_AS0_pointer_and_index_layout");
    if (!F || F->isDeclaration()) Errors.push_back("missing_defined_target");
    else {
      if (F->isVarArg() || F->getCallingConv() != CallingConv::C || !scalar(F->getReturnType()))
        Errors.push_back("unsupported_function_ABI");
      for (Argument &A : F->args()) {
        if (!scalar(A.getType()) || A.hasByValAttr() || A.hasStructRetAttr() ||
            A.hasInAllocaAttr() || A.hasAttribute(Attribute::SwiftSelf) ||
            A.hasAttribute(Attribute::SwiftError) || A.hasAttribute(Attribute::Nest) ||
            A.hasAttribute(Attribute::InReg) || A.hasAttribute(Attribute::Preallocated))
          Errors.push_back("unsupported_argument_ABI");
      }
      for (BasicBlock &BB : *F) for (Instruction &I : BB) {
        std::string Reason;
        std::string Op = I.getOpcodeName();
        Opcodes[Op] = Opcodes.getInteger(Op).value_or(0) + 1;
        if (!scalar(I.getType())) Reason = "nonscalar_result";
        for (Use &U : I.operands()) {
          if (invalidConstant(U.get())) Reason = "poison_or_undef_operand";
          if (!isa<BasicBlock>(U.get()) && !scalar(U->getType())) Reason = "nonscalar_operand";
        }
        switch (I.getOpcode()) {
        case Instruction::Add: case Instruction::Sub: case Instruction::Mul:
        case Instruction::UDiv: case Instruction::SDiv: case Instruction::URem: case Instruction::SRem:
        case Instruction::And: case Instruction::Or: case Instruction::Xor:
        case Instruction::Shl: case Instruction::LShr: case Instruction::AShr:
          if (!I.getType()->isIntegerTy(32) && !I.getType()->isIntegerTy(64)) Reason = "unverified_narrow_arithmetic";
          break;
        case Instruction::ICmp: {
          auto &Cmp = cast<ICmpInst>(I);
          if (Cmp.getOperand(0)->getType()->isPointerTy() && !Cmp.isEquality()) Reason = "ordered_pointer_comparison";
          if (!Cmp.getOperand(0)->getType()->isPointerTy() &&
              !Cmp.getOperand(0)->getType()->isIntegerTy(32) &&
              !Cmp.getOperand(0)->getType()->isIntegerTy(64)) Reason = "unverified_narrow_comparison";
          break;
        }
        case Instruction::Load:
          if (cast<LoadInst>(I).isVolatile() || cast<LoadInst>(I).isAtomic()) Reason = "volatile_or_atomic_load";
          break;
        case Instruction::Store:
          if (cast<StoreInst>(I).isVolatile() || cast<StoreInst>(I).isAtomic()) Reason = "volatile_or_atomic_store";
          break;
        case Instruction::Alloca:
          if (!isa<ConstantInt>(cast<AllocaInst>(I).getArraySize())) Reason = "dynamic_alloca";
          break;
        case Instruction::GetElementPtr: {
          auto &G = cast<GetElementPtrInst>(I);
          if (G.getPointerAddressSpace() != 0) Reason = "nonzero_GEP_address_space";
          if (!G.hasAllConstantIndices()) {
            Type *Element = G.getSourceElementType();
            Value *Index = nullptr;
            if (G.getNumIndices() == 1) Index = G.getOperand(1);
            else if (G.getNumIndices() == 2 && isa<ArrayType>(Element) &&
                     isa<ConstantInt>(G.getOperand(1)) && cast<ConstantInt>(G.getOperand(1))->isZero()) {
              Element = cast<ArrayType>(Element)->getElementType(); Index = G.getOperand(2);
            } else Reason = "unsupported_dynamic_GEP_shape";
            if (Index && !Index->getType()->isIntegerTy(32) && !Index->getType()->isIntegerTy(64)) Reason = "unsupported_GEP_index_width";
            if (!Element->isSized() || DL.getTypeAllocSize(Element).isScalable() ||
                DL.getTypeAllocSize(Element).getKnownMinValue() > 65535) Reason = "unsupported_GEP_stride";
          }
          break;
        }
        case Instruction::Call: {
          auto &Call = cast<CallInst>(I);
          Function *Callee = Call.getCalledFunction();
          if (!Callee || Callee == F || Call.isInlineAsm() || Call.getCallingConv() != CallingConv::C ||
              Call.getFunctionType()->isVarArg() || Call.hasOperandBundles()) Reason = "unsupported_call_ABI";
          else {
            Calls.insert(Callee->getName().str());
            // No native call ABI has been accepted for these two L0 kernels yet.
            Reason = "native_helper_requires_separate_ABI_acceptance:" + Callee->getName().str();
          }
          break;
        }
        case Instruction::Switch:
          if (!cast<SwitchInst>(I).getCondition()->getType()->isIntegerTy(32)) Reason = "unsupported_switch_width";
          break;
        case Instruction::PHI: case Instruction::Select:
          if (!I.getType()->isPointerTy() && !I.getType()->isIntegerTy(32) && !I.getType()->isIntegerTy(64)) Reason = "unverified_narrow_merge";
          break;
        case Instruction::ZExt: case Instruction::SExt:
          if (!I.getType()->isIntegerTy(32) && !I.getType()->isIntegerTy(64)) Reason = "unsupported_extension_width";
          if (I.getOpcode() == Instruction::SExt && I.getOperand(0)->getType()->isIntegerTy(1)) Reason = "unsupported_i1_sign_extension";
          break;
        case Instruction::Trunc:
          if (!I.getOperand(0)->getType()->isIntegerTy(32) && !I.getOperand(0)->getType()->isIntegerTy(64)) Reason = "unsupported_truncation_width";
          break;
        case Instruction::Br: case Instruction::Ret:
          break;
        default: Reason = "unreviewed_opcode"; break;
        }
        if (!Reason.empty()) Errors.push_back(Op + ":" + Reason);
      }
    }
    bool Pass = Errors.empty();
    AllValid = AllValid && Pass;
    json::Array Helpers; for (const auto &C : Calls) Helpers.push_back(C);
    Results.push_back(json::Object{{"target", Name}, {"status", Pass ? "pass" : "blocked"},
        {"opcodes", std::move(Opcodes)}, {"native_helpers", std::move(Helpers)}, {"reasons", std::move(Errors)}});
  }
  outs() << json::Value(json::Object{{"schema_version", 1}, {"llvm_version", LLVM_VERSION_STRING},
      {"target_triple", M->getTargetTriple().str()}, {"data_layout", DL.getStringRepresentation()},
      {"status", AllValid ? "pass" : "blocked"}, {"targets", std::move(Results)}}) << "\n";
  return AllValid ? 0 : 1;
}
