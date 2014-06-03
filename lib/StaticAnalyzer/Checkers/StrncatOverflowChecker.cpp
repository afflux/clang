// vim:et:sts=2:sw=2:ts=2

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "llvm/ADT/Optional.h"

using namespace clang;

namespace {
  class StrncatOverflowChecker : public ento::Checker< ento::check::PreStmt<CallExpr> > {
    private:
      bool isLimitedStringFunction(const IdentifierInfo& II) const;
      bool isLimitingParameter(const IdentifierInfo& II) const;
      llvm::Optional<ento::SVal> findLimitingArgument(const ento::CheckerContext&, FunctionDecl::param_const_iterator, const FunctionDecl::param_const_iterator, CallExpr::const_arg_iterator, const CallExpr::const_arg_iterator) const;
    public:
      void checkPreStmt(const CallExpr *E, ento::CheckerContext &C) const;
  };  
} // end anonymous namespace


bool StrncatOverflowChecker::isLimitedStringFunction(const IdentifierInfo& II) const {
  return II.isStr("strncpy") || II.isStr("strncat") || II.isStr("snprintf");
}

bool StrncatOverflowChecker::isLimitingParameter(const IdentifierInfo& II) const {
  return II.isStr("strncpy") || II.isStr("strncat") || II.isStr("snprintf");
}

llvm::Optional<ento::SVal> StrncatOverflowChecker::findLimitingArgument(const ento::CheckerContext& C,
    FunctionDecl::param_const_iterator formalParamIt, const FunctionDecl::param_const_iterator formal_end,
    CallExpr::const_arg_iterator argumentIt, const CallExpr::const_arg_iterator arg_end) const {
  for (; formalParamIt != formal_end && argumentIt != arg_end; ++formalParamIt, ++argumentIt) {
    const Type& paramType = *(*formalParamIt)->getOriginalType();
    if (paramType.isUnsignedIntegerType()) {
      return C.getState()->getSVal(*argumentIt, C.getLocationContext());
    }
  }
  return llvm::None;
}

void StrncatOverflowChecker::checkPreStmt(const CallExpr *E, ento::CheckerContext &C) const {
  const SourceManager &SM = C.getSourceManager();
  const FunctionDecl *FD = C.getCalleeDecl(E);

  const IdentifierInfo* FII;

  // retrieve function declaration
  if (!FD)
    FD = dyn_cast<FunctionDecl>(E->getCalleeDecl());
  if (!FD) {
    llvm::errs() << "failed to get functiondecl at ";
    E->getLocStart().print(llvm::errs(), SM);
    llvm::errs() << '\n';
    return;
  }

  // retrieve function identifier
  FII = FD->getIdentifier();
  if (!FII) {
    llvm::errs() << "non-identified function call at ";
    E->getLocStart().print(llvm::errs(), SM);
    llvm::errs() << ": " << *FD << '\n';
    return;
  }


  // determine if function is a limited string function
  if (!isLimitedStringFunction(*FII))
    return;

  llvm::errs() << "got strn* at ";
  E->getLocStart().print(llvm::errs(), SM);
  llvm::errs() << ": " << *FD << '\n';


  // walk through parameters
  FunctionDecl::param_const_iterator formalParamIt = FD->param_begin();
  CallExpr::const_arg_iterator argumentIt = E->arg_begin();

  if (formalParamIt == FD->param_end() || argumentIt == E->arg_end()) {
    // this is a weird strn* function, it doesn't have parameters...
    return;
  }

  // first parameter is supposed to be the destination string
  const ento::SVal destArg = C.getState()->getSVal(*argumentIt, C.getLocationContext());

  // walk through parameter list to find the unsigned integer that is the limit
  const llvm::Optional<ento::SVal> limitArg = findLimitingArgument(C, ++formalParamIt, FD->param_end(), ++argumentIt, E->arg_end());

}

void clang::ento::registerStrncatOverflowChecker(ento::CheckerManager &mgr) {
  mgr.registerChecker<StrncatOverflowChecker>();
}
