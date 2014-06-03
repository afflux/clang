//===--- CallAndMessageChecker.cpp ------------------------------*- C++ -*--==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This defines UninitStrcatChecker, a builtin checker that checks for strn?cat
// to allocated but uninitialized memory regions, which lead to unpredictable
// writes.
//
//===----------------------------------------------------------------------===//

#include "ClangSACheckers.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

using namespace clang;

namespace {
  class UninitStrcatChecker : public ento::Checker<ento::check::PreCall> {
    private:
      mutable std::unique_ptr<ento::BugType> bt;
    public:
      void checkPreCall(const ento::CallEvent &Call, ento::CheckerContext &C) const;
  };  
} // end anonymous namespace

void UninitStrcatChecker::checkPreCall(const ento::CallEvent &Call, ento::CheckerContext &C) const {
  if (ento::CE_Function != Call.getKind())
    return;

  if (!Call.isInSystemHeader())
    return;

  if (!Call.isGlobalCFunction("strcat") && !Call.isGlobalCFunction("strncat"))
    return;

  // first parameter is the destination string address
  const ento::SVal destArg = Call.getArgSVal(0);

  const ento::MemRegion* region = destArg.getAsRegion();
  if (!region)
    return;

  const ento::SVal regionV = C.getState()->getSVal(region);
  if (!regionV.isUndef())
    return;

  const ento::ExplodedNode* N = C.generateSink();

  if (!N)
    return;

  // Generate a report for this bug.
  static const char* desc = "Uninitialized memory as destination in strcat/strncat";
  if (!bt)
    bt.reset(new ento::BuiltinBug(this, desc));
  ento::BugReport *R = new ento::BugReport(*bt, desc, N);
  R->addRange(Call.getArgSourceRange(0));
  ento::bugreporter::trackNullOrUndefValue(N, Call.getArgExpr(0), *R);
  C.emitReport(R);
}

void clang::ento::registerUninitStrcatChecker(ento::CheckerManager &mgr) {
  mgr.registerChecker<UninitStrcatChecker>();
}
