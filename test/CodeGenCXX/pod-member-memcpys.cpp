// RUN: %clang_cc1 -triple x86_64-apple-darwin10 -emit-llvm -std=c++03 -fexceptions -fcxx-exceptions -o - %s | FileCheck %s
// RUN: %clang_cc1 -triple i386-apple-darwin10 -emit-llvm -std=c++03 -o - %s | FileCheck --check-prefix=CHECK-2 %s

struct POD {
  int w, x, y, z;
};

struct PODLike {
  int w, x, y, z;
  PODLike();
  ~PODLike();
};

struct NonPOD {
  NonPOD();
  NonPOD(const NonPOD&);
  NonPOD& operator=(const NonPOD&);
};

struct Basic {
  int a, b, c, d;
  NonPOD np;
  int w, x, y, z;
};

struct PODMember {
  int a, b, c, d;
  POD p;
  NonPOD np;
  int w, x, y, z;
};

struct PODLikeMember {
  int a, b, c, d;
  PODLike pl;
  NonPOD np;
  int w, x, y, z;
};

struct ArrayMember {
  int a, b, c, d;
  int e[12];
  NonPOD np;
  int f[12];
  int w, x, y, z;
};

struct VolatileMember {
  int a, b, c, d;
  volatile int v;
  NonPOD np;
  int w, x, y, z;
};

struct BitfieldMember {
  int a, b, c, d;
  NonPOD np;
  int w : 6;
  int x : 6;
  int y : 6;
  int z : 6;
};

struct BitfieldMember2 {
  unsigned a : 1;
  unsigned b, c, d;
  NonPOD np;
};

struct InnerClassMember {
  struct {
    int a, b, c, d;
  } a;
  int b, c, d, e;
  NonPOD np;
  int w, x, y, z;
};

struct ReferenceMember {
  ReferenceMember(int &a, int &b, int &c, int &d)
    : a(a), b(b), c(c), d(d) {}
  int &a;
  int &b;
  NonPOD np;
  int &c;
  int &d;
};

struct __attribute__((packed)) PackedMembers {
  char c;
  NonPOD np;
  int w, x, y, z;
};

// COPY-ASSIGNMENT OPERATORS:

// Assignment operators are output in the order they're encountered.

#define CALL_AO(T) void callAO##T(T& a, const T& b) { a = b; } 

CALL_AO(Basic)
CALL_AO(PODMember)
CALL_AO(PODLikeMember)
CALL_AO(ArrayMember)
CALL_AO(VolatileMember)
CALL_AO(BitfieldMember)
CALL_AO(InnerClassMember)
CALL_AO(PackedMembers)

// Basic copy-assignment:
// CHECK-LABEL: define linkonce_odr nonnull %struct.Basic* @_ZN5BasicaSERKS_(%struct.Basic* %this, %struct.Basic* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: call nonnull %struct.NonPOD* @_ZN6NonPODaSERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: ret %struct.Basic*

// PODMember copy-assignment:
// CHECK-LABEL: define linkonce_odr nonnull %struct.PODMember* @_ZN9PODMemberaSERKS_(%struct.PODMember* %this, %struct.PODMember* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 32, i32 4{{.*}})
// CHECK: call nonnull %struct.NonPOD* @_ZN6NonPODaSERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: ret %struct.PODMember*

// PODLikeMember copy-assignment:
// CHECK-LABEL: define linkonce_odr nonnull %struct.PODLikeMember* @_ZN13PODLikeMemberaSERKS_(%struct.PODLikeMember* %this, %struct.PODLikeMember* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 32, i32 4{{.*}})
// CHECK: call nonnull %struct.NonPOD* @_ZN6NonPODaSERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: ret %struct.PODLikeMember*

// ArrayMember copy-assignment:
// CHECK-LABEL: define linkonce_odr nonnull %struct.ArrayMember* @_ZN11ArrayMemberaSERKS_(%struct.ArrayMember* %this, %struct.ArrayMember* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 64, i32 4{{.*}})
// CHECK: call nonnull %struct.NonPOD* @_ZN6NonPODaSERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 64, i32 4{{.*}})
// CHECK: ret %struct.ArrayMember*

// VolatileMember copy-assignment:
// CHECK-LABEL: define linkonce_odr nonnull %struct.VolatileMember* @_ZN14VolatileMemberaSERKS_(%struct.VolatileMember* %this, %struct.VolatileMember* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: load volatile i32* {{.*}}, align 4
// CHECK: store volatile i32 {{.*}}, align 4
// CHECK: call nonnull %struct.NonPOD* @_ZN6NonPODaSERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: ret %struct.VolatileMember*

// BitfieldMember copy-assignment:
// CHECK-LABEL: define linkonce_odr nonnull %struct.BitfieldMember* @_ZN14BitfieldMemberaSERKS_(%struct.BitfieldMember* %this, %struct.BitfieldMember* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: call nonnull %struct.NonPOD* @_ZN6NonPODaSERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 3, i32 1{{.*}})
// CHECK: ret %struct.BitfieldMember*

// InnerClass copy-assignment:
// CHECK-LABEL: define linkonce_odr nonnull %struct.InnerClassMember* @_ZN16InnerClassMemberaSERKS_(%struct.InnerClassMember* %this, %struct.InnerClassMember* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 32, i32 4{{.*}})
// CHECK: call nonnull %struct.NonPOD* @_ZN6NonPODaSERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: ret %struct.InnerClassMember*

// PackedMembers copy-assignment:
// CHECK-LABEL: define linkonce_odr nonnull %struct.PackedMembers* @_ZN13PackedMembersaSERKS_(%struct.PackedMembers* %this, %struct.PackedMembers* nonnull)
// CHECK: call nonnull %struct.NonPOD* @_ZN6NonPODaSERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 1{{.*}})
// CHECK: ret %struct.PackedMembers*

// COPY-CONSTRUCTORS:

// Clang outputs copy-constructors in the reverse of the order that
// copy-constructor calls are encountered. Add functions that call the copy
// constructors of the classes above in reverse order here.

#define CALL_CC(T) T callCC##T(const T& b) { return b; }

CALL_CC(PackedMembers)
CALL_CC(BitfieldMember2)
CALL_CC(ReferenceMember)
CALL_CC(InnerClassMember)
CALL_CC(BitfieldMember)
CALL_CC(VolatileMember)
CALL_CC(ArrayMember)
CALL_CC(PODLikeMember)
CALL_CC(PODMember)
CALL_CC(Basic)

// Basic copy-constructor:
// CHECK-LABEL: define linkonce_odr void @_ZN5BasicC2ERKS_(%struct.Basic* %this, %struct.Basic* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: call void @_ZN6NonPODC1ERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: ret void

// PODMember copy-constructor:
// CHECK-LABEL: define linkonce_odr void @_ZN9PODMemberC2ERKS_(%struct.PODMember* %this, %struct.PODMember* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 32, i32 4{{.*}})
// CHECK: call void @_ZN6NonPODC1ERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: ret void

// PODLikeMember copy-constructor:
// CHECK-LABEL: define linkonce_odr void @_ZN13PODLikeMemberC2ERKS_(%struct.PODLikeMember* %this, %struct.PODLikeMember* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 32, i32 4{{.*}})
// CHECK: invoke void @_ZN6NonPODC1ERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: ret void
// CHECK: landingpad
// CHECK: invoke void @_ZN7PODLikeD1Ev

// ArrayMember copy-constructor:
// CHECK-LABEL: define linkonce_odr void @_ZN11ArrayMemberC2ERKS_(%struct.ArrayMember* %this, %struct.ArrayMember* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 64, i32 4{{.*}})
// CHECK: call void @_ZN6NonPODC1ERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 64, i32 4{{.*}})
// CHECK: ret void

// VolatileMember copy-constructor:
// CHECK-LABEL: define linkonce_odr void @_ZN14VolatileMemberC2ERKS_(%struct.VolatileMember* %this, %struct.VolatileMember* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: load volatile i32* {{.*}}, align 4
// CHECK: store volatile i32 {{.*}}, align 4
// CHECK: call void @_ZN6NonPODC1ERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: ret void

// BitfieldMember copy-constructor:
// CHECK-LABEL: define linkonce_odr void @_ZN14BitfieldMemberC2ERKS_(%struct.BitfieldMember* %this, %struct.BitfieldMember* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: call void @_ZN6NonPODC1ERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 3, i32 1{{.*}})
// CHECK: ret void

// InnerClass copy-constructor:
// CHECK-LABEL: define linkonce_odr void @_ZN16InnerClassMemberC2ERKS_(%struct.InnerClassMember* %this, %struct.InnerClassMember* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 32, i32 4{{.*}})
// CHECK: call void @_ZN6NonPODC1ERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4{{.*}})
// CHECK: ret void

// ReferenceMember copy-constructor:
// CHECK-LABEL: define linkonce_odr void @_ZN15ReferenceMemberC2ERKS_(%struct.ReferenceMember* %this, %struct.ReferenceMember* nonnull)
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 8{{.*}})
// CHECK: call void @_ZN6NonPODC1ERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 8{{.*}})
// CHECK: ret void

// BitfieldMember2 copy-constructor:
// CHECK-2-LABEL: define linkonce_odr void @_ZN15BitfieldMember2C2ERKS_(%struct.BitfieldMember2* %this, %struct.BitfieldMember2* nonnull)
// CHECK-2: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 4, i1 false)
// CHECK-2: call void @_ZN6NonPODC1ERKS_
// CHECK-2: ret void

// PackedMembers copy-assignment:
// CHECK-LABEL: define linkonce_odr void @_ZN13PackedMembersC2ERKS_(%struct.PackedMembers* %this, %struct.PackedMembers* nonnull)
// CHECK: call void @_ZN6NonPODC1ERKS_
// CHECK: call void @llvm.memcpy.p0i8.p0i8.i64({{.*}}i64 16, i32 1{{.*}})
// CHECK: ret void
