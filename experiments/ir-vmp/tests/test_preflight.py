"""Set CPRISK_PREFLIGHT to the built checker to run LLVM boundary fixtures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.environ.get("CPRISK_PREFLIGHT"), "LLVM preflight executable not configured")
class PreflightTests(unittest.TestCase):
    def check(self, body, expected, target="f", layout="e-p:64:64-i64:64-n8:16:32:64-S128"):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"fixture.ll"
            path.write_text('target datalayout = "'+layout+'"\n'+body)
            result=subprocess.run([os.environ["CPRISK_PREFLIGHT"],str(path),target],capture_output=True,text=True,timeout=30)
            self.assertEqual(result.returncode,0 if expected else 1,result.stderr+result.stdout)
            report=json.loads(result.stdout)
            self.assertEqual(report["status"],"pass" if expected else "blocked")
            return report

    def test_scalar_loop_and_phi(self):
        self.check('''define i32 @f(i32 %n) {
entry: br label %loop
loop: %i = phi i32 [0, %entry], [%next, %again]
 %done = icmp eq i32 %i, %n
 br i1 %done, label %exit, label %again
again: %next = add i32 %i, 1
 br label %loop
exit: ret i32 %i
}''',True)

    def test_pointer_eq_and_ordered_rejection(self):
        self.check('define i1 @f(ptr %p) { %r = icmp eq ptr %p, null\n ret i1 %r }',True)
        self.check('define i1 @f(ptr %p) { %r = icmp ult ptr %p, null\n ret i1 %r }',False)

    def test_narrow_arithmetic(self):
        self.check('define i8 @f(i8 %a) { %b = add i8 %a, 1\n ret i8 %b }',False)

    def test_float_vector_atomic_volatile(self):
        for body in ('define float @f(float %a) { ret float %a }',
                     'define <2 x i32> @f(<2 x i32> %a) { ret <2 x i32> %a }',
                     'define i32 @f(ptr %p) { %v = load volatile i32, ptr %p\n ret i32 %v }',
                     'define i32 @f(ptr %p) { %v = load atomic i32, ptr %p acquire, align 4\n ret i32 %v }'):
            with self.subTest(body=body):self.check(body,False)

    def test_narrow_memory_allowed(self):
        self.check('define i32 @f(ptr %p) { %v = load i8, ptr %p\n %w = zext i8 %v to i32\n ret i32 %w }',True)

    def test_unknown_calls_and_recursion(self):
        for body in ('declare i32 @g()\ndefine i32 @f() { %r = call i32 @g()\n ret i32 %r }',
                     'define i32 @f() { %r = call i32 @f()\n ret i32 %r }'):
            with self.subTest(body=body):self.check(body,False)

    def test_unknown_target(self):
        self.check('define void @other() { ret void }',False)

    def test_nonzero_address_space_and_non64_layout(self):
        self.check('define ptr addrspace(1) @f(ptr addrspace(1) %p) { ret ptr addrspace(1) %p }',False)
        self.check('define i32 @f() { ret i32 0 }',False,layout='e-p:32:32-i64:64-n8:16:32')

    def test_dynamic_gep_boundary(self):
        self.check('define ptr @f(ptr %p, i64 %i) { %r = getelementptr i32, ptr %p, i64 %i\n ret ptr %r }',True)
        self.check('define ptr @f(ptr %p, i64 %i) { %r = getelementptr [65536 x i8], ptr %p, i64 %i\n ret ptr %r }',False)

    def test_poison_and_freeze(self):
        self.check('define i32 @f() { ret i32 poison }',False)
        self.check('define i32 @f(i32 %x) { %y = freeze i32 %x\n ret i32 %y }',False)


if __name__=="__main__":unittest.main()
