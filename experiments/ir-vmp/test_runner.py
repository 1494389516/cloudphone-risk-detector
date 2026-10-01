"""Unit tests for false-success gates; synthetic IR is not execution evidence."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
import run


class RunnerGates(unittest.TestCase):
    def test_versions_reject_incompatible_or_apple(self):
        for clang, opt in (("clang version 21.1.0", "LLVM version 21.1.0"),
                           ("clang version 22.1.0", "LLVM version 23.1.0"),
                           ("clang version 22.1.0", "LLVM version 22.1.1"),
                           ("Apple clang version 22.1.0", "LLVM version 22.1.0")):
            with self.subTest(clang=clang, opt=opt), self.assertRaises(run.GateError):
                run.check_versions(clang, opt)
        self.assertEqual(run.check_versions("clang version 22.1.0", "LLVM version 22.1.0"), "22.1.0")

    def test_annotation_or_unrelated_ir_change_is_not_vmp(self):
        before = "define i64 @target(i64 %x) {\n ret i64 %x\n}\n"
        after = before.replace("ret", "; vm marker\n ret")
        with self.assertRaises(run.GateError):
            run.inspect_ir(before, after, ("target",))

    def test_per_function_vm_evidence_required(self):
        before = "define i64 @target(i64 %x) {\n ret i64 %x\n}\n"
        # This tiny fixture only exercises the parser. It is not valid LLVM IR.
        after = ("@target.vm.bytecode = private unnamed_addr constant [4 x i8] zeroinitializer\n"
                 "@target.vm.ophandlers = private constant [1 x ptr] zeroinitializer\n"
                 "define i64 @target(i64 %x) {\nvm.entry:\n"
                 " %bc = getelementptr i8, ptr @target.vm.bytecode, i64 0\n"
                 " %ht = getelementptr ptr, ptr @target.vm.ophandlers, i64 0\n"
                 " %r = call i64 %engine(ptr %bc, ptr %ht)\n ret i64 %r\n}\n"
                 "define void @__vm_engine() {\n indirectbr ptr null, []\n}\n")
        self.assertEqual(run.inspect_ir(before, after, ("target",))["target"]["bytecode_bytes"], 4)
        for token in ("indirectbr", "@target.vm.bytecode", "@target.vm.ophandlers", "vm.entry", "call"):
            with self.subTest(token=token), self.assertRaises(run.GateError):
                run.inspect_ir(before, after.replace(token, "missing"), ("target",))
        commented = after.replace(" %bc =", " ; %bc =").replace(" %ht =", " ; %ht =")
        with self.assertRaises(run.GateError):
            run.inspect_ir(before, commented, ("target",))

    def test_report_requires_exact_ran_changed_and_no_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pass.json"
            good = {"name": "target", "skipped": False,
                    "passes": [{"id": "vm", "status": "ran", "changed": True}]}
            path.write_text(json.dumps({"functions": [good]}))
            run.inspect_pass_reports(directory, ("target",))
            for records in ([], [None], [dict(good, passes=[None])], [good, good], [dict(good, skipped=True)],
                            [dict(good, passes=[{"id": "vm", "status": "ran", "changed": False}])],
                            [dict(good, passes=[{"id": "vm", "status": "success", "changed": True}])]):
                path.write_text(json.dumps({"functions": records}))
                with self.subTest(records=records), self.assertRaises(run.GateError):
                    run.inspect_pass_reports(directory, ("target",))

    def test_plugin_hash_commit_and_version_are_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "plugin.so"
            plugin.write_bytes(b"fixture, not a plugin")
            path = Path(directory) / "provenance.json"
            good = {"xollvm_commit": run.PINNED_COMMIT, "plugin_sha256": run.sha256(plugin),
                    "llvm_version": "22.1.0", "status": "built"}
            path.write_text(json.dumps(good))
            run.check_provenance(path, plugin, "22.1.0")
            for key in good:
                path.write_text(json.dumps(dict(good, **{key: "wrong"})))
                with self.subTest(key=key), self.assertRaises(run.GateError):
                    run.check_provenance(path, plugin, "22.1.0")

    def test_missing_compiler_overwrites_stale_success_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text('{"status":"HOST_VMP_PASS","vmp_verified":true}')
            args = SimpleNamespace(output=directory, mode="xollvm", suite="gf2", timeout=10,
                                   clang="/definitely/absent/clang", opt="opt", plugin=None,
                                   plugin_provenance=None)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(run.execute(args), 1)
            report = json.loads(path.read_text())
            self.assertEqual(report["status"], "BLOCKED_OR_FAILED")
            self.assertFalse(report["vmp_verified"])


if __name__ == "__main__":
    unittest.main()
