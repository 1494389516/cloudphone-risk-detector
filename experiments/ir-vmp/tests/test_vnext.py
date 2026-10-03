import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import vnext
import run as runner
import verify_sources


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "policy.json"
        self.policy = vnext.load(HERE / "policy.semantic-lab.json")

    def validate(self, data=None):
        self.path.write_text(json.dumps(self.policy if data is None else data))
        return vnext.validate_policy(self.path)

    def test_checked_in_policy_and_schemas(self):
        self.validate()
        report = vnext.new_evidence(self.policy, vnext.sha256(self.path))
        vnext.schema_validate(report, "release_evidence.schema.json")

    def test_duplicate_and_nonfinite_json(self):
        for text in ('{"a":1,"a":2}', '{"a":{"b":1,"b":2}}', 'NaN', 'Infinity', '-Infinity', '1e999'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                vnext.strict_json(text)

    def test_unknown_root_and_nested_keys(self):
        for nested in (False, True):
            p=copy.deepcopy(self.policy)
            (p["candidates"][0]["annotation"] if nested else p)["typo"]=True
            with self.subTest(nested=nested), self.assertRaises(ValueError): self.validate(p)

    def test_version_and_types(self):
        for field,value in (("schema_version",2),("schema_version",1.0),("schema_version",True),
                            ("required","true"),("seeds",[True]),("seeds",[1.0]),("seeds",[0]),
                            ("profile","max"),("target_triple","arm64-apple-ios15.0"),
                            ("upstream_commit","0"*40),("patch_set","pointer-eq-ne-v1")):
            p=copy.deepcopy(self.policy);p[field]=value
            with self.subTest(field=field,value=value), self.assertRaises(ValueError): self.validate(p)

    def test_duplicate_empty_unknown_candidates(self):
        for candidates in ([],[self.policy["candidates"][0]]*2,[{"candidate_id":"unknown"}]):
            p=copy.deepcopy(self.policy);p["candidates"]=candidates
            with self.subTest(candidates=candidates), self.assertRaises(ValueError): self.validate(p)

    def test_hashes_and_annotation_cannot_be_reused(self):
        for field in ("source_sha256","body_sha256","dependencies_sha256"):
            p=copy.deepcopy(self.policy);p["candidates"][0][field]="0"*64
            with self.subTest(field=field), self.assertRaises(ValueError): self.validate(p)
        p=copy.deepcopy(self.policy);p["candidates"][0]["annotation"]["hardened"]=1
        with self.assertRaises(ValueError): self.validate(p)

    def test_mode_conflicts(self):
        for profile,target,required in (("off","host",True),("ir-vmp-canary","host",True),
                                        ("ir-vmp-release","arm64-apple-ios14.0",False)):
            p=copy.deepcopy(self.policy);p.update(profile=profile,target_triple=target,required=required)
            with self.subTest(profile=profile), self.assertRaises(ValueError):self.validate(p)

    def test_duplicate_seed(self):
        self.policy["seeds"]=[1,1]
        with self.assertRaises(ValueError): self.validate()

    def test_missing_required_key(self):
        for key in self.policy:
            p=copy.deepcopy(self.policy);del p[key]
            with self.subTest(key=key),self.assertRaises(ValueError):self.validate(p)

    def test_paths(self):
        (Path(self.tmp.name)/"good").write_text("x")
        self.assertTrue(vnext.safe_file(Path(self.tmp.name),"good").is_file())
        for name in ("../escape","/tmp/escape","missing","./good"):
            with self.subTest(name=name),self.assertRaises(ValueError):vnext.safe_file(Path(self.tmp.name),name)

    def test_evidence_is_ineligible(self):
        self.validate();e=Path(self.tmp.name)/"evidence.json"
        r=vnext.new_evidence(self.policy,vnext.sha256(self.path));vnext.atomic_json(e,r)
        self.assertFalse(vnext.verify_release_evidence(e,self.path))

    def test_forged_eligibility_and_missing_target(self):
        self.validate();e=Path(self.tmp.name)/"evidence.json"
        for mutation in ("eligible","missing","duplicate","config","bare_pass","unknown_status"):
            r=vnext.new_evidence(self.policy,vnext.sha256(self.path))
            if mutation=="eligible":r["targets"][0]["release_eligible"]=True
            if mutation=="missing":r["targets"].pop()
            if mutation=="duplicate":r["targets"][1]=r["targets"][0]
            if mutation=="config":r["config_sha256"]="0"*64
            if mutation=="bare_pass":r["targets"][0]["conversion"]["status"]="pass"
            if mutation=="unknown_status":r["targets"][0]["conversion"]["status"]="host_pass"
            vnext.atomic_json(e,r)
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):vnext.verify_release_evidence(e,self.path)

    def test_reused_or_damaged_evidence(self):
        self.validate();base=Path(self.tmp.name);e=base/"evidence.json";log=base/"log.json"
        r=vnext.new_evidence(self.policy,vnext.sha256(self.path))
        log.write_text('{}')
        r["targets"][0]["conversion"]["evidence"]=[{"path":"log.json","sha256":vnext.sha256(log)}]
        vnext.atomic_json(e,r)
        with self.assertRaisesRegex(ValueError,"evidence_identity"):vnext.verify_release_evidence(e,self.path)
        log.write_text('{"changed":true}')
        with self.assertRaisesRegex(ValueError,"evidence_hash_mismatch"):vnext.verify_release_evidence(e,self.path)


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.directory=Path(self.tmp.name)

    def test_exact_source_extraction(self):
        verify_sources.verify()
        for suite in runner.BUSINESS_TARGETS:verify_sources.verify_suite(suite)

    def test_llvm_version_mismatch(self):
        for clang,opt in (("Apple clang version 22.1.8","LLVM version 22.1.8"),
                          ("clang version 22.1.8","LLVM version 22.1.7"),
                          ("clang version 21.1.0","LLVM version 21.1.0")):
            with self.subTest(clang=clang,opt=opt),self.assertRaises(runner.GateError):runner.check_versions(clang,opt)

    def test_missing_tools_overwrite_stale_success(self):
        (self.directory/"report.json").write_text('{"status":"HOST_VMP_PASS","vmp_verified":true}')
        p=subprocess.run([sys.executable,str(HERE/"run.py"),"--mode","xollvm","--clang","/no/such/clang",
                          "--suite","policy_selection","--output",str(self.directory)],capture_output=True,text=True)
        self.assertNotEqual(p.returncode,0)
        r=json.loads((self.directory/"report.json").read_text())
        self.assertFalse(r["vmp_verified"]);self.assertEqual(r["status"],"BLOCKED_OR_FAILED")

    def test_pass_report_requires_exact_targets(self):
        def record(name):return {"name":name,"skipped":False,"passes":[{"id":"vm","status":"ran","changed":True}]}
        file=self.directory/"passes.json"
        file.write_text(json.dumps({"functions":[record("one")]}))
        runner.inspect_pass_reports(self.directory,["one"])
        for rows in ([record("one")],[record("one"),record("one")],[record("one"),record("two"),record("extra")]):
            file.write_text(json.dumps({"functions":rows}))
            with self.subTest(rows=rows),self.assertRaises(runner.GateError):runner.inspect_pass_reports(self.directory,["one","two"])

    def test_unrelated_engine_does_not_prove_connection(self):
        instructions="  call void @__vm_engine(ptr @unrelated.vm.bytecode, ptr @x.vm.ophandlers)\n"
        with self.assertRaises(runner.GateError):runner.inspect_engine_call(instructions,"constant [1 x ptr] [ptr @__vm_engine]","x")

    def test_plugin_and_patch_mismatch(self):
        plugin=self.directory/"plugin.so";plugin.write_bytes(b"not executable")
        provenance=self.directory/"provenance.json"
        p={"schema_version":1,"xollvm_commit":runner.PINNED_COMMIT,"plugin_sha256":"0"*64,"llvm_version":"22.1.8","status":"built"}
        provenance.write_text(json.dumps(p))
        with self.assertRaises(runner.GateError):runner.check_provenance(provenance,plugin,"22.1.8")
        p.update(plugin_sha256=runner.sha256(plugin),schema_version=2,local_patch_set={"id":"wrong"},patched_source_tree_sha256="0"*64)
        provenance.write_text(json.dumps(p))
        with self.assertRaises(ValueError):runner.check_provenance(provenance,plugin,"22.1.8")

    @unittest.skipUnless(shutil.which("cc"),"host C compiler unavailable")
    def test_harness_rejects_corrupted_business_results(self):
        for suite,old,new in (("policy_selection","return selected_bits;","return selected_bits ^ 1u;"),
                              ("policy_selection","*out_selected_entries = selected_count;","*out_selected_entries = selected_count + 1u;"),
                              ("strong_mix","lane0 ^ lane1 ^ lane2 ^ lane3 ^ rc","lane0 ^ lane1 ^ lane2 ^ lane3 ^ rc ^ 1u")):
            with self.subTest(suite=suite,mutation=new):
                directory=self.directory/(suite+str(len(list(self.directory.iterdir()))))
                shutil.copytree(HERE/"suites"/suite,directory)
                plain=directory/"plain.o";protected=directory/"protected.o";exe=directory/"test"
                common=["cc","-std=c11","-O2","-Wall","-Wextra","-Werror"]
                subprocess.run(common+["-DCPRISK_VMP_PREFIX=plain_","-c",str(directory/"candidates.c"),"-o",str(plain)],check=True,capture_output=True)
                body=directory/"body.inc";self.assertIn(old,body.read_text());body.write_text(body.read_text().replace(old,new))
                subprocess.run(common+["-DCPRISK_VMP_PREFIX=protected_","-c",str(directory/"candidates.c"),"-o",str(protected)],check=True,capture_output=True)
                subprocess.run(common+[str(directory/"differential.c"),str(plain),str(protected),"-o",str(exe)],check=True,capture_output=True)
                result=subprocess.run([str(exe)],capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0);self.assertIn("FAIL",result.stderr)


if __name__=="__main__":unittest.main()
