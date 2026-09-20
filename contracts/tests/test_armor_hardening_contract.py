import re
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ArmorHardeningContractTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_release_scripts_are_syntax_valid_and_fail_closed(self) -> None:
        scripts = [
            ROOT / "RiskDetectorApp/Scripts/apply-cprisk-armor.sh",
            ROOT / "RiskDetectorApp/Scripts/inject-vm-self-expect.sh",
        ]
        for script in scripts:
            subprocess.run(["bash", "-n", str(script)], check=True)
            source = script.read_text(encoding="utf-8")
            self.assertIn("set -euo pipefail", source)
            self.assertNotIn("|| true", source)
            self.assertNotIn('--key "$CPRISK_ARMOR_KEY"', source)
            self.assertNotIn('--root-key-hex "$CPRISK_ARMOR_KEY"', source)

    def test_requested_armor_fails_if_tool_or_binary_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("CPRISK_")}
            env.update(
                SRCROOT=directory, TARGET_BUILD_DIR=directory,
                EXECUTABLE_PATH="missing-binary", CONFIGURATION="Release",
                SCRIPT_OUTPUT_FILE_1=str(Path(directory) / "stamp"),
                DERIVED_FILE_DIR=directory, CPRISK_ARMOR_REQUIRED="1",
            )
            result = subprocess.run(
                ["bash", str(ROOT / "RiskDetectorApp/Scripts/apply-cprisk-armor.sh")],
                env=env, capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("requested but toolroot or executable is missing", result.stderr)
            self.assertFalse((Path(directory) / "stamp").exists())

    def test_unconfigured_optional_skip_creates_dependency_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env = {key: value for key, value in os.environ.items()
                   if not key.startswith("CPRISK_")}
            env.update(
                SRCROOT=directory, TARGET_BUILD_DIR=directory,
                EXECUTABLE_PATH="missing-binary", CONFIGURATION="Release",
                SCRIPT_OUTPUT_FILE_1=str(Path(directory) / "stamp"),
                DERIVED_FILE_DIR=directory,
            )
            result = subprocess.run(
                ["bash", str(ROOT / "RiskDetectorApp/Scripts/apply-cprisk-armor.sh")],
                env=env, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((Path(directory) / "stamp").is_file())
            self.assertEqual((Path(directory) / "cprisk_armor_build_seed").read_text(), "")

    def test_xcode_sources_share_scripts_and_reserve_self_expect(self) -> None:
        project_yml = self.read("RiskDetectorApp/project.yml")
        pbxproj = self.read("RiskDetectorApp/RiskDetectorApp.xcodeproj/project.pbxproj")
        for source in (project_yml, pbxproj):
            self.assertIn("Scripts/apply-cprisk-armor.sh", source)
            self.assertIn("Scripts/inject-vm-self-expect.sh", source)
            self.assertIn("cprisk_armor_build_seed", source)
            self.assertIn("__swift5_mdvsk", source)
            self.assertNotIn("cprisk-vm-self-expect >/dev/null) || true", source)

    def test_pass_order_encodes_producer_runtime_dependencies(self) -> None:
        source = self.read("cprisk-armor/Sources/MachOKit/PassOrdering.swift")
        compact = re.sub(r"\s+", "", source)
        for dependency in (
            "9:[8]",
            "13:[8,9]",
            "4:[8,9,13]",
            "3:[4]",
            "12:[4,13]",
        ):
            self.assertIn(dependency, compact)
        self.assertRegex(compact, r"11:\[[^]]*6[^]]*13[^]]*\]")

    def test_mini_vm_xor_constant_is_cross_language_locked(self) -> None:
        swift = self.read("cprisk-armor/Sources/MachOKit/ArmorABI.swift")
        c_header = self.read("RiskDetectorApp/Sources/CRiskCore/include/cprisk_armor_abi.h")
        self.assertRegex(swift, r"miniVMBootstrapXor:\s*UInt8\s*=\s*0xA5")
        self.assertRegex(c_header, r"CPRISK_MINI_VM_BOOTSTRAP_XOR\s+0xA5u")

    def test_vm_self_check_kdf_has_no_runtime_session_dependency(self) -> None:
        producer = self.read("cprisk-armor/Sources/MachOKit/VMSelfExpectInjector.swift")
        runtime = self.read("RiskDetectorApp/Sources/CRiskCore/cprisk_vm_interpreter.c")
        start = runtime.index("static void cprisk_vm_selfchk_hmac_key_i")
        end = runtime.index("static uint64_t cprisk_vm_selfchk_fault_mask_i", start)
        kdf = runtime[start:end]
        self.assertIn("Data(count: 50)", producer)
        self.assertIn("uint8_t buf[50]", kdf)
        self.assertNotIn("cprisk_get_session_key", kdf)

    def test_static_whitebox_domains_use_build_stable_inputs(self) -> None:
        string_producer = self.read(
            "cprisk-armor/Sources/StringEncryptor/StringEncryptor.swift"
        )
        import_producer = self.read(
            "cprisk-armor/Sources/ImportEncryptor/ImportEncryptor.swift"
        )
        header_producer = self.read(
            "cprisk-armor/Sources/HeaderEncryptor/HeaderEncryptor.swift"
        )
        runtime = self.read("RiskDetectorApp/Sources/CRiskCore/cprisk_whitebox.c")

        for producer, domain in (
            (string_producer, ".pass1StringKey"),
            (import_producer, ".importEncryptionKey"),
            (header_producer, ".headerEncryptionKey"),
        ):
            start = producer.index(f"domain: {domain}")
            window = producer[start : start + 180]
            self.assertIn("Data(repeating: 0, count: ArmorABI.hashSize)", window)

        binding_start = runtime.index("static int cprisk_whitebox_prepare_prf_input_i")
        binding_end = runtime.index("static uint32_t cprisk_base_capabilities_i", binding_start)
        binding = runtime[binding_start:binding_end]
        self.assertIn("domain_id > CPRISK_WHITEBOX_DOMAIN_SESSION_BOUND", binding)
        self.assertNotIn("domain_id > CPRISK_WHITEBOX_DOMAIN_HEADER_ENCRYPTION", binding)


if __name__ == "__main__":
    unittest.main()
