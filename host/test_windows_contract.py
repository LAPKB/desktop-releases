"""Structural coverage/payload regressions; approved CI only.

No key, signature, app binary, release, historical adoption or live root is
fabricated. These tests are not authenticated publication/runtime evidence.
"""
import copy
from types import SimpleNamespace
import unittest

import release_contract as contract
import publish_remote as publisher


class WindowsContractTests(unittest.TestCase):
    def fixture(self, app="papir", executable="papir-v3", version="0.1.5"):
        return {
            "build": {"runId": "123", "runAttempt": 1, "profile": "public-staging"},
            "windowsPayload": {
                "schema": "lapkb-windows-payload-v1", "productName": contract.WINDOWS_PRODUCTS[app],
                "executable": executable + ".exe", "architecture": "x86_64", "version": version,
                "installMode": "currentUser", "files": [
                    {"path": executable + ".exe", "size": 10, "sha256": "a" * 64}
                ],
            },
        }

    def test_payload_structure_uses_real_app_names_and_exact_scope(self):
        for app, executable, version in [
            ("papir", "papir-v3", "0.1.5"), ("bdautodial", "bdautodial", "0.2.4"),
            ("bestdose", "bestdose", "1.0.11"), ("checkerboard", "checkmate-desktop", "0.8.2"),
        ]:
            record = self.fixture(app, executable, version)
            contract._validate_windows_payload(record, app, version, executable)
            for field, value in [("architecture", "aarch64"), ("version", "0.0.1"),
                                 ("installMode", "perMachine"), ("executable", "exported.exe"),
                                 ("productName", "Unknown")]:
                changed = copy.deepcopy(record)
                changed["windowsPayload"][field] = value
                with self.subTest(app=app, field=field), self.assertRaises(contract.ContractError):
                    contract._validate_windows_payload(changed, app, version, executable)

    def test_inventory_rejects_missing_duplicate_traversal_device_and_hash_evidence(self):
        record = self.fixture()
        for path in ["../app.exe", "C:/app.exe", "a\\app.exe", "CON", "file.exe:stream", "x.", ""]:
            changed = copy.deepcopy(record)
            changed["windowsPayload"]["files"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(contract.ContractError):
                contract._validate_windows_payload(changed, "papir", "0.1.5", "papir-v3")
        for files in [[], record["windowsPayload"]["files"] * 2,
                      [{"path": "papir-v3.exe", "size": 0, "sha256": "a" * 64}],
                      [{"path": "papir-v3.exe", "size": 10, "sha256": "caller-hash"}]]:
            changed = copy.deepcopy(record)
            changed["windowsPayload"]["files"] = files
            with self.assertRaises(contract.ContractError):
                contract._validate_windows_payload(changed, "papir", "0.1.5", "papir-v3")

    def test_source_run_attempt_and_profile_are_not_optional(self):
        record = self.fixture()
        for field, value in [("runId", "0"), ("runId", "00123"), ("runAttempt", 0),
                             ("runAttempt", True), ("profile", "unconfigured")]:
            changed = copy.deepcopy(record)
            changed["build"][field] = value
            with self.subTest(field=field), self.assertRaises(contract.ContractError):
                contract._validate_windows_payload(changed, "papir", "0.1.5", "papir-v3")

    def test_fixed_coverage_feed_target_identity_rejects_confusion(self):
        policy = SimpleNamespace(apps={"papir": {"allowedCoverages": ["windows-x64"],
            "channels": {"stable": {"manualTargets": []}}}})
        record = {"app": "papir", "channel": "stable", "coverage": "windows-x64",
                  "feed": "latest-windows.json", "targets": ["windows-x86_64"], "distribution": "signed"}
        publisher._validate_scope(record, policy)
        for key, value in (("coverage", "full-six"), ("feed", "latest.json"), ("targets", ["darwin-aarch64"]),
                           ("distribution", "manual-checksum"), ("channel", "beta")):
            with self.subTest(key=key), self.assertRaises(publisher.PublicationError):
                publisher._validate_scope({**record, key: value}, policy)
        self.assertEqual(contract.feed_for_coverage("full-six"), "latest.json")
        self.assertEqual(contract.feed_for_coverage("windows-x64"), "latest-windows.json")
        with self.assertRaises(contract.ContractError):
            contract.feed_for_coverage("caller-feed")


if __name__ == "__main__":
    unittest.main()
