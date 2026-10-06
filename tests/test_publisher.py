from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
HOST = Path(__file__).resolve().parents[1] / "host"
sys.path.insert(0, str(HOST))

import publish_remote as publisher
import release_contract as contract
from support import (
    SIGNER, VERIFIER, SyntheticSigner, canonical, make_bundle, make_root,
    make_trust, stage_bundle, make_historical_input, public_snapshot,
)


class PublisherCoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not VERIFIER.is_file() or not SIGNER.is_file():
            raise RuntimeError("run scripts/test-publisher.sh to build the locked verifier and test signer")
        cls.signer = SyntheticSigner()

    @classmethod
    def tearDownClass(cls):
        cls.signer.close()

    def setUp(self):
        self.temp, self.root = make_root()
        self.policy, self.trust = make_trust(self.root, self.signer.public_key, self.signer.key_id)

    def tearDown(self):
        self.temp.cleanup()

    def _stage(self, bundle):
        return stage_bundle(publisher, self.policy, bundle)

    def _validate(self, app, channel, bundle):
        name, files = self._stage(bundle)
        try:
            return contract.validate_release(
                app, channel, files, self.policy, verifier=VERIFIER,
                scratch=files[next(iter(files))].parent,
            )
        finally:
            publisher.remove_staging(self.policy, name)

    def _publish(self, app, channel, bundle):
        name, files = self._stage(bundle)
        try:
            return publisher.publish_files(
                self.policy, app, channel, files, name, verifier=VERIFIER,
            )
        finally:
            publisher.remove_staging(self.policy, name)

    def test_unconfigured_publisher_example_fails_closed_without_keys(self):
        example = json.loads((HOST / "publisher-trust.example.json").read_bytes())
        self.assertEqual(set(example["apps"]), set(contract.APP_IDS))
        for app, entry in example["apps"].items():
            self.assertIsNone(entry["branch"])
            self.assertIsNone(entry["channels"]["stable"]["publicKey"])
            self.assertIsNone(entry["channels"]["stable"]["keyId"])
            self.assertNotIn("retainedSourceRecords", entry)
            self.assertEqual(entry["allowedCoverages"], ["launcher-desktop"] if app == "launcher" else ["macos-arm64", "windows-x64"])
        with self.assertRaises(contract.ContractError):
            contract.validate_policy(example)

    def test_all_five_apps_and_all_six_target_profiles_validate(self):
        for app in contract.APP_IDS:
            with self.subTest(app=app):
                bundle = make_bundle(self.signer, self.policy, app=app)
                release = self._validate(app, "stable", bundle)
                self.assertEqual(set(release["receipt"]["targets"]), set(contract.TARGETS))
                self.assertEqual(len(release["receipt"]["targets"]), 6)

    def test_complete_six_target_publication_retry_legacy_and_catalog(self):
        bundle = make_bundle(self.signer, self.policy, app="launcher")
        first = self._publish("launcher", "stable", bundle)
        self.assertEqual(first["status"], "published")
        retry = self._publish("launcher", "stable", bundle)
        self.assertEqual(retry["status"], "identical-retry")
        self.assertEqual(retry["inventory"], first["inventory"])

        channel = self.root / "downloads" / "launcher" / "stable"
        legacy = self.root / "launcher"
        self.assertEqual((channel / "latest.json").read_bytes(), bundle["latest.json"])
        self.assertEqual((legacy / "latest.json").read_bytes(), bundle["latest.json"])
        receipt_name = next(name for name in bundle if name.startswith("release-receipt-") and name.endswith(".json"))
        self.assertEqual((channel / receipt_name).read_bytes(), bundle[receipt_name])
        catalog = json.loads((self.root / "downloads" / "catalog.json").read_text())
        files = catalog["apps"]["launcher"]["channels"]["stable"]["files"]
        self.assertEqual(len(files), 6)
        self.assertEqual({info["target"] for info in files.values()}, set(contract.TARGETS))
        self.assertTrue(all("installer" in info["roles"] for info in files.values()))
        page = (self.root / "downloads" / "index.html").read_text()
        self.assertIn("&lt;bundle&gt;", page)
        self.assertNotIn("<bundle>", page)

    def test_bestdose_windows_uses_configured_nsis_not_a_hardcoded_msi(self):
        self._windows_policy()
        bundle = make_bundle(self.signer, self.policy, app="bestdose", version="1.0.11", coverage="windows-x64")
        release = self._validate("bestdose", "stable", bundle)
        records = release["receipt"]["targets"]["windows-x86_64"]["artifacts"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["kind"], "nsis")
        self.assertEqual(records[0]["roles"], ["installer", "updater"])
        self.assertTrue(records[0]["name"].endswith(".exe"))
        self.assertFalse(any(name.endswith(".msi") for name in bundle))

    def test_missing_target_is_rejected_after_real_attestation_verification(self):
        bundle = make_bundle(self.signer, self.policy, omit_target="linux-x86_64")
        name, files = self._stage(bundle)
        try:
            with self.assertRaisesRegex(contract.ContractError, "declared target coverage"):
                contract.validate_release("launcher", "stable", files, self.policy,
                                          verifier=VERIFIER, scratch=files[next(iter(files))].parent)
        finally:
            publisher.remove_staging(self.policy, name)

    def test_minimum_protected_checkmate_version_is_explicit_and_enforced(self):
        bundle = make_bundle(self.signer, self.policy, app="checkerboard", version="0.9.9")
        name, files = self._stage(bundle)
        try:
            with self.assertRaisesRegex(contract.ContractError, "below the configured minimum"):
                contract.validate_release("checkerboard", "stable", files, self.policy,
                                          verifier=VERIFIER, scratch=files[next(iter(files))].parent)
        finally:
            publisher.remove_staging(self.policy, name)

    def test_signature_receipt_manifest_and_asset_tampering_fail_closed(self):
        original = make_bundle(self.signer, self.policy)
        attestation_name = next(name for name in original if name.startswith("build-attestation-") and name.endswith(".json"))
        receipt_name = next(name for name in original if name.startswith("release-receipt-") and name.endswith(".json"))
        cases = (
            (attestation_name + ".sig", lambda value: bytes([value[0] ^ 1]) + value[1:]),
            (receipt_name, lambda value: value[:-1] + bytes([value[-1] ^ 1])),
            (receipt_name + ".sig", lambda value: bytes([value[0] ^ 1]) + value[1:]),
            ("latest.json", lambda value: value + b" "),
        )
        package_name = next(name for name in original if name.endswith(".bundle.zip"))
        cases += ((package_name, lambda value: value + b"tamper"),)
        cases += (("unexpected.bin", lambda value: value),)
        for name, mutate in cases:
            with self.subTest(file=name):
                bundle = dict(original)
                if name == "unexpected.bin":
                    bundle[name] = b"unlisted"
                else:
                    bundle[name] = mutate(bundle[name])
                stage, files = self._stage(bundle)
                try:
                    with self.assertRaises(contract.ContractError):
                        contract.validate_release("launcher", "stable", files, self.policy,
                                                  verifier=VERIFIER, scratch=files[next(iter(files))].parent)
                finally:
                    publisher.remove_staging(self.policy, stage)

    def test_tampered_embedded_updater_signature_is_not_trusted(self):
        bundle = make_bundle(self.signer, self.policy)
        attestation_name = next(name for name in bundle if name.startswith("build-attestation-") and name.endswith(".json"))
        receipt_name = next(name for name in bundle if name.startswith("release-receipt-") and name.endswith(".json"))
        attestation = json.loads(bundle[attestation_name])
        target = "darwin-aarch64"
        updater = next(item for item in attestation["targets"][target]["artifacts"]
                       if "updater" in item["roles"])
        updater["updaterSignature"] = base64.b64encode(b"not a Minisign signature").decode()
        att_bytes = canonical(attestation)
        bundle[attestation_name] = att_bytes
        bundle[attestation_name + ".sig"] = self.signer.sign(att_bytes)
        manifest = json.loads(bundle["latest.json"])
        manifest["platforms"][target]["signature"] = updater["updaterSignature"]
        manifest_bytes = canonical(manifest)
        bundle["latest.json"] = manifest_bytes
        receipt = json.loads(bundle[receipt_name])
        receipt["buildAttestationSha256"] = hashlib.sha256(att_bytes).hexdigest()
        receipt["manifestSha256"] = hashlib.sha256(manifest_bytes).hexdigest()
        receipt_bytes = canonical(receipt)
        bundle[receipt_name] = receipt_bytes
        bundle[receipt_name + ".sig"] = self.signer.sign(receipt_bytes)
        name, files = self._stage(bundle)
        try:
            with self.assertRaises(contract.ContractError):
                contract.validate_release("launcher", "stable", files, self.policy,
                                          verifier=VERIFIER, scratch=files[next(iter(files))].parent)
        finally:
            publisher.remove_staging(self.policy, name)

    def test_same_version_conflict_stale_retry_and_historical_assets(self):
        first = make_bundle(self.signer, self.policy, version="1.2.3", nonce="first")
        newer = make_bundle(self.signer, self.policy, version="1.3.0", nonce="newer")
        conflict = make_bundle(self.signer, self.policy, version="1.2.3", nonce="different")
        self._publish("launcher", "stable", first)
        channel = self.root / "downloads" / "launcher" / "stable"
        old_name = next(name for name in first if name.endswith(".bundle.zip"))
        old_bytes = (channel / old_name).read_bytes()
        with self.assertRaisesRegex(publisher.PublicationError, "same-version release conflicts"):
            self._publish("launcher", "stable", conflict)
        self.assertEqual((channel / "latest.json").read_bytes(), first["latest.json"])
        self._publish("launcher", "stable", newer)
        self.assertTrue((channel / old_name).is_file())
        self.assertEqual((channel / old_name).read_bytes(), old_bytes)
        with self.assertRaisesRegex(publisher.PublicationError, "stale release retry"):
            self._publish("launcher", "stable", first)
        catalog = json.loads((self.root / "downloads" / "catalog.json").read_bytes())
        current_files = catalog["apps"]["launcher"]["channels"]["stable"]["files"]
        self.assertIn(old_name, current_files)
        self.assertEqual(current_files[old_name]["version"], "1.2.3")
        self.assertEqual(catalog["apps"]["launcher"]["channels"]["stable"]["targets"]["darwin-aarch64"]["version"], "1.3.0")

    def test_catalog_tampering_blocks_publication_and_unlisted_files_are_not_cataloged(self):
        bundle = make_bundle(self.signer, self.policy)
        self._publish("launcher", "stable", bundle)
        channel = self.root / "downloads" / "launcher" / "stable"
        unlisted = channel / "unlisted.bin"
        unlisted.write_bytes(b"preserve, never adopt")
        publisher.recover_publications(self.policy, verifier=VERIFIER)
        catalog_path = self.root / "downloads" / "catalog.json"
        catalog = json.loads(catalog_path.read_bytes())
        names = catalog["apps"]["launcher"]["channels"]["stable"]["files"]
        self.assertNotIn(unlisted.name, names)
        catalog_path.write_bytes(catalog_path.read_bytes() + b" ")
        with self.assertRaisesRegex(publisher.PublicationError, "catalog differs"):
            publisher.recover_publications(self.policy, verifier=VERIFIER)

    def test_unreviewed_existing_downloads_require_bootstrap_gate(self):
        downloads = self.root / "downloads"
        downloads.mkdir()
        (downloads / "catalog.json").write_text("{}")
        with self.assertRaisesRegex(publisher.PublicationError, "reviewed bootstrap/migration"):
            publisher.recover_publications(self.policy, verifier=VERIFIER)
        self.assertEqual((downloads / "catalog.json").read_text(), "{}")

    def test_unreviewed_legacy_feed_also_requires_bootstrap(self):
        alias = self.root / "launcher"
        alias.mkdir()
        (alias / "latest.json").write_text("{}")
        with self.assertRaisesRegex(publisher.PublicationError, "reviewed bootstrap/migration"):
            publisher.recover_publications(self.policy, verifier=VERIFIER)
        self.assertEqual((alias / "latest.json").read_text(), "{}")

    def test_frame_round_trip_and_duplicate_oversize_truncated_extra_and_bad_types(self):
        bundle = {"a.bin": b"first", "b.bin": b"second"}
        encoded = io.BytesIO()
        publisher.write_payload(encoded, "launcher", "stable", {
            key: self._source_file(key, value) for key, value in bundle.items()
        })
        with tempfile.TemporaryDirectory() as raw_stage:
            app, channel, restored = publisher.read_payload(io.BytesIO(encoded.getvalue()), Path(raw_stage))
            self.assertEqual((app, channel), ("launcher", "stable"))
            self.assertEqual({name: path.read_bytes() for name, path in restored.items()}, bundle)

        duplicate_header = {
            "schema": "lapkb-publish-frame-v1", "app": "launcher", "channel": "stable",
            "files": [self._frame_record("a.bin", b"a"), self._frame_record("a.bin", b"a")],
        }
        with tempfile.TemporaryDirectory() as raw_stage:
            with self.assertRaisesRegex(publisher.PublicationError, "duplicate"):
                publisher.read_payload(self._frame(duplicate_header, b"a"), Path(raw_stage))

        oversized = publisher.FRAME_PREFIX.pack(publisher.FRAME_MAGIC, publisher.MAX_HEADER_BYTES + 1)
        with tempfile.TemporaryDirectory() as raw_stage:
            with self.assertRaisesRegex(publisher.PublicationError, "oversized"):
                publisher.read_payload(io.BytesIO(oversized), Path(raw_stage))

        bad_bool = {"schema": "lapkb-publish-frame-v1", "app": "launcher", "channel": "stable",
                    "files": [{"name": "a.bin", "size": True, "sha256": hashlib.sha256(b"a").hexdigest()}]}
        with tempfile.TemporaryDirectory() as raw_stage:
            with self.assertRaisesRegex(publisher.PublicationError, "size"):
                publisher.read_payload(self._frame(bad_bool, b"a"), Path(raw_stage))

        truncated = {"schema": "lapkb-publish-frame-v1", "app": "launcher", "channel": "stable",
                     "files": [self._frame_record("a.bin", b"abcde")]}
        with tempfile.TemporaryDirectory() as raw_stage:
            with self.assertRaisesRegex(publisher.PublicationError, "truncated"):
                publisher.read_payload(self._frame(truncated, b"a"), Path(raw_stage))

        one = {"schema": "lapkb-publish-frame-v1", "app": "launcher", "channel": "stable",
               "files": [self._frame_record("a.bin", b"a")]}
        with tempfile.TemporaryDirectory() as raw_stage:
            with self.assertRaisesRegex(publisher.PublicationError, "trailing"):
                publisher.read_payload(self._frame(one, b"a", extra=b"x"), Path(raw_stage))

        for invalid_name in ("../escape", ".", "..", "nested/file"):
            bad = {"schema": "lapkb-publish-frame-v1", "app": "launcher", "channel": "stable",
                   "files": [self._frame_record(invalid_name, b"a")]}
            with self.subTest(name=invalid_name), tempfile.TemporaryDirectory() as raw_stage:
                with self.assertRaises(publisher.PublicationError):
                    publisher.read_payload(self._frame(bad, b"a"), Path(raw_stage))

        scalar_header = canonical(7)
        scalar_frame = publisher.FRAME_PREFIX.pack(publisher.FRAME_MAGIC, len(scalar_header)) + scalar_header
        with tempfile.TemporaryDirectory() as raw_stage:
            with self.assertRaisesRegex(publisher.PublicationError, "canonical"):
                publisher.read_payload(io.BytesIO(scalar_frame), Path(raw_stage))

        duplicate_json = (b'{"schema":"lapkb-publish-frame-v1","app":"launcher",'
                          b'"app":"launcher","channel":"stable","files":[]}')
        payload = publisher.FRAME_PREFIX.pack(publisher.FRAME_MAGIC, len(duplicate_json)) + duplicate_json
        with tempfile.TemporaryDirectory() as raw_stage:
            with self.assertRaisesRegex(contract.ContractError, "duplicate JSON key"):
                publisher.read_payload(io.BytesIO(payload), Path(raw_stage))

    def _source_file(self, name, data):
        path = self.root / name
        path.write_bytes(data)
        os.chmod(path, 0o600)
        return path

    @staticmethod
    def _frame_record(name, data):
        return {"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}

    @staticmethod
    def _frame(header, bodies, extra=b""):
        encoded = canonical(header)
        return io.BytesIO(publisher.FRAME_PREFIX.pack(publisher.FRAME_MAGIC, len(encoded))
                          + encoded + bodies + extra)

    def test_symlink_ancestor_descendant_and_special_file_confinement(self):
        outside = self.root.parent / "outside"
        outside.mkdir()
        symlink_root = self.root.parent / "root-link"
        symlink_root.symlink_to(self.root, target_is_directory=True)
        bad_policy, _ = make_trust(symlink_root, self.signer.public_key, self.signer.key_id)
        with self.assertRaises((publisher.PublicationError, OSError)):
            publisher.recover_publications(bad_policy, verifier=VERIFIER)

        ancestor = self.root.parent / "ancestor-link"
        ancestor.symlink_to(self.root.parent, target_is_directory=True)
        nested_policy, _ = make_trust(ancestor / "new-root", self.signer.public_key, self.signer.key_id)
        with self.assertRaises((publisher.PublicationError, OSError)):
            publisher.recover_publications(nested_policy, verifier=VERIFIER)

        (self.root / "downloads").symlink_to(outside, target_is_directory=True)
        with self.assertRaises((publisher.PublicationError, OSError)):
            publisher.recover_publications(self.policy, verifier=VERIFIER)
        self.assertEqual(list(outside.iterdir()), [])
        (self.root / "downloads").unlink()

        bundle = make_bundle(self.signer, self.policy)
        name, files = self._stage(bundle)
        fifo_name = next(filename for filename in files if filename.endswith(".bundle.zip"))
        files[fifo_name].unlink()
        os.mkfifo(files[fifo_name])
        try:
            with self.assertRaises(contract.ContractError):
                contract.validate_release("launcher", "stable", files, self.policy,
                                          verifier=VERIFIER, scratch=files[next(iter(files))].parent)
        finally:
            files[fifo_name].unlink()
            publisher.remove_staging(self.policy, name)

    def test_two_real_publisher_processes_serialize_and_retry(self):
        bundle = make_bundle(self.signer, self.policy)
        with tempfile.TemporaryDirectory(prefix="lapkb-bundle-") as raw_bundle:
            bundle_dir = Path(raw_bundle)
            os.chmod(bundle_dir, 0o700)
            for name, data in bundle.items():
                target = bundle_dir / name
                target.write_bytes(data)
                os.chmod(target, 0o600)
            trust_json = json.dumps(self.trust, separators=(",", ":"))
            code = r'''
import json, os, shutil, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import publish_remote, release_contract
policy = release_contract.validate_policy(json.loads(sys.argv[2]))
app, channel, source, verifier = sys.argv[3:]
name, stage = publish_remote.create_staging(policy)
files = {}
try:
    for item in Path(source).iterdir():
        dest = stage / item.name
        shutil.copyfile(item, dest)
        os.chmod(dest, 0o600)
        files[item.name] = dest
    result = publish_remote.publish_files(policy, app, channel, files, name, verifier=Path(verifier))
    print(json.dumps(result, sort_keys=True))
finally:
    publish_remote.remove_staging(policy, name)
'''
            args = [sys.executable, "-c", code, str(HOST), trust_json, "launcher", "stable",
                    str(bundle_dir), str(VERIFIER)]
            first = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            second = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            outputs = [process.communicate(timeout=90) for process in (first, second)]
            self.assertEqual([first.returncode, second.returncode], [0, 0], outputs)
            statuses = {json.loads(stdout)["status"] for stdout, _ in outputs}
            self.assertEqual(statuses, {"published", "identical-retry"})

    def test_restart_completes_every_durable_promotion_boundary(self):
        bundle = make_bundle(self.signer, self.policy)
        package_names = sorted(name for name in bundle if name.endswith(".bundle.zip"))
        inventory_names = sorted(name for name in bundle if name != "latest.json")
        boundaries = ["transaction", "journal"]
        boundaries.extend("asset:" + name for name in inventory_names)
        boundaries.extend("legacy:" + name for name in package_names)
        boundaries.extend(["feed:latest.json", "feed:legacy", "state", "catalog", "index", "journal-cleared"])

        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                temp, root = make_root()
                policy, _ = make_trust(root, self.signer.public_key, self.signer.key_id)
                stage_name, files = stage_bundle(publisher, policy, bundle)
                original = publisher._checkpoint
                fired = []

                def interrupt(label):
                    if label == boundary and not fired:
                        fired.append(label)
                        raise RuntimeError("synthetic interruption")

                publisher._checkpoint = interrupt
                try:
                    with self.assertRaisesRegex(RuntimeError, "synthetic interruption"):
                        publisher.publish_files("" if False else policy, "launcher", "stable",
                                                files, stage_name, verifier=VERIFIER)
                finally:
                    publisher._checkpoint = original
                self.assertEqual(fired, [boundary])
                publisher.recover_publications(policy, verifier=VERIFIER)
                if boundary == "transaction":
                    self.assertFalse((root / "downloads").exists())
                    publisher.remove_staging(policy, stage_name)
                    stage_name, files = stage_bundle(publisher, policy, bundle)
                    publisher.publish_files(policy, "launcher", "stable", files, stage_name,
                                            verifier=VERIFIER)
                else:
                    self.assertEqual((root / "downloads" / "launcher" / "stable" / "latest.json").read_bytes(),
                                     bundle["latest.json"])
                    publisher.remove_staging(policy, stage_name)
                self.assertEqual((root / "launcher" / "latest.json").read_bytes(), bundle["latest.json"])
                temp.cleanup()

    def _windows_policy(self):
        self.policy, self.trust = make_trust(self.root, self.signer.public_key, self.signer.key_id, windows_only=True)

    def _initialize_fixture(self, root=None, policy=None):
        root, policy = root or self.root, policy or self.policy
        reviewed = make_historical_input(root, policy)
        path = root.parent / "fresh-reviewed-history.json"
        data = canonical(reviewed)
        path.write_bytes(data)
        os.chmod(path, 0o600)
        result = publisher.initialize_history(policy, path, hashlib.sha256(data).hexdigest())
        self.assertEqual(result["status"], "history-initialized")
        self.assertEqual(public_snapshot(root), reviewed["inventory"])
        return reviewed, path

    def test_windows_only_policy_does_not_fabricate_beta_or_six_profiles(self):
        self._windows_policy()
        for app in contract.APP_IDS:
            self.assertEqual(set(self.policy.apps[app]["channels"]), {"stable"})
            self.assertEqual(set(self.policy.apps[app]["channels"]["stable"]["profiles"]), {"windows-x86_64"})
            with self.assertRaisesRegex(contract.ContractError, "not configured"):
                contract.release_mode(self.policy, app, "beta", "windows-x64")
            with self.assertRaisesRegex(contract.ContractError, "not configured"):
                contract.release_mode(self.policy, app, "stable", "full-six")
        bad = copy.deepcopy(self.trust)
        bad["apps"]["papir"]["allowedCoverages"] = ["full-six"]
        with self.assertRaisesRegex(contract.ContractError, "coverage targets"):
            contract.validate_policy(bad)
        bad = copy.deepcopy(self.trust)
        bad["apps"]["papir"]["channels"]["stable"].update(publicKey=None, keyId=None, manualTargets=["windows-x86_64"])
        with self.assertRaisesRegex(contract.ContractError, "only supported for Launcher"):
            contract.validate_policy(bad)

    def test_history_initialization_is_explicit_fresh_protected_and_preserves_every_public_entry(self):
        self._windows_policy()
        reviewed = make_historical_input(self.root, self.policy)
        before = public_snapshot(self.root)
        with self.assertRaisesRegex(publisher.PublicationError, "automatic adoption is disabled"):
            publisher.recover_publications(self.policy, verifier=VERIFIER)
        self.assertEqual(public_snapshot(self.root), before)
        path = self.root.parent / "review.json"
        path.write_bytes(canonical(reviewed))
        os.chmod(path, 0o644)
        with self.assertRaises(contract.ContractError):
            publisher.initialize_history(self.policy, path, hashlib.sha256(path.read_bytes()).hexdigest())
        os.chmod(path, 0o600)
        with self.assertRaisesRegex(publisher.PublicationError, "approved SHA-256"):
            publisher.initialize_history(self.policy, path, "0" * 64)
        stale = {**reviewed, "observedAt": "2026-01-01T00:00:00Z"}
        path.write_bytes(canonical(stale))
        with self.assertRaisesRegex(publisher.PublicationError, "fresh UTC"):
            publisher.initialize_history(self.policy, path, hashlib.sha256(path.read_bytes()).hexdigest())
        drift = copy.deepcopy(reviewed)
        drift["inventory"].pop(next(p for p in drift["inventory"] if "opaque" in p))
        path.write_bytes(canonical(drift))
        with self.assertRaisesRegex(publisher.PublicationError, "complete public"):
            publisher.initialize_history(self.policy, path, hashlib.sha256(path.read_bytes()).hexdigest())
        path.write_bytes(canonical(reviewed))
        publisher.initialize_history(self.policy, path, hashlib.sha256(path.read_bytes()).hexdigest())
        publisher.recover_publications(self.policy, verifier=VERIFIER)
        self.assertEqual(public_snapshot(self.root), before)
        state = json.loads((self.root / publisher.STATE_NAME / publisher.STATE_FILE).read_bytes())
        self.assertEqual(state["history"], [])
        self.assertEqual(state["historical"]["schema"], "lapkb-observed-history-v1")
        self.assertNotIn("receipt", state["historical"])
        self.assertTrue(any(item["mode"] == 0o600 for item in before.values() if item["kind"] == "file"))
        with self.assertRaisesRegex(publisher.PublicationError, "no existing state or journal"):
            publisher.initialize_history(self.policy, path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_mixed_mac_windows_catalog_current_versions_and_all_old_modes_feeds_history(self):
        self._windows_policy()
        reviewed, _ = self._initialize_fixture()
        before = public_snapshot(self.root)
        windows_versions = {"launcher": "0.1.9", "checkerboard": "0.8.2", "bdautodial": "0.2.4", "bestdose": "1.0.11", "papir": "0.1.5"}
        for app, version in windows_versions.items():
            bundle = make_bundle(self.signer, self.policy, app=app, version=version, coverage="windows-x64")
            result = self._publish(app, "stable", bundle)
            self.assertEqual(result["feed"], "latest-windows.json")
            self.assertEqual(result["targets"], ["windows-x86_64"])
            contract.validate_publication_result(result, self.policy)
        after = public_snapshot(self.root)
        for path, metadata in before.items():
            if path not in ("downloads/catalog.json", "downloads/index.html"):
                self.assertEqual(after[path], metadata, path)
        catalog = json.loads((self.root / "downloads/catalog.json").read_bytes())
        for item in reviewed["current"]:
            app = item["app"]
            channel = catalog["apps"][app]["channels"]["stable"]
            self.assertNotIn("version", channel)
            self.assertEqual(channel["targets"]["darwin-aarch64"]["version"], item["version"])
            self.assertEqual(channel["targets"]["darwin-aarch64"]["distribution"], "observed-history")
            self.assertEqual(channel["targets"]["windows-x86_64"]["version"], windows_versions[app])
            for name, metadata in reviewed["catalog"]["apps"][app]["channels"]["stable"]["files"].items():
                self.assertEqual(channel["files"][name], metadata)
        page = (self.root / "downloads/index.html").read_text()
        self.assertIn("manual / checksum only", page)
        self.assertIn("no updater signature or self-update", page)
        self.assertIn(".exe", page)
        self.assertNotIn("Current verified release installers", page)
        self.assertNotIn("opaque-old-placeholder", page)
        publisher.recover_publications(self.policy, verifier=VERIFIER)

    def test_launcher_manual_history_transitions_to_signed_two_target_updates(self):
        self._windows_policy()
        self._initialize_fixture()
        versions = {"launcher": "0.1.9", "checkerboard": "0.8.2", "bdautodial": "0.2.4", "bestdose": "1.0.11", "papir": "0.1.5"}
        for app, version in versions.items():
            self._publish(app, "stable", make_bundle(self.signer, self.policy, app=app, version=version, coverage="windows-x64"))
        before = public_snapshot(self.root)
        state_path = self.root / publisher.STATE_NAME / publisher.STATE_FILE
        old_state = json.loads(state_path.read_bytes())
        manual = next(r for r in old_state["history"] if r["app"] == "launcher")
        old_policy = self.policy
        updated = copy.deepcopy(self.trust)
        entry = updated["apps"]["launcher"]
        entry["allowedCoverages"] = ["launcher-desktop"]
        entry["retainedManualRecords"] = {"0.1.9": hashlib.sha256(canonical(manual)).hexdigest()}
        entry["channels"]["stable"] = {"publicKey": self.signer.public_key, "keyId": self.signer.key_id,
            "profiles": {"windows-x86_64": [{"id": "nsis", "extension": "exe", "kind": "nsis", "required": True, "roles": ["installer", "updater"]}],
            "darwin-aarch64": [{"id": "app-tar", "extension": "app.tar.gz", "kind": "app-tar-gz", "required": True, "roles": ["installer", "updater"]}]}}
        self.policy = contract.validate_policy(updated)
        # Existing exact records/bytes are valid under the new policy without
        # reinitializing, rewriting, re-signing or changing old null key IDs.
        publisher.recover_publications(self.policy, verifier=VERIFIER)
        self.assertEqual(json.loads(state_path.read_bytes()), old_state)
        self.assertEqual(public_snapshot(self.root), before)
        changed = copy.deepcopy(old_state)
        next(r for r in changed["history"] if r["app"] == "launcher")["source"]["commit"] = "b" * 40
        with self.assertRaises(publisher.PublicationError):
            publisher._validate_state(canonical(changed), self.policy)
        new_unsigned = make_bundle(None, old_policy, app="launcher", version="0.1.11", coverage="windows-x64")
        with self.assertRaises(contract.ContractError):
            contract.release_mode(self.policy, "launcher", "stable", "windows-x64")
        with self.assertRaises(contract.ContractError):
            self._validate("launcher", "stable", new_unsigned)
        signed = make_bundle(self.signer, self.policy, app="launcher", version="0.1.11", coverage="launcher-desktop")
        for name in ["build-attestation-0.1.11.json.sig", "release-receipt-0.1.11.json.sig"]:
            with self.assertRaises(contract.ContractError):
                self._validate("launcher", "stable", {n: b for n, b in signed.items() if n != name})
        result = self._publish("launcher", "stable", signed)
        self.assertEqual(result["targets"], ["darwin-aarch64", "windows-x86_64"])
        self.assertEqual(result["feed"], "latest.json")
        after = public_snapshot(self.root)
        for path, metadata in before.items():
            if path not in ("downloads/catalog.json", "downloads/index.html", "downloads/launcher/stable/latest.json", "launcher/latest.json"):
                self.assertEqual(after[path], metadata, path)
        new_state = json.loads(state_path.read_bytes())
        self.assertEqual(new_state["historical"], old_state["historical"])
        self.assertTrue(all(record in new_state["history"] for record in old_state["history"]))
        self.assertEqual(next(r for r in new_state["history"] if r["app"] == "launcher" and r["version"] == "0.1.9"), manual)
        feed = json.loads((self.root / "downloads/launcher/stable/latest.json").read_bytes())
        self.assertEqual(set(feed["platforms"]), {"darwin-aarch64", "windows-x86_64"})
        publisher.recover_publications(self.policy, verifier=VERIFIER)

    def test_manual_launcher_has_no_key_signature_updater_or_unsigned_app_escape(self):
        self._windows_policy()
        manual_policy = self.policy.apps["launcher"]["channels"]["stable"]
        self.assertIsNone(manual_policy["publicKey"])
        self.assertIsNone(manual_policy["keyId"])
        bundle = make_bundle(None, self.policy, app="launcher", version="0.1.9", coverage="windows-x64")
        self.assertFalse(any(name.endswith(".sig") for name in bundle))
        name, files = self._stage(bundle)
        try:
            release = contract.validate_release("launcher", "stable", files, self.policy,
                                                verifier=Path("/nonexistent-verifier"))
            receipt = release["receipt"]
            self.assertIsNone(receipt["signatureKeyId"])
            self.assertIsNone(receipt["targets"]["windows-x86_64"]["roles"]["updater"])
            self.assertNotIn("installerSignature", receipt["targets"]["windows-x86_64"])
            self.assertNotIn("platforms", json.loads(release["manifestBytes"]))
        finally:
            publisher.remove_staging(self.policy, name)
        for version in ("0.1.11", "1.2.3"):
            unsigned = make_bundle(None, self.policy, app="launcher", version=version, coverage="windows-x64")
            with self.subTest(version=version), self.assertRaisesRegex(
                    contract.ContractError, "new Launcher updates require signed bootstrap trust"):
                self._validate("launcher", "stable", unsigned)
        for app in ("papir", "checkerboard", "bdautodial", "bestdose"):
            signed = make_bundle(self.signer, self.policy, app=app, coverage="windows-x64")
            unsigned = {key: value for key, value in signed.items() if not key.endswith(".sig")}
            with self.subTest(app=app), self.assertRaises(contract.ContractError):
                self._validate(app, "stable", unsigned)
        claimed = dict(bundle)
        claimed["release-receipt-0.1.9.json.sig"] = b"no manual signature claim allowed"
        with self.assertRaisesRegex(contract.ContractError, "unexpected files"):
            self._validate("launcher", "stable", claimed)

    def test_windows_feed_confusion_provenance_payload_and_wrong_signature_fail_closed(self):
        self._windows_policy()
        original = make_bundle(self.signer, self.policy, app="checkerboard", version="0.8.2", coverage="windows-x64")
        for names in ({**original, "latest.json": original["latest-windows.json"]},
                      {("latest.json" if name == "latest-windows.json" else name): data for name, data in original.items()}):
            with self.assertRaises(contract.ContractError):
                self._validate("checkerboard", "stable", names)
        attestation_name = "build-attestation-0.8.2.json"
        attestation = json.loads(original[attestation_name])
        cases = [("build", "runId", "0"), ("build", "runAttempt", True), ("build", "profile", "development"),
                 ("windowsPayload", "executable", "checkmate.exe"), ("windowsPayload", "installMode", "perMachine")]
        for section, key, value in cases:
            changed = copy.deepcopy(attestation)
            changed["targets"]["windows-x86_64"][section][key] = value
            bundle = {**original, attestation_name: canonical(changed),
                      attestation_name + ".sig": self.signer.sign(canonical(changed))}
            with self.subTest(section=section, key=key), self.assertRaises(contract.ContractError):
                self._validate("checkerboard", "stable", bundle)
        wrong = SyntheticSigner()
        try:
            bundle = {**original, attestation_name + ".sig": wrong.sign(original[attestation_name])}
            with self.assertRaisesRegex(contract.ContractError, "signature verification failed"):
                self._validate("checkerboard", "stable", bundle)
        finally:
            wrong.close()

    def test_windows_exact_retry_conflict_stale_and_retained_receipts(self):
        self._windows_policy()
        self._initialize_fixture()
        first = make_bundle(self.signer, self.policy, app="papir", version="0.1.5", coverage="windows-x64")
        result = self._publish("papir", "stable", first)
        self.assertEqual(self._publish("papir", "stable", first)["status"], "identical-retry")
        before = public_snapshot(self.root)
        conflicting = make_bundle(self.signer, self.policy, app="papir", version="0.1.5", coverage="windows-x64", nonce="other-source-bytes")
        with self.assertRaisesRegex(publisher.PublicationError, "same-version release conflicts"):
            self._publish("papir", "stable", conflicting)
        self.assertEqual(public_snapshot(self.root), before)
        newer = make_bundle(self.signer, self.policy, app="papir", version="0.1.6", coverage="windows-x64")
        self._publish("papir", "stable", newer)
        for item in result["inventory"]:
            if item["name"] != "latest-windows.json":
                path = self.root / "downloads/papir/stable" / item["name"]
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), item["sha256"])
        with self.assertRaisesRegex(publisher.PublicationError, "stale release retry"):
            self._publish("papir", "stable", first)
        catalog = json.loads((self.root / "downloads/catalog.json").read_bytes())
        self.assertIn(next(name for name in first if name.endswith(".exe")), catalog["apps"]["papir"]["channels"]["stable"]["files"])

    def test_configured_full_six_and_windows_scopes_do_not_collapse_versions_or_feeds(self):
        # Keep the original full-six path, explicitly enabling Windows only for Papir.
        trust = copy.deepcopy(self.trust)
        entry = trust["apps"]["papir"]
        entry["allowedCoverages"] = ["full-six", "windows-x64"]
        profile = [{"id": "nsis", "extension": "exe", "kind": "nsis", "roles": ["installer", "updater"], "required": True}]
        for channel in entry["channels"].values():
            channel["profiles"]["windows-x86_64"] = profile
        self.policy = contract.validate_policy(trust)
        full = make_bundle(self.signer, self.policy, app="papir", version="1.2.3")
        self._publish("papir", "stable", full)
        windows = make_bundle(self.signer, self.policy, app="papir", version="1.2.4", coverage="windows-x64")
        self._publish("papir", "stable", windows)
        channel = self.root / "downloads/papir/stable"
        self.assertEqual((channel / "latest.json").read_bytes(), full["latest.json"])
        self.assertEqual((self.root / "papir/latest.json").read_bytes(), full["latest.json"])
        self.assertEqual((channel / "latest-windows.json").read_bytes(), windows["latest-windows.json"])
        state = json.loads((self.root / publisher.STATE_NAME / publisher.STATE_FILE).read_bytes())
        self.assertEqual(len(publisher._latest_by_app_channel(state)), 2)
        catalog = json.loads((self.root / "downloads/catalog.json").read_bytes())
        targets = catalog["apps"]["papir"]["channels"]["stable"]["targets"]
        self.assertEqual(targets["darwin-aarch64"]["version"], "1.2.3")
        self.assertEqual(targets["windows-x86_64"]["version"], "1.2.4")
        before = public_snapshot(self.root)
        same_version_other_scope = make_bundle(self.signer, self.policy, app="papir", version="1.2.4")
        with self.assertRaisesRegex(publisher.PublicationError, "same-version release conflicts"):
            self._publish("papir", "stable", same_version_other_scope)
        with self.assertRaisesRegex(publisher.PublicationError, "stale release retry"):
            self._publish("papir", "stable", full)
        self.assertEqual(public_snapshot(self.root), before)

    def test_history_initialization_rejects_links_and_restart_never_rewrites_public_files(self):
        from unittest import mock
        self._windows_policy()
        reviewed = make_historical_input(self.root, self.policy)
        path = self.root.parent / "fresh-history.json"
        data = canonical(reviewed)
        path.write_bytes(data)
        os.chmod(path, 0o600)
        outside = self.root.parent / "outside-history"
        outside.write_bytes(b"outside")
        link = self.root / "escape-link"
        link.symlink_to(outside)
        with self.assertRaises((publisher.PublicationError, OSError)):
            publisher.initialize_history(self.policy, path, hashlib.sha256(data).hexdigest())
        self.assertTrue(link.is_symlink())
        self.assertEqual(outside.read_bytes(), b"outside")
        link.unlink()
        alias = self.root / "hardlink-history"
        target = next(p for p in self.root.rglob("*.zip") if p.is_file())
        os.link(target, alias)
        with self.assertRaises(publisher.PublicationError):
            publisher.initialize_history(self.policy, path, hashlib.sha256(data).hexdigest())
        alias.unlink()
        def interrupt(label):
            if label == "history-initialized":
                raise RuntimeError("synthetic interruption")
        with mock.patch.object(publisher, "_checkpoint", side_effect=interrupt):
            with self.assertRaises(RuntimeError):
                publisher.initialize_history(self.policy, path, hashlib.sha256(data).hexdigest())
        publisher.recover_publications(self.policy, verifier=VERIFIER)
        self.assertEqual(public_snapshot(self.root), reviewed["inventory"])

    def test_windows_restart_all_journal_boundaries_preserves_mac_and_manual_status(self):
        for app, version in (("papir", "0.1.5"), ("launcher", "0.1.9")):
            self._windows_policy()
            bundle = make_bundle(self.signer, self.policy, app=app, version=version, coverage="windows-x64")
            boundaries = ["transaction", "journal"] + ["asset:" + name for name in sorted(bundle) if name != "latest-windows.json"]
            boundaries += ["feed:latest-windows.json", "state", "catalog", "index", "journal-cleared"]
            for boundary in boundaries:
                with self.subTest(app=app, boundary=boundary):
                    temp, root = make_root()
                    try:
                        policy, _ = make_trust(root, self.signer.public_key, self.signer.key_id, windows_only=True)
                        reviewed, _ = self._initialize_fixture(root, policy)
                        stage, files = stage_bundle(publisher, policy, bundle)
                        fired = []
                        def interrupt(label):
                            if label == boundary and not fired:
                                fired.append(label)
                                raise RuntimeError("synthetic interruption")
                        from unittest import mock
                        with mock.patch.object(publisher, "_checkpoint", side_effect=interrupt):
                            with self.assertRaisesRegex(RuntimeError, "synthetic interruption"):
                                publisher.publish_files(policy, app, "stable", files, stage, verifier=VERIFIER)
                        self.assertEqual(fired, [boundary])
                        publisher.recover_publications(policy, verifier=VERIFIER)
                        if boundary == "transaction":
                            self.assertEqual(public_snapshot(root), reviewed["inventory"])
                            publisher.remove_staging(policy, stage)
                            stage, files = stage_bundle(publisher, policy, bundle)
                            publisher.publish_files(policy, app, "stable", files, stage, verifier=VERIFIER)
                        self.assertEqual((root / "downloads" / app / "stable/latest-windows.json").read_bytes(), bundle["latest-windows.json"])
                        after = public_snapshot(root)
                        for path, item in reviewed["inventory"].items():
                            if path not in ("downloads/catalog.json", "downloads/index.html"):
                                self.assertEqual(after[path], item, path)
                        publisher.remove_staging(policy, stage)
                    finally:
                        temp.cleanup()

    def test_recovery_denies_feed_scope_tampering_and_never_cleans_a_live_journal_input(self):
        from unittest import mock
        self._windows_policy()
        reviewed, _ = self._initialize_fixture()
        bundle = make_bundle(self.signer, self.policy, app="papir", version="0.1.5", coverage="windows-x64")
        stage, files = self._stage(bundle)
        def interrupt(label):
            if label == "journal":
                raise RuntimeError("synthetic interruption")
        with mock.patch.object(publisher, "_checkpoint", side_effect=interrupt):
            with self.assertRaises(RuntimeError):
                publisher.publish_files(self.policy, "papir", "stable", files, stage, verifier=VERIFIER)
        journal_path = self.root / publisher.STATE_NAME / publisher.JOURNAL_FILE
        journal_bytes = journal_path.read_bytes()
        extra_stage, _ = publisher.create_staging(self.policy)
        self.assertTrue((self.root / publisher.STATE_NAME / stage).is_dir())
        journal = json.loads(journal_bytes)
        self.assertTrue((self.root / publisher.STATE_NAME / journal["transaction"]).is_dir())
        for key, value in (("coverage", "full-six"), ("feed", "latest.json"), ("targets", ["darwin-aarch64"]), ("distribution", "manual-checksum")):
            journal_path.write_bytes(canonical({**journal, key: value}))
            with self.subTest(key=key), self.assertRaises(publisher.PublicationError):
                publisher.recover_publications(self.policy, verifier=VERIFIER)
            self.assertEqual(public_snapshot(self.root), reviewed["inventory"])
        journal_path.write_bytes(journal_bytes)
        publisher.recover_publications(self.policy, verifier=VERIFIER)
        publisher.remove_staging(self.policy, extra_stage)

    def test_recovery_removes_only_dead_owned_link_temp_before_strict_journal_open(self):
        from unittest import mock
        self._windows_policy()
        self._initialize_fixture()
        bundle = make_bundle(self.signer, self.policy, app="papir", version="0.1.5", coverage="windows-x64")
        stage, files = self._stage(bundle)
        def interrupt(label):
            if label == "journal":
                raise RuntimeError("synthetic interruption")
        with mock.patch.object(publisher, "_checkpoint", side_effect=interrupt):
            with self.assertRaises(RuntimeError):
                publisher.publish_files(self.policy, "papir", "stable", files, stage, verifier=VERIFIER)
        state_dir = self.root / publisher.STATE_NAME
        journal = state_dir / publisher.JOURNAL_FILE
        dead_temp = state_dir / (".lapkb-pubtmp-2147483647-" + "0" * 32)
        os.link(journal, dead_temp)
        self.assertEqual(journal.stat().st_nlink, 2)
        # Model the create-new link/unlink crash window, without relaxing any
        # single-link check or simulating a real release signature.
        publisher.recover_publications(self.policy, verifier=VERIFIER)
        self.assertFalse(dead_temp.exists())
        self.assertFalse(journal.exists())
        state = state_dir / publisher.STATE_FILE
        self.assertEqual(state.stat().st_nlink, 1)
        self.assertEqual((self.root / "downloads/papir/stable/latest-windows.json").read_bytes(), bundle["latest-windows.json"])

    def test_state_denies_coverage_receipt_feed_and_payload_confusion(self):
        self._windows_policy()
        bundle = make_bundle(self.signer, self.policy, app="papir", version="0.1.5", coverage="windows-x64")
        self._publish("papir", "stable", bundle)
        state = json.loads((self.root / publisher.STATE_NAME / publisher.STATE_FILE).read_bytes())
        for key, value in (("coverage", "full-six"), ("feed", "latest.json"), ("targets", ["windows-aarch64"]), ("distribution", "manual-checksum")):
            altered = copy.deepcopy(state)
            altered["history"][0][key] = value
            with self.subTest(key=key), self.assertRaises(publisher.PublicationError):
                publisher._validate_state(canonical(altered), self.policy)
        altered = copy.deepcopy(state)
        altered["history"][0]["receipt"]["targets"]["windows-x86_64"]["build"]["runAttempt"] = True
        with self.assertRaises((publisher.PublicationError, contract.ContractError)):
            publisher._validate_state(canonical(altered), self.policy)

    def test_symlink_file_in_bundle_and_hardlink_are_rejected(self):
        bundle = make_bundle(self.signer, self.policy)
        name, files = self._stage(bundle)
        package = next(path for path in files.values() if path.name.endswith(".bundle.zip"))
        target = self.root / "outside-bytes"
        target.write_bytes(package.read_bytes())
        package.unlink()
        package.symlink_to(target)
        try:
            with self.assertRaises(contract.ContractError):
                contract.validate_release("launcher", "stable", files, self.policy,
                                          verifier=VERIFIER, scratch=files[next(iter(files))].parent)
        finally:
            package.unlink()
            publisher.remove_staging(self.policy, name)

        name, files = self._stage(bundle)
        package = next(path for path in files.values() if path.name.endswith(".bundle.zip"))
        linked = self.root / "hardlink-copy"
        os.link(package, linked)
        try:
            with self.assertRaises(contract.ContractError):
                contract.validate_release("launcher", "stable", files, self.policy,
                                          verifier=VERIFIER, scratch=files[next(iter(files))].parent)
        finally:
            linked.unlink()
            publisher.remove_staging(self.policy, name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
