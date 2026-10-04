from __future__ import annotations

import contextlib
import email.message
import hashlib
import importlib.util
import io
import json
import os
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

HOST = Path(__file__).resolve().parents[1] / "host"
sys.path.insert(0, str(HOST))
sys.path.insert(0, str(Path(__file__).resolve().parent))

spec = importlib.util.spec_from_file_location("lapkb_pickup", HOST / "lapkb-pickup.py")
pickup = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = pickup
spec.loader.exec_module(pickup)

import publish_remote
import release_contract as contract
from support import VERIFIER, SyntheticSigner, make_bundle, make_root, make_trust


class FakeResponse:
    def __init__(self, body, url, *, status=200, headers=None, chunk_size=1024):
        self.body = body
        self.url = url
        self.status = status
        self.headers = headers or email.message.Message()
        self.position = 0
        self.chunk_size = chunk_size
        self.closed = False

    def geturl(self):
        return self.url

    def read(self, size=-1):
        size = min(size, self.chunk_size)
        if self.position >= len(self.body):
            return b""
        end = min(len(self.body), self.position + size)
        value = self.body[self.position:end]
        self.position = end
        return value

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.close()


class FakeOpener:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class PickupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = SyntheticSigner()

    @classmethod
    def tearDownClass(cls):
        cls.signer.close()

    def setUp(self):
        self.temp, self.root = make_root()
        self.policy, self.trust = make_trust(self.root, self.signer.public_key, self.signer.key_id)

    def tearDown(self):
        self.temp.cleanup()

    def test_redirect_sends_token_only_to_exact_github_asset_api(self):
        api_url = "https://api.github.com/repos/LAPKB/desktop-releases/releases/assets/7"
        cdn_url = "https://release-assets.githubusercontent.com/github-production-release-asset/7?token=signed-query"
        headers = email.message.Message()
        headers["Location"] = cdn_url
        redirect = urllib.error.HTTPError(api_url, 302, "Found", headers, io.BytesIO())
        response_headers = email.message.Message()
        response_headers["Content-Length"] = "11"
        response = FakeResponse(b"hello world", cdn_url, headers=response_headers, chunk_size=3)
        opener = FakeOpener([redirect, response])
        asset = {"url": api_url, "size": 11, "digest": None}
        destination = self.root / "asset.bin"
        with mock.patch.object(pickup, "_http_opener", return_value=opener):
            result = pickup.download_asset(asset, "synthetic-token-not-a-secret", destination)
        self.assertEqual(destination.read_bytes(), b"hello world")
        self.assertEqual(result["sha256"], hashlib.sha256(b"hello world").hexdigest())
        self.assertEqual(opener.requests[0][0].get_header("Authorization"),
                         "Bearer synthetic-token-not-a-secret")
        self.assertIsNone(opener.requests[1][0].get_header("Authorization"))
        self.assertEqual(opener.requests[1][0].full_url, cdn_url)
        self.assertTrue(response.closed)

    def test_unapproved_redirect_is_rejected_without_logging_query_or_sending_token(self):
        api_url = "https://api.github.com/repos/LAPKB/desktop-releases/releases/assets/8"
        headers = email.message.Message()
        headers["Location"] = "https://evil.example.test/github-production-release-asset/8?token=do-not-log"
        redirect = urllib.error.HTTPError(api_url, 302, "Found", headers, io.BytesIO())
        opener = FakeOpener([redirect])
        asset = {"url": api_url, "size": 1, "digest": None}
        destination = self.root / "asset.bin"
        with mock.patch.object(pickup, "_http_opener", return_value=opener):
            with self.assertRaises(contract.ContractError) as caught:
                pickup.download_asset(asset, "synthetic-token", destination)
        self.assertNotIn("synthetic-token", str(caught.exception))
        self.assertNotIn("do-not-log", str(caught.exception))
        self.assertEqual(len(opener.requests), 1)
        self.assertEqual(opener.requests[0][0].get_header("Authorization"), "Bearer synthetic-token")
        self.assertFalse(destination.exists())

    def test_cdn_response_identity_length_and_digest_are_checked(self):
        api_url = "https://api.github.com/repos/LAPKB/desktop-releases/releases/assets/9"
        cdn_url = "https://objects.githubusercontent.com/github-production-release-asset/9?token=q"
        redirect_headers = email.message.Message()
        redirect_headers["Location"] = cdn_url
        redirect = urllib.error.HTTPError(api_url, 302, "Found", redirect_headers, io.BytesIO())
        response_headers = email.message.Message()
        response_headers["Content-Length"] = "4"
        response = FakeResponse(b"data", cdn_url, headers=response_headers)
        opener = FakeOpener([redirect, response])
        asset = {"url": api_url, "size": 4, "digest": "sha256:" + "0" * 64}
        destination = self.root / "asset.bin"
        with mock.patch.object(pickup, "_http_opener", return_value=opener):
            with self.assertRaisesRegex(contract.ContractError, "digest"):
                pickup.download_asset(asset, "", destination)
        self.assertFalse(destination.exists())

    def test_release_api_pagination_is_bounded_and_complete(self):
        pages = [[{} for _ in range(100)], [{}]]
        requested = []

        def api(url, token):
            requested.append(url)
            page = int(url.rsplit("=", 1)[1])
            return contract.canonical_json(pages[page - 1])

        with mock.patch.object(pickup, "api_get", side_effect=api):
            releases = pickup.list_releases(self.policy.pickup_repository, "synthetic-token")
        self.assertEqual(len(releases), 101)
        self.assertEqual(len(requested), 2)
        self.assertTrue(requested[0].endswith("per_page=100&page=1"))
        self.assertTrue(requested[1].endswith("per_page=100&page=2"))

        with mock.patch.object(pickup, "MAX_PAGES", 2), \
                mock.patch.object(pickup, "api_get", return_value=contract.canonical_json([{}] * 100)) as api_mock:
            with self.assertRaisesRegex(contract.ContractError, "pagination exceeded"):
                pickup.list_releases(self.policy.pickup_repository, "")
        self.assertEqual(api_mock.call_count, 2)

    def test_private_pickup_configuration_and_state_reject_unsafe_files(self):
        home = self.root / "pickup-home"
        home.mkdir(mode=0o700)
        config_dir = home / ".config" / "lapkb"
        config_dir.mkdir(mode=0o700, parents=True)
        state_dir = home / ".local" / "state" / "lapkb"
        state_dir.mkdir(mode=0o700, parents=True)
        config = {"schema": "lapkb-pickup-v1", "enabled": True,
                  "repository": self.policy.pickup_repository}
        config_path = config_dir / "pickup.json"
        config_path.write_bytes(contract.canonical_json(config))
        os.chmod(config_path, 0o600)
        token_path = config_dir / "pickup-token"
        token_path.write_text("synthetic_token_123\n")
        os.chmod(token_path, 0o600)
        state_path = state_dir / "pickup-state.json"
        lock_path = state_dir / "pickup-state.lock"
        with mock.patch.multiple(pickup, CONFIG=config_path, TOKEN=token_path,
                                 STATE=state_path, LOCK=lock_path):
            self.assertEqual(pickup._load_pickup_config(self.policy), config)
            self.assertEqual(pickup._token(), "synthetic_token_123")
            state_fd = pickup._open_dir_chain(state_dir, private_final=True)
            try:
                value = pickup._load_state(state_fd, self.policy)
                self.assertEqual(value, {"schema": "lapkb-pickup-state-v1", "published": {}})
                pickup._write_state(state_fd, value)
                self.assertEqual(pickup._load_state(state_fd, self.policy), value)
                os.chmod(state_path, 0o644)
                with self.assertRaisesRegex(contract.ContractError, "ownership or permissions"):
                    pickup._load_state(state_fd, self.policy)
            finally:
                os.close(state_fd)

            bad_config = {**config, "enabled": False}
            config_path.write_bytes(contract.canonical_json(bad_config))
            os.chmod(config_path, 0o600)
            with self.assertRaisesRegex(contract.ContractError, "disabled"):
                pickup._load_pickup_config(self.policy)

    def test_windows_scope_identity_and_processed_state_deny_feed_coverage_or_disabled_channel(self):
        self.policy, _ = make_trust(self.root, self.signer.public_key, self.signer.key_id, windows_only=True)
        for app in ("papir", "launcher"):
            bundle = make_bundle(self.signer, self.policy, app=app, coverage="windows-x64")
            assets = [{"id": index, "name": name, "size": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
                      for index, (name, data) in enumerate(sorted(bundle.items()), 1)]
            identity = pickup._release_identity({"id": 7, "draft": False, "prerelease": False}, app, "stable", "1.2.3", assets, self.policy)
            self.assertEqual(identity["feed"], "latest-windows.json")
            self.assertEqual(identity["targets"], ["windows-x86_64"])
            self.assertEqual(identity["distribution"], "manual-checksum" if app == "launcher" else "signed")
            tag = f"publish-{app}-stable-1.2.3"
            state_dir = self.root.parent / ("pickup-state-" + app)
            state_dir.mkdir(mode=0o700)
            state_path = state_dir / "pickup-state.json"
            entry = {**identity, "inventoryDigest": "a" * 64}
            fd = pickup._open_dir_chain(state_dir, private_final=True)
            try:
                with mock.patch.object(pickup, "STATE", state_path):
                    pickup._write_state(fd, {"schema": "lapkb-pickup-state-v1", "published": {tag: entry}})
                    self.assertEqual(pickup._load_state(fd, self.policy)["published"][tag], entry)
                    for key, value in (("feed", "latest.json"), ("coverage", "full-six"), ("targets", ["windows-aarch64"])):
                        pickup._write_state(fd, {"schema": "lapkb-pickup-state-v1", "published": {tag: {**entry, key: value}}})
                        with self.assertRaisesRegex(contract.ContractError, "coverage/feed/target"):
                            pickup._load_state(fd, self.policy)
            finally:
                os.close(fd)
            with self.assertRaisesRegex(contract.ContractError, "not configured"):
                pickup._asset_scope(self.policy, app, "beta", assets)
            confused = assets + [{"id": 999, "name": "latest.json", "size": 1, "digest": None}]
            with self.assertRaisesRegex(contract.ContractError, "exactly one fixed"):
                pickup._asset_scope(self.policy, app, "stable", confused)

    def test_signed_windows_and_manual_launcher_pickup_use_the_same_real_core_then_idle(self):
        self.policy, _ = make_trust(self.root, self.signer.public_key, self.signer.key_id, windows_only=True)
        original_publish, original_recover = publish_remote.publish_files, publish_remote.recover_publications
        for app in ("papir", "launcher"):
            bundle = make_bundle(self.signer, self.policy, app=app, coverage="windows-x64")
            tag = f"publish-{app}-stable-1.2.3"
            home = self.root.parent / ("private-pickup-" + app)
            config_dir, state_dir = home / ".config/lapkb", home / ".local/state/lapkb"
            config_dir.mkdir(mode=0o700, parents=True)
            state_dir.mkdir(mode=0o700, parents=True)
            config_path = config_dir / "pickup.json"
            config_path.write_bytes(contract.canonical_json({"schema": "lapkb-pickup-v1", "enabled": True, "repository": self.policy.pickup_repository}))
            os.chmod(config_path, 0o600)
            assets = [{"id": index, "name": name, "size": len(data),
                       "url": f"https://api.github.com/repos/{self.policy.pickup_repository}/releases/assets/{index}",
                       "digest": "sha256:" + hashlib.sha256(data).hexdigest()}
                      for index, (name, data) in enumerate(sorted(bundle.items()), 1)]
            release = {"id": 700, "tag_name": tag, "draft": False, "prerelease": False, "assets": assets}
            def download(asset, token, destination):
                data = bundle[asset["name"]]
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                try:
                    os.write(fd, data)
                finally:
                    os.close(fd)
                return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            def publish(policy, app, channel, files, staging):
                return original_publish(policy, app, channel, files, staging, verifier=VERIFIER)
            state_path = state_dir / "pickup-state.json"
            with mock.patch.multiple(pickup, CONFIG=config_path, TOKEN=config_dir / "absent-token", STATE=state_path, LOCK=state_dir / "pickup-state.lock"), \
                    mock.patch.object(contract, "load_policy", return_value=self.policy), \
                    mock.patch.object(pickup, "list_releases", return_value=[release]), \
                    mock.patch.object(pickup, "download_asset", side_effect=download), \
                    mock.patch.object(publish_remote, "publish_files", side_effect=publish) as published, \
                    mock.patch.object(publish_remote, "recover_publications", side_effect=lambda policy: original_recover(policy, verifier=VERIFIER)), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pickup.main(), 0)
                stored = json.loads(state_path.read_bytes())["published"][tag]
                self.assertEqual(stored["feed"], "latest-windows.json")
                self.assertEqual(stored["distribution"], "manual-checksum" if app == "launcher" else "signed")
                self.assertEqual(pickup.main(), 0)
                self.assertEqual(published.call_count, 1)
            self.assertEqual((self.root / "downloads" / app / "stable/latest-windows.json").read_bytes(), bundle["latest-windows.json"])

    def test_failed_publish_is_not_marked_processed_and_changed_tag_is_rejected(self):
        home = self.root / "pickup-home"
        home.mkdir(mode=0o700)
        config_dir = home / ".config" / "lapkb"
        config_dir.mkdir(mode=0o700, parents=True)
        state_dir = home / ".local" / "state" / "lapkb"
        state_dir.mkdir(mode=0o700, parents=True)
        config_path = config_dir / "pickup.json"
        config_path.write_bytes(contract.canonical_json({
            "schema": "lapkb-pickup-v1", "enabled": True,
            "repository": self.policy.pickup_repository,
        }))
        os.chmod(config_path, 0o600)
        token_path = config_dir / "pickup-token"
        token_path.write_text("synthetic_token_123")
        os.chmod(token_path, 0o600)
        state_path = state_dir / "pickup-state.json"
        lock_path = state_dir / "pickup-state.lock"
        bundle = make_bundle(self.signer, self.policy)
        tag = "publish-launcher-stable-1.2.3"

        def github_release(assets):
            return {"id": 101, "tag_name": tag, "draft": False, "prerelease": False,
                    "assets": assets}

        def asset_records(contents):
            assets = []
            for index, (name, data) in enumerate(sorted(contents.items()), start=1):
                assets.append({
                    "id": index, "name": name, "size": len(data),
                    "url": f"https://api.github.com/repos/{self.policy.pickup_repository}/releases/assets/{index}",
                    "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                })
            return assets

        original_assets = asset_records(bundle)
        changed_assets = [dict(item) for item in original_assets]
        changed_assets[0]["digest"] = "sha256:" + "0" * 64
        inventory = [
            {"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(bundle.items())
        ]

        def download(asset, token, destination):
            data = bundle[asset["name"]]
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
            self.assertEqual(token, "synthetic_token_123")
            return {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}

        patches = mock.patch.multiple(
            pickup, CONFIG=config_path, TOKEN=token_path, STATE=state_path, LOCK=lock_path,
        )
        with patches, mock.patch.object(pickup.contract, "load_policy", return_value=self.policy), \
                mock.patch.object(pickup, "list_releases", return_value=[github_release(original_assets)]), \
                mock.patch.object(pickup, "download_asset", side_effect=download), \
                mock.patch.object(pickup.publish_remote, "recover_publications") as recover_mock:
            with mock.patch.object(pickup.publish_remote, "publish_files",
                                   side_effect=publish_remote.PublicationError("synthetic promotion failure")):
                with self.assertRaisesRegex(publish_remote.PublicationError, "synthetic promotion failure"):
                    pickup.main()
            recover_mock.assert_called_once_with(self.policy)
            self.assertFalse(state_path.exists())

            response = {"status": "published", "app": "launcher", "channel": "stable", "version": "1.2.3",
                        "coverage": "full-six", "feed": "latest.json", "targets": sorted(contract.TARGETS),
                        "distribution": "signed", "inventory": inventory,
                        "inventoryDigest": hashlib.sha256(contract.canonical_json(inventory)).hexdigest()}
            with mock.patch.object(pickup.publish_remote, "publish_files",
                                   return_value=response), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(pickup.main(), 0)
            stored = json.loads(state_path.read_bytes())
            self.assertEqual(stored["published"][tag]["inventoryDigest"],
                             hashlib.sha256(contract.canonical_json(inventory)).hexdigest())

        with patches, mock.patch.object(pickup.contract, "load_policy", return_value=self.policy), \
                mock.patch.object(pickup, "list_releases", return_value=[github_release(changed_assets)]), \
                mock.patch.object(pickup.publish_remote, "recover_publications"):
            with self.assertRaisesRegex(contract.ContractError, "changed its release or asset identity"):
                pickup.main()


if __name__ == "__main__":
    unittest.main(verbosity=2)
