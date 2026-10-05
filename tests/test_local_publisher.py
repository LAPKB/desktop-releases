from __future__ import annotations

import contextlib
import email.message
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "host"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import publish_artifact
import publish_remote
import release_contract as contract
from support import VERIFIER, SyntheticSigner, canonical, make_bundle, make_root, make_trust


class MemoryInput:
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, value):
        self.data.extend(value)
        return len(value)

    def flush(self):
        pass

    def close(self):
        self.closed = True


class FakeProcess:
    def __init__(self, *, stdout, result):
        self.stdin = MemoryInput()
        self.returncode = None
        stdout.write(canonical(result))
        stdout.flush()

    def wait(self, timeout=None):
        self.returncode = 0
        return 0


class FakeResponse:
    def __init__(self, body, url, *, status=200):
        self.body = body
        self.url = url
        self.status = status
        self.headers = email.message.Message()
        self.headers["Content-Length"] = str(len(body))
        self.offset = 0

    def geturl(self):
        return self.url

    def read(self, size=-1):
        if self.offset == len(self.body):
            return b""
        chunk = self.body[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class FakeOpener:
    def __init__(self, outcome):
        self.outcome = outcome
        self.request = None

    def open(self, request, timeout):
        self.request = request
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class LocalPublisherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not VERIFIER.is_file():
            raise RuntimeError("run scripts/test-publisher.sh to build the locked verifier")
        cls.signer = SyntheticSigner()

    @classmethod
    def tearDownClass(cls):
        cls.signer.close()

    def setUp(self):
        self.temp, self.public_root = make_root()
        self.policy, self.raw_policy = make_trust(
            self.public_root, self.signer.public_key, self.signer.key_id,
        )
        self.config = self.public_root.parent / "publisher.json"
        self.config.write_bytes(canonical(self.raw_policy))
        os.chmod(self.config, 0o600)
        self.bundle_dir = self.public_root.parent / "bundle"
        self.bundle_dir.mkdir(mode=0o700)
        self.bundle = make_bundle(self.signer, self.policy)
        self._write_bundle(self.bundle)
        self.credentials = self.public_root.parent / "credentials"
        self.credentials.mkdir(mode=0o700)
        self.key = self.credentials / "publisher-key"
        self.key.write_text("synthetic private-key placeholder")
        os.chmod(self.key, 0o600)
        self.known_hosts = self.credentials / "known_hosts"
        self.known_hosts.write_text("publisher.example.test ssh-ed25519 synthetic-host-key\n")
        os.chmod(self.known_hosts, 0o600)
        self.environment = {
            "LAPKB_PUBLISHER_CONFIG": str(self.config),
            "LAPKB_PUBLISH_KEY": str(self.key),
            "LAPKB_PUBLISH_KNOWN_HOSTS": str(self.known_hosts),
            "LAPKB_PUBLISH_USER": "publisher",
            "LAPKB_PUBLISH_HOST": "publisher.example.test",
            "LAPKB_PUBLISH_PORT": "2222",
        }

    def tearDown(self):
        self.temp.cleanup()

    def _write_bundle(self, bundle):
        for name in self.bundle_dir.iterdir():
            if name.is_file() or name.is_symlink():
                name.unlink()
        for name, data in bundle.items():
            path = self.bundle_dir / name
            path.write_bytes(data)
            os.chmod(path, 0o600)

    def _assert_ssh_restrictions(self, command, *, host="publisher.example.test", alias=None):
        self.assertEqual(command[:7], ["/usr/bin/ssh", "-F", "/dev/null", "-i", str(self.key), "-p", "2222"])
        self.assertEqual(command[-2:], [f"publisher@{host}", publish_artifact.REMOTE_COMMAND])
        options = command[7:-2]
        self.assertEqual(len(options) % 2, 0)
        self.assertTrue(all(value == "-o" for value in options[::2]))
        expected = {
            "BatchMode": "yes", "IdentitiesOnly": "yes", "IdentityAgent": "none",
            "StrictHostKeyChecking": "yes", "UserKnownHostsFile": str(self.known_hosts),
            "GlobalKnownHostsFile": "/dev/null", "UpdateHostKeys": "no", "VerifyHostKeyDNS": "no",
            "ForwardAgent": "no", "ClearAllForwardings": "yes", "ProxyCommand": "none", "ProxyJump": "none",
            "ControlMaster": "no", "ControlPath": "none", "PreferredAuthentications": "publickey",
            "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no", "ConnectTimeout": "15",
            "ServerAliveInterval": "30", "ServerAliveCountMax": "3",
        }
        if alias is not None:
            expected["HostKeyAlias"] = alias
            self.assertEqual(command[-4:-2], ["-o", f"HostKeyAlias={alias}"])
        self.assertEqual(len(options), 2 * len(expected))
        self.assertEqual(dict(value.split("=", 1) for value in options[1::2]), expected)

    def test_ssh_command_requires_explicit_files_and_disables_ambient_auth_and_proxies(self):
        with mock.patch.dict(os.environ, self.environment, clear=True):
            command = publish_artifact._ssh_command()
        self._assert_ssh_restrictions(command)
        self.assertFalse(any(value.startswith("HostKeyAlias=") for value in command))
        with mock.patch.dict(os.environ, {"SSH_AUTH_SOCK": "/synthetic/agent"}, clear=True):
            with self.assertRaisesRegex(contract.ContractError, "LAPKB_PUBLISH_KEY is required"):
                publish_artifact._ssh_command()

        environment = {**self.environment, "LAPKB_PUBLISH_HOST_KEY_ALIAS": "192.168.0.74"}
        for variable, source in (("LAPKB_PUBLISH_KEY", self.key), ("LAPKB_PUBLISH_KNOWN_HOSTS", self.known_hosts)):
            link = self.credentials / (source.name + "-link")
            link.symlink_to(source)
            with self.subTest(variable=variable, unsafe="link"), \
                    mock.patch.dict(os.environ, {**environment, variable: str(link)}, clear=True):
                with self.assertRaisesRegex(contract.ContractError, "credential file"):
                    publish_artifact._ssh_command()
            os.chmod(source, 0o666)
            try:
                with self.subTest(variable=variable, unsafe="permissions"), \
                        mock.patch.dict(os.environ, environment, clear=True):
                    with self.assertRaisesRegex(contract.ContractError, "credential file"):
                        publish_artifact._ssh_command()
            finally:
                os.chmod(source, 0o600)

    def test_optional_host_key_alias_reuses_only_the_explicit_pin(self):
        for alias in ("192.168.0.74", "publisher-pin.example.test", "Pin-1"):
            environment = {**self.environment, "LAPKB_PUBLISH_HOST": "100.84.10.45",
                           "LAPKB_PUBLISH_HOST_KEY_ALIAS": alias, "SSH_AUTH_SOCK": "/synthetic/agent"}
            with self.subTest(alias=alias), mock.patch.dict(os.environ, environment, clear=True):
                command = publish_artifact._ssh_command()
            self._assert_ssh_restrictions(command, host="100.84.10.45", alias=alias)

    def test_host_key_alias_rejects_empty_whitespace_options_and_controls(self):
        for alias in ("", " ", "192.168.0.74 ", " 192.168.0.74", "pin name", "pin\tname",
                      "pin\nname", "pin\rname", "pin\x1fname", "pin\x7fname", "pin\u00a0name",
                      "-oProxyCommand=evil", "HostKeyAlias=pin", "pin,other", "pin/other", "$(id)",
                      "pin;id", "pin`id`", "pin%h", "é", "a" * 254):
            with self.subTest(alias=repr(alias)), mock.patch.dict(
                    os.environ, {**self.environment, "LAPKB_PUBLISH_HOST_KEY_ALIAS": alias}, clear=True):
                with self.assertRaisesRegex(contract.ContractError, "LAPKB_PUBLISH_HOST_KEY_ALIAS is invalid"):
                    publish_artifact._ssh_command()
        # NUL cannot be put in a process environment; exercise the same validator directly.
        with self.assertRaisesRegex(contract.ContractError, "LAPKB_PUBLISH_HOST_KEY_ALIAS is invalid"):
            publish_artifact._valid_host("pin\x00name", "LAPKB_PUBLISH_HOST_KEY_ALIAS")

    def test_publish_validates_shared_contract_before_sending_and_verifies_served_result(self):
        files = {name: self.bundle_dir / name for name in self.bundle}
        release = contract.validate_release("launcher", "stable", files, self.policy,
                                            verifier=VERIFIER, scratch=self.bundle_dir)
        remote = publish_remote._publication_result(release, "published")
        seen = {}

        def run_remote(command, app, channel, staged_files):
            seen["command"] = command
            seen["app"] = app
            seen["channel"] = channel
            seen["names"] = set(staged_files)
            return remote

        def verify_served(policy, checked_release, result):
            self.assertEqual(policy.root, str(self.public_root))
            self.assertEqual(checked_release["inventory"], release["inventory"])
            self.assertIs(result, remote)
            seen["verified"] = True

        output = io.StringIO()
        with mock.patch.dict(os.environ, self.environment, clear=True), \
                mock.patch.object(publish_artifact, "_run_remote", side_effect=run_remote), \
                mock.patch.object(publish_artifact, "_verify_served", side_effect=verify_served), \
                contextlib.redirect_stdout(output):
            result = publish_artifact.publish("launcher", "stable", self.bundle_dir, verifier=VERIFIER)
        self.assertTrue(seen["verified"])
        self.assertEqual(seen["app"], "launcher")
        self.assertEqual(seen["channel"], "stable")
        self.assertEqual(seen["names"], set(self.bundle))
        self.assertEqual(result["status"], "published")
        self.assertEqual(json.loads(output.getvalue())["files"], len(self.bundle))

    def test_tampered_bundle_never_starts_ssh(self):
        manifest = self.bundle_dir / "latest.json"
        manifest.write_bytes(manifest.read_bytes() + b" ")
        with mock.patch.dict(os.environ, self.environment, clear=True), \
                mock.patch.object(publish_artifact, "_run_remote") as run_remote:
            with self.assertRaisesRegex(contract.ContractError, "release feed"):
                publish_artifact.publish("launcher", "stable", self.bundle_dir, verifier=VERIFIER)
        run_remote.assert_not_called()

    def test_forced_command_runs_the_maintained_receiver_with_a_real_signed_frame(self):
        # Fixed-path fixtures are confined to the existing credential-free Docker CI layer.
        self.assertEqual(os.environ.get("LAPKB_PUBLISHER_ISOLATED_CI"), "1")
        self.assertEqual(sys.platform, "linux")
        self.assertEqual(os.geteuid(), 0)
        self.assertEqual(ROOT, Path("/workspace"))
        self.assertEqual(os.environ.get("HOME"), "/tmp/publisher-jobs2/home")
        self.assertEqual(os.environ.get("CARGO_NET_OFFLINE"), "true")
        policy, raw_policy = make_trust(self.public_root, self.signer.public_key,
                                       self.signer.key_id, windows_only=True)
        bundle = make_bundle(self.signer, policy, app="checkerboard", coverage="windows-x64")
        self._write_bundle(bundle)
        self.config.write_bytes(canonical(raw_policy))
        files = {name: self.bundle_dir / name for name in bundle}
        release = contract.validate_release("checkerboard", "stable", files, policy,
                                            verifier=VERIFIER, scratch=self.bundle_dir)
        receiver_home = Path("/home/siel")
        config_dir = Path("/etc/lapkb")
        verifier = contract.VERIFIER_PATH
        for path in (receiver_home, config_dir, verifier):
            self.assertFalse(os.path.lexists(path), f"refusing an existing fixed-path fixture: {path}")
        with contextlib.ExitStack() as cleanup:
            for directory in (receiver_home, receiver_home / "bin", config_dir):
                directory.mkdir(mode=0o700)
                cleanup.callback(directory.rmdir)
            if not os.path.lexists(verifier.parent):
                verifier.parent.mkdir(mode=0o755)
                cleanup.callback(verifier.parent.rmdir)
            self.assertEqual(verifier.parent.resolve(strict=True), verifier.parent)
            for source, destination, mode in (
                (ROOT / "host/publish_remote.py", receiver_home / "bin/publish_remote.py", 0o600),
                (ROOT / "host/release_contract.py", receiver_home / "bin/release_contract.py", 0o600),
                (self.config, contract.CONFIG_PATH, 0o600), (VERIFIER, verifier, 0o755),
            ):
                with destination.open("xb") as output:
                    cleanup.callback(destination.unlink)
                    with source.open("rb") as input_file:
                        shutil.copyfileobj(input_file, output)
                os.chmod(destination, mode)
            environment = {**self.environment, "PYTHONDONTWRITEBYTECODE": "1"}
            with mock.patch.dict(os.environ, environment, clear=True):
                # No patched receiver/client function or fabricated successful response.
                os.environ["SSH_ORIGINAL_COMMAND"] = publish_artifact._ssh_command()[-1]
                for status in ("published", "identical-retry"):
                    result = publish_artifact._run_remote(
                        ["/bin/sh", str(ROOT / "host/publish-forced-command.sh"), "ignored-caller-argument"],
                        "checkerboard", "stable", files,
                    )
                    contract.validate_publication_result(result, policy, release)
                    self.assertEqual(result["status"], status)
            for name, data in bundle.items():
                self.assertEqual((self.public_root / "downloads/checkerboard/stable" / name).read_bytes(), data)
            self.assertTrue((self.public_root / ".lapkb-publisher/state.json").is_file())
            self.assertFalse((self.public_root / ".lapkb-publisher/journal.json").exists())

    def test_forced_command_rejects_every_other_command_without_execution(self):
        script = ROOT / "host/publish-forced-command.sh"
        marker = self.public_root.parent / "unexpected-execution"
        fixed = publish_artifact.REMOTE_COMMAND
        commands = (
            None, "", "id", fixed.replace("python3", "/usr/bin/python3", 1),
            fixed.replace("--receive-v1", "--receive-v2"), fixed + " --root /tmp/attacker",
            fixed + " extra", fixed + " ", " " + fixed, fixed + "\n", fixed.replace(" ", "  ", 1),
            "python3 /home/siel/bin/publish_remote.py /home/siel/public launcher stable",
            "python3 /home/siel/bin/publish_remote.py /home/siel/public papir stable papir",
            "python3 /home/siel/bin/publish_remote.py --initialize-history-v1 --inventory /tmp/input --sha256 " + "0" * 64,
            "python3 /home/siel/bin/publish_remote.py --recover-v1",
            fixed + f"; touch {marker}", fixed + f" $(touch {marker})", fixed + f" `touch {marker}`",
            fixed + f"\ntouch {marker}", "'" + fixed + "'",
        )
        for command in commands:
            environment = {} if command is None else {"SSH_ORIGINAL_COMMAND": command}
            with self.subTest(command=command):
                result = subprocess.run(["/bin/sh", str(script), "ignored-caller-argument"], env=environment,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
                self.assertEqual(result.returncode, 64)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, "restricted publisher: unexpected command\n")
                self.assertFalse(marker.exists())

    def test_bundle_and_served_http_redirects_are_rejected(self):
        link = self.public_root.parent / "bundle-link"
        link.symlink_to(self.bundle_dir, target_is_directory=True)
        with self.assertRaises(OSError):
            publish_artifact._secure_bundle_dir(link)

        url = self.policy.origin + "/downloads/launcher/stable/latest.json"
        headers = email.message.Message()
        redirect = urllib.error.HTTPError(url, 302, "Found", headers, io.BytesIO())
        opener = FakeOpener(redirect)
        with mock.patch.object(publish_artifact, "_opener", return_value=opener):
            with self.assertRaisesRegex(contract.ContractError, "refused an HTTP redirect"):
                publish_artifact._fetch_exact(url, self.policy, 4096)
        self.assertIsNone(opener.request.get_header("Authorization"))
        self.assertIsNone(opener.request.get_header("Proxy-Authorization"))

    def test_windows_served_verification_binds_fixed_feed_and_complete_response_identity(self):
        self.policy, _ = make_trust(self.public_root, self.signer.public_key, self.signer.key_id, windows_only=True)
        # The manual Launcher case is the historical 0.1.9 feed.
        for app, version in (("papir", "1.2.3"), ("launcher", "0.1.9")):
            bundle = make_bundle(self.signer, self.policy, app=app, version=version, coverage="windows-x64")
            self._write_bundle(bundle)
            release = contract.validate_release(app, "stable", {name: self.bundle_dir / name for name in bundle},
                                                self.policy, verifier=VERIFIER, scratch=self.bundle_dir)
            response = publish_remote._publication_result(release, "published")
            seen = []
            def fetch(url, policy, maximum, expected=None):
                name = url.rsplit("/", 1)[-1]
                seen.append((url, maximum, expected))
                self.assertIn(name, bundle)
                return bundle[name] if expected is None else {"size": len(bundle[name]), "sha256": hashlib.sha256(bundle[name]).hexdigest()}
            with mock.patch.object(publish_artifact, "_fetch_exact", side_effect=fetch):
                publish_artifact._verify_served(self.policy, release, response)
            self.assertEqual(len(seen), len(bundle))
            self.assertFalse(any(url.endswith("/latest.json") for url, _, _ in seen))
            feed_calls = [(maximum, expected) for url, maximum, expected in seen if url.endswith("/latest-windows.json")]
            self.assertEqual(feed_calls, [(contract.MAX_MANIFEST_BYTES, None)])
            for key, value in (("coverage", "full-six"), ("feed", "latest.json"), ("targets", ["darwin-aarch64"]),
                               ("distribution", "signed" if app == "launcher" else "manual-checksum"), ("version", "9.9.9")):
                with self.subTest(app=app, key=key), mock.patch.object(publish_artifact, "_fetch_exact") as network:
                    with self.assertRaises(contract.ContractError):
                        publish_artifact._verify_served(self.policy, release, {**response, key: value})
                    network.assert_not_called()
            def corrupt_feed(url, policy, maximum, expected=None):
                return release["manifestBytes"] + b" " if expected is None else expected
            with mock.patch.object(publish_artifact, "_fetch_exact", side_effect=corrupt_feed):
                with self.assertRaisesRegex(contract.ContractError, "fixed coverage feed"):
                    publish_artifact._verify_served(self.policy, release, response)

    def test_remote_frame_is_bounded_and_ssh_command_is_exact(self):
        files = {name: self.bundle_dir / name for name in self.bundle}
        response = {"app": "launcher", "channel": "stable", "status": "published"}
        launched = {}

        def fake_popen(command, **kwargs):
            launched["command"] = command
            launched["process"] = FakeProcess(stdout=kwargs["stdout"], result=response)
            return launched["process"]

        command = ["/usr/bin/ssh", "publisher@publisher.example.test", publish_artifact.REMOTE_COMMAND]
        with mock.patch.object(publish_artifact.subprocess, "Popen", side_effect=fake_popen):
            result = publish_artifact._run_remote(command, "launcher", "stable", files)
        self.assertEqual(result, response)
        self.assertEqual(launched["command"], command)
        self.assertTrue(launched["process"].stdin.closed)
        self.assertTrue(launched["process"].stdin.data.startswith(publish_remote.FRAME_PREFIX.pack(
            publish_remote.FRAME_MAGIC, len(publish_remote._canonical({
                "schema": "lapkb-publish-frame-v1", "app": "launcher", "channel": "stable",
                "files": [{"name": name, "size": path.stat().st_size,
                           "sha256": contract._sha256_file(path)[1]} for name, path in sorted(files.items())],
            }))
        )))
        self.assertGreater(len(launched["process"].stdin.data), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
