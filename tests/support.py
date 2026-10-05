from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

import release_contract as contract

HOST = Path(__file__).resolve().parents[1] / "host"
VERIFIER = HOST / "verifier" / "target" / "debug" / "lapkb-release-verifier"
SIGNER = HOST / "verifier" / "target" / "debug" / "examples" / "synthetic-signer"
PICKUP_REPOSITORY = "LAPKB/desktop-releases"
SOURCE_REPOSITORIES = {
    app: f"LAPKB/synthetic-{app}-source" for app in contract.APP_IDS
}


class SyntheticSigner:
    """Fresh, process-local test key. No private key is written to disk."""

    def __init__(self):
        self.process = subprocess.Popen(
            [str(SIGNER)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, bufsize=1,
        )
        line = self.process.stdout.readline().rstrip("\n")
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] != "PUBKEY":
            raise RuntimeError("synthetic signer did not return a public key")
        self.public_key = fields[1] + "\n" + fields[2] + "\n"
        raw = base64.b64decode(fields[2], validate=True)
        self.key_id = f"{int.from_bytes(raw[2:10], 'little'):016X}"

    def sign(self, payload: bytes) -> bytes:
        self.process.stdin.write(payload.hex() + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline().rstrip("\n")
        fields = line.split("\t", 1)
        if len(fields) != 2 or fields[0] != "SIG":
            raise RuntimeError("synthetic signer failed: " + self.process.stderr.read(200))
        return bytes.fromhex(fields[1])

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.write("QUIT\n")
            self.process.stdin.flush()
            self.process.wait(timeout=10)
        self.process.stdin.close()
        self.process.stdout.close()
        self.process.stderr.close()


def make_trust(root: Path, public_key: str, key_id: str, *, windows_only=False):
    aliases = {
        app: {"stable": app, "beta": None}
        for app in contract.APP_IDS
    }
    apps = {}
    for app in contract.APP_IDS:
        per_target = {}
        for target in contract.TARGETS:
            per_target[target] = [
                {"id": "bundle", "extension": "bundle.zip", "kind": "Synthetic <bundle>",
                 "roles": ["installer", "updater"], "required": True},
            ]
        apps[app] = {
            "sourceRepository": SOURCE_REPOSITORIES[app],
            "branch": "reviewed-release-branch",
            "bundleIdentifier": contract.BUNDLE_IDS[app],
            "executable": "checkmate-desktop" if app == "checkerboard" else f"{app}-desktop",
            "channels": {
                channel: {"publicKey": public_key, "keyId": key_id,
                          "profiles": per_target}
                for channel in contract.CHANNELS
            },
        }
    if windows_only:
        for app, entry in apps.items():
            manual = app == "launcher"
            entry["allowedCoverages"] = ["windows-x64"]
            entry["channels"] = {"stable": {
                "publicKey": None if manual else public_key, "keyId": None if manual else key_id,
                "manualTargets": ["windows-x86_64"] if manual else [],
                "profiles": {"windows-x86_64": [{"id": "nsis", "extension": "exe", "kind": "nsis",
                    "roles": ["installer"] if manual else ["installer", "updater"], "required": True}]},
            }}
            aliases[app] = {"stable": app}
    raw = {
        "schema": "lapkb-publisher-trust-v1",
        "root": str(root),
        "origin": "https://downloads.example.test",
        "pickupRepository": PICKUP_REPOSITORY,
        "checkmateMinimumVersion": "0.8.0" if windows_only else "1.0.0",
        "legacyAliases": aliases,
        "apps": apps,
    }
    return contract.validate_policy(raw), raw


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def make_bundle(signer: SyntheticSigner, policy, app="launcher", channel="stable",
                version="1.2.3", *, nonce="same", omit_target=None,
                omit_profile=None, include_optional=False, coverage="full-six"):
    app_policy = policy.apps[app]
    channel_policy = app_policy["channels"][channel]
    manual = bool(channel_policy["manualTargets"])
    selected_targets = contract.COVERAGES[coverage]
    source = {
        "repository": app_policy["sourceRepository"],
        "branch": app_policy["branch"],
        "commit": "a" * 40,
        "tag": f"publish-{app}-{channel}-{version}",
    }
    files = {}
    targets = {}
    for target in selected_targets:
        target_identity = {
            "bundleIdentifier": contract.BUNDLE_IDS[app],
            "displayName": contract.WINDOWS_PRODUCTS[app] if coverage in ("windows-x64", "launcher-desktop") else contract.DISPLAY_NAMES[app],
            "executable": app_policy["executable"],
            "architecture": target.split("-")[-1],
            "version": version,
        }
        artifacts = []
        updater_signature = None
        updater_name = None
        for profile in channel_policy["profiles"][target]:
            if target == omit_target and profile["extension"] == omit_profile:
                continue
            if not profile["required"] and not include_optional:
                continue
            payload = f"synthetic:{app}:{channel}:{version}:{target}:{profile['id']}:{nonce}".encode()
            digest = hashlib.sha256(payload).hexdigest()
            name = f"{app}-{version}-{target}-{digest}.{profile['extension']}"
            roles = list(profile["roles"])
            signature = signer.sign(payload) if "updater" in roles else None
            item = {
                "name": name, "kind": profile["kind"], "roles": roles,
                "size": len(payload), "sha256": digest,
                "signatureKeyId": signer.key_id if signature is not None else None,
                "updaterSignature": base64.b64encode(signature).decode("ascii") if signature is not None else None,
            }
            artifacts.append(item)
            files[name] = payload
            if "updater" in roles:
                updater_signature = item["updaterSignature"]
                updater_name = name
        artifacts.sort(key=lambda item: item["name"])
        targets[target] = {"packageIdentity": target_identity, "artifacts": artifacts}
        if target == "windows-x86_64" and coverage in ("windows-x64", "launcher-desktop"):
            executable_bytes = f"synthetic installed executable:{app}:{version}:{nonce}".encode()
            targets[target].update(
                build={"runId": "12345", "runAttempt": 1, "profile": "public-staging"},
                windowsPayload={"schema": "lapkb-windows-payload-v1", "productName": contract.WINDOWS_PRODUCTS[app],
                    "executable": app_policy["executable"] + ".exe", "architecture": "x86_64", "version": version,
                    "installMode": "currentUser", "files": [{"path": app_policy["executable"] + ".exe",
                        "size": len(executable_bytes), "sha256": hashlib.sha256(executable_bytes).hexdigest()}]},
            )
        elif coverage == "launcher-desktop":
            targets[target]["build"] = {"runId": "12345", "runAttempt": 1, "profile": "public-staging"}

    attestation = {
        "schema": "lapkb-build-attestation-v1", "app": app, "channel": channel,
        "version": version, "source": source,
        "notes": "Synthetic <release> & test fixture",
        "pub_date": "2026-09-25T00:00:00Z",
        "targets": targets,
    }
    if coverage in ("windows-x64", "launcher-desktop"):
        attestation["coverage"] = coverage
    if manual:
        attestation["distribution"] = "manual-checksum"
    if omit_target is not None and omit_profile is None:
        attestation["targets"].pop(omit_target, None)
    attestation_bytes = canonical(attestation)
    attestation_signature = None if manual else signer.sign(attestation_bytes)
    attestation_name = f"build-attestation-{version}.json"
    receipt_name = f"release-receipt-{version}.json"
    files[attestation_name] = attestation_bytes
    if not manual:
        files[attestation_name + ".sig"] = attestation_signature

    platforms = {}
    for target in selected_targets:
        if target not in targets:
            # A deliberately incomplete signed target set still gets a normal
            # six-key manifest; the contract must reject the attestation first.
            platforms[target] = {"url": f"{policy.origin}/downloads/{app}/{channel}/missing",
                                 "signature": "AA=="}
            continue
        artifact = next(item for item in targets[target]["artifacts"] if ("installer" if manual else "updater") in item["roles"])
        url = f"{policy.origin}/downloads/{app}/{channel}/{artifact['name']}"
        platforms[target] = ({"url": url, "size": artifact["size"], "sha256": artifact["sha256"], "kind": "nsis"}
                             if manual else {"url": url, "signature": artifact["updaterSignature"]})
    manifest = {
        "version": version,
        "notes": attestation["notes"],
        "pub_date": attestation["pub_date"],
        "installers" if manual else "platforms": platforms,
    }
    if manual:
        manifest.update(schema="lapkb-manual-download-v1", app=app, channel=channel,
                        coverage=coverage, distribution="manual-checksum")
    manifest_bytes = canonical(manifest)
    feed = "latest-windows.json" if coverage == "windows-x64" else "latest.json"
    files[feed] = manifest_bytes

    receipt_targets = {}
    for target in selected_targets:
        if target not in targets:
            continue
        records = targets[target]["artifacts"]
        receipt_targets[target] = {
            "packageIdentity": targets[target]["packageIdentity"],
            "roles": {
                "installer": sorted(item["name"] for item in records if "installer" in item["roles"]),
                "updater": next((item["name"] for item in records if "updater" in item["roles"]), None),
            },
            "artifacts": [
                {key: item[key] for key in ("name", "kind", "roles", "size", "sha256", "signatureKeyId")}
                for item in records
            ],
        }
        if target == "windows-x86_64" and coverage in ("windows-x64", "launcher-desktop"):
            receipt_targets[target].update(build=targets[target]["build"], windowsPayload=targets[target]["windowsPayload"])
            if not manual:
                receipt_targets[target]["installerSignature"] = next(item["updaterSignature"] for item in records if "updater" in item["roles"])
        elif coverage == "launcher-desktop":
            receipt_targets[target]["build"] = targets[target]["build"]
    receipt = {
        "schema": "release-receipt-v1", "app": app, "channel": channel, "version": version,
        "source": source,
        "buildAttestationSha256": hashlib.sha256(attestation_bytes).hexdigest(),
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "signatureKeyId": None if manual else signer.key_id, "targets": receipt_targets,
    }
    if coverage in ("windows-x64", "launcher-desktop"):
        receipt.update(coverage=coverage, feed=feed)
    if manual:
        receipt["distribution"] = "manual-checksum"
    receipt_bytes = canonical(receipt)
    files[receipt_name] = receipt_bytes
    if not manual:
        files[receipt_name + ".sig"] = signer.sign(receipt_bytes)
    return files


def stage_bundle(publisher, policy, bundle):
    name, path = publisher.create_staging(policy)
    files = {}
    try:
        for filename, data in bundle.items():
            destination = path / filename
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                view = memoryview(data)
                while view:
                    size = os.write(fd, view)
                    view = view[size:]
                os.fsync(fd)
            finally:
                os.close(fd)
            files[filename] = destination
        directory_fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return name, files
    except BaseException:
        publisher.remove_staging(policy, name)
        raise


def public_snapshot(root):
    """Independent test byte/mode/path inventory; no signed provenance claim."""
    import stat
    result = {".": {"kind": "directory", "mode": stat.S_IMODE(root.stat().st_mode)}}
    for path in sorted(root.rglob("*")):
        relative = str(path.relative_to(root))
        if relative.split("/")[0] in (".lapkb-publisher", ".lapkb-publisher.lock"):
            continue
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            result[relative] = {"kind": "directory", "mode": stat.S_IMODE(info.st_mode)}
        elif stat.S_ISREG(info.st_mode):
            data = path.read_bytes()
            result[relative] = {"kind": "file", "mode": stat.S_IMODE(info.st_mode),
                                "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        else:
            raise RuntimeError("test snapshot found a link/special file")
    return result


def make_historical_input(root, policy):
    """Synthetic retained history, including opaque data and a 0600 old archive.

    These are observed fixture bytes, not app binaries or genuine old receipts.
    """
    import datetime
    versions = {"launcher": ("0.1.7", "0.1.8"), "papir": ("0.1.3", "0.1.4"),
                "checkerboard": ("0.8.0", "0.8.1"), "bdautodial": ("0.2.2", "0.2.3"),
                "bestdose": ("1.0.9", "1.0.10")}
    apps, current = {}, []
    for app, app_versions in versions.items():
        directory = root / "downloads" / app / "stable"
        directory.mkdir(parents=True, mode=0o755)
        files = {}
        for version in app_versions:
            data = f"observed synthetic historical archive:{app}:{version}".encode()
            digest = hashlib.sha256(data).hexdigest()
            name = f"{app}-{version}-darwin-aarch64-{digest}.app.zip"
            path = directory / name
            path.write_bytes(data)
            os.chmod(path, 0o600 if app == "papir" and version == app_versions[0] else 0o644)
            files[name] = {"size": len(data), "sha256": digest}
        latest = {"version": app_versions[-1], "platforms": {"darwin-aarch64": {
            "url": f"{policy.origin}/downloads/{app}/stable/{name}"}}}
        (directory / "latest.json").write_bytes(canonical(latest) + b"\n")
        os.chmod(directory / "latest.json", 0o644)
        apps[app] = {"channels": {"stable": {"version": app_versions[-1], "files": files}}}
        current.append({"app": app, "channel": "stable", "target": "darwin-aarch64",
                        "version": app_versions[-1], "feed": "latest.json", "artifact": name})
        if app in ("launcher", "papir"):
            alias = root / app
            alias.mkdir(mode=0o755)
            (alias / name).write_bytes(data)
            os.chmod(alias / name, 0o644)
            (alias / "latest.json").write_bytes(canonical(latest) + b"\n")
            os.chmod(alias / "latest.json", 0o644)
    catalog = {"schema": "lapkb-downloads-v1", "apps": apps}
    downloads = root / "downloads"
    (downloads / "catalog.json").write_bytes(canonical(catalog) + b"\n")
    (downloads / "index.html").write_bytes(b"<html>retained original fixture page</html>\n")
    (root / "launcher" / "opaque-old-placeholder.zip").write_bytes(b"not architecture/signature evidence")
    (root / "launcher" / "retained-empty-placeholder").write_bytes(b"")
    return {"schema": "lapkb-historical-inventory-v1", "root": str(root), "origin": policy.origin,
            "observedAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "inventory": public_snapshot(root), "catalog": catalog,
            "current": sorted(current, key=lambda item: (item["app"], item["channel"], item["target"]))}


def make_root():
    temp = tempfile.TemporaryDirectory(prefix="lapkb-publisher-test-")
    root = Path(temp.name).resolve() / "public"
    root.mkdir(mode=0o700)
    return temp, root
