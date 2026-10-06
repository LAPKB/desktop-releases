"""Prepare the existing canonical signed contract from exact successful CI inputs.

Only pinned administrative tools execute here. Product archives/executables and
producer proofs are bounded data. Launcher artifact signatures remain originals;
new app signatures use that app's existing archive key, never licence keys.
"""
from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
from pathlib import Path

from release_github import TARGETS, producer_attempt, require, validate_candidate
import release_contract as contract
import publish_artifact


class Signer:
    def __init__(self, policy, app, key, tool, verifier):
        self.public = policy.apps[app]["channels"]["stable"]["publicKey"]
        self.key = publish_artifact._owned_regular_file(str(key), private=True)
        self.tool, self.verifier = Path(tool), Path(verifier)

    def sign(self, payload, scratch):
        # The maintained Tauri signer writes an encoded minisign sibling. Work
        # only on a private copy; no signed bundle file is ever overwritten.
        scratch.mkdir(mode=0o700)
        copy = scratch / payload.name
        shutil.copyfile(payload, copy)
        os.chmod(copy, 0o600)
        before = contract._sha256_file(copy)
        try:
            subprocess.run([str(self.tool), "signer", "sign", "--private-key-path", str(self.key), "--password", "", str(copy)], cwd=scratch, env={"PATH": "/usr/bin:/bin", "HOME": str(scratch), "LC_ALL": "C"}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300, check=True)
        except (OSError, subprocess.SubprocessError) as error:
            raise contract.ContractError("Existing app signing key/tool could not sign; no publication attempted") from error
        require(contract._sha256_file(copy) == before, "Signing changed the candidate payload")
        encoded = contract._read_regular(copy.with_name(copy.name + ".sig"), contract.MAX_SIGNATURE_BYTES, "Tauri signature").decode("ascii").strip()
        raw = decode_signature(encoded)
        contract.verify_minisign(copy, contract._signature_text(raw, "generated signature"), self.public, self.verifier, scratch)
        return raw


def decode_signature(encoded):
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, UnicodeError) as error:
        raise contract.ContractError("Candidate signature is not canonical base64 minisign") from error
    require(base64.b64encode(raw).decode("ascii") == encoded, "Candidate signature encoding is noncanonical")
    contract._signature_text(raw, "candidate signature")
    return raw


def write_new(path, data):
    with Path(path).open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def proof_file(directory, item):
    require(type(item) is dict and {"filename", "size", "sha256"} <= set(item), "Package proof is missing its original file identity")
    name = item["filename"]
    require(type(name) is str and name == Path(name).name and name not in (".", ".."), "Unsafe original package proof filename")
    path = directory / name
    require(contract._sha256_file(path, expected_size=item["size"]) == (item["size"], item["sha256"]), "Original file bytes differ from successful native package proof")
    return path


def read_proof(directory, plan, target, policy):
    validate_candidate(directory, plan, target)
    filename = "macos-package.json" if target == "darwin-aarch64" else "windows-package.json"
    proof = contract.strict_json(contract._read_regular(directory / filename, 2 * 1024 * 1024, "package proof"), 2 * 1024 * 1024, "package proof")
    build = {"runId": str(plan["producerRun"]), "runAttempt": producer_attempt(plan), "profile": "public-staging"}
    require(type(proof) is dict and proof.get("schema") == ("lapkb-macos-package-v1" if target == "darwin-aarch64" else "lapkb-windows-package-v1") and proof.get("app") == plan["app"] and proof.get("target") == target and proof.get("version") == plan["version"] and proof.get("sourceCommit") == plan["source"] and proof.get("build") == build, "Native package proof source/run/attempt/profile/version/target differs")
    identity = {"bundleIdentifier": contract.BUNDLE_IDS[plan["app"]], "displayName": contract.WINDOWS_PRODUCTS[plan["app"]] if target == "windows-x86_64" or plan["app"] == "launcher" else contract.DISPLAY_NAMES[plan["app"]], "executable": policy.apps[plan["app"]]["executable"], "architecture": target.split("-")[-1], "version": plan["version"]}
    if target == "darwin-aarch64":
        require(proof.get("packageIdentity") == identity and type(proof.get("checks")) is list and "ad-hoc seal" in proof["checks"] and any("tar" in c for c in proof["checks"]), "Mac identity/resource-seal/package proof is missing")
        require(type(proof.get("artifacts")) is list and 1 <= len(proof["artifacts"]) <= 3, "Mac original package inventory is invalid")
        originals = [(item, proof_file(directory, item)) for item in proof["artifacts"]]
        require(len({p.name for _, p in originals}) == len(originals) and sum(p.name == proof.get("updater") for _, p in originals) == 1, "Mac package proof updater/original inventory is ambiguous")
    else:
        require(proof.get("installer", {}).get("kind") == "nsis" and proof.get("installer", {}).get("stubMachine") in (0x14c, 0x8664), "Genuine inspected NSIS installer proof is missing")
        compiled = proof["compiledApplication"]
        # Launcher exports the compiled PE under its original content-addressed
        # name; the proof retains the native compiler's leaf. All other apps
        # retain the compiler leaf. Do not execute a new/parallel PE parser.
        if plan["app"] == "launcher":
            matches = [p for p in directory.iterdir() if p.name.endswith(".exe") and p.name != proof["installer"]["filename"] and contract._sha256_file(p) == (compiled["size"], compiled["sha256"])]
            require(len(matches) == 1, "Exactly one original compiled Launcher PE is required")
        else:
            proof_file(directory, compiled)
        contract._validate_windows_payload({"build": build, "windowsPayload": proof["windowsPayload"]}, plan["app"], plan["version"], identity["executable"])
        originals = [(proof["installer"], proof_file(directory, proof["installer"]))]
    return proof, identity, originals


def prepare(plan, policy, candidates, output, signer, verifier):
    app, version = plan["app"], plan["version"]
    require(policy.apps[app]["branch"] == plan["branch"] and policy.apps[app]["sourceRepository"] == plan["repository"], "Protected policy source differs from resolved release source")
    expected_coverage = ["launcher-desktop"] if app == "launcher" else ["macos-arm64", "windows-x64"]
    require(policy.apps[app]["allowedCoverages"] == expected_coverage, "Protected policy must explicitly qualify Mac ARM64 and Windows x64")
    output.mkdir(mode=0o700)
    signing = output.parent / "signing"
    signing.mkdir(mode=0o700)
    targets = {}
    # Both original candidate proofs/inventories must validate before signing.
    proofs = {t: read_proof(candidates / t, plan, t, policy) for t in TARGETS}
    scopes = {"launcher-desktop": TARGETS} if app == "launcher" else {"macos-arm64": (TARGETS[0],), "windows-x64": (TARGETS[1],)}
    bundle_dirs = {}
    for coverage, selected in scopes.items():
        bundle = output / coverage
        bundle.mkdir(mode=0o700)
        bundle_dirs[coverage] = bundle
        for target in selected:
            proof, identity, originals = proofs[target]
            records, profiles_used = [], set()
            profiles = policy.apps[app]["channels"]["stable"]["profiles"][target]
            for item, original in originals:
                profiles_for_file = [p for p in profiles if original.name.endswith("." + p["extension"])]
                require(len(profiles_for_file) == 1, "Original candidate format is not an exact protected package profile")
                profile = profiles_for_file[0]
                require(profile["id"] not in profiles_used, "Duplicate candidate package profile")
                profiles_used.add(profile["id"])
                name = f"{app}-{version}-{target}-{item['sha256']}.{profile['extension']}"
                destination = bundle / name
                shutil.copyfile(original, destination)
                os.chmod(destination, 0o600)
                require(contract._sha256_file(destination) == (item["size"], item["sha256"]), "Candidate changed during private preparation")
                encoded = None
                if "updater" in profile["roles"]:
                    if app == "launcher":
                        encoded = contract._read_regular(original.with_name(original.name + ".sig"), contract.MAX_SIGNATURE_BYTES, "original Launcher signature").decode("ascii").strip()
                        raw = decode_signature(encoded)
                        if target == "darwin-aarch64":
                            require(encoded == proof["updaterSignature"], "Original Launcher signature differs from native proof")
                    else:
                        raw = signer.sign(destination, signing / (target + "-payload"))
                        encoded = base64.b64encode(raw).decode("ascii")
                    contract.verify_minisign(destination, contract._signature_text(raw, "updater signature"), policy.apps[app]["channels"]["stable"]["publicKey"], verifier, signing)
                records.append({"name": name, "kind": profile["kind"], "roles": profile["roles"], "size": item["size"], "sha256": item["sha256"], "signatureKeyId": policy.apps[app]["channels"]["stable"]["keyId"] if encoded else None, "updaterSignature": encoded})
            require(all(not p["required"] or p["id"] in profiles_used for p in profiles), "Native candidate is missing a required installer/updater profile")
            targets[target] = {"packageIdentity": identity, "build": proof["build"], "artifacts": sorted(records, key=lambda r: r["name"])}
            if target == "windows-x86_64":
                targets[target]["windowsPayload"] = proof["windowsPayload"]
        source = {"repository": plan["repository"], "branch": plan["branch"], "commit": plan["source"], "tag": f"publish-{app}-stable-{version}"}
        attestation = {"schema": "lapkb-build-attestation-v1", "app": app, "channel": "stable", "version": version, "coverage": coverage, "source": source, "targets": {t: targets[t] for t in selected}}
        manifest = contract._expected_manifest(policy, app, "stable", version, attestation)
        receipt = contract._expected_receipt(policy, app, "stable", version, attestation, manifest)
        write_new(bundle / contract.feed_for_coverage(coverage), manifest)
        attestation_name, receipt_name = contract.metadata_names(version, coverage)
        for prefix, name, value in (("build-attestation", attestation_name, attestation), ("release-receipt", receipt_name, receipt)):
            payload = bundle / name
            write_new(payload, contract.canonical_json(value))
            write_new(payload.with_name(payload.name + ".sig"), signer.sign(payload, signing / (coverage + "-" + prefix)))
    # The sole shared validator/native verifier authorizes the complete pair
    # before the existing writer is allowed to promote either app feed.
    releases = validate_bundles(plan, policy, output, verifier, _preparing=True)
    meta = {"schema": "lapkb-automatic-release-bundle-v1", "plan": plan, "bundles": {scope: {"inventory": r["inventory"], "inventoryDigest": r["inventoryDigest"], "receiptSha256": hashlib.sha256(r["receiptBytes"]).hexdigest()} for scope, r in releases.items()}}
    write_new(output / "automation.json", contract.canonical_json(meta))
    return meta


def validate_bundles(plan, policy, output, verifier, *, _preparing=False):
    scopes = ("launcher-desktop",) if plan["app"] == "launcher" else ("macos-arm64", "windows-x64")
    allowed = set(scopes) | (set() if _preparing else {"automation.json"})
    require({p.name for p in output.iterdir()} == allowed, "Immutable signed release contains missing/unexpected scopes")
    releases = {}
    for scope in scopes:
        bundle = output / scope
        release = contract.validate_release(plan["app"], "stable", {p.name: p for p in bundle.iterdir()}, policy, verifier=verifier, scratch=output.parent)
        require(release["coverage"] == scope and release["version"] == plan["version"] and release["source"]["repository"] == plan["repository"] and release["source"]["branch"] == plan["branch"] and release["source"]["commit"] == plan["source"], "Immutable retry version/source/coverage differs")
        require(all(t["build"] == {"runId": str(plan["producerRun"]), "runAttempt": producer_attempt(plan), "profile": "public-staging"} for t in release["receipt"]["targets"].values()), "Immutable retry mixes producer run/attempts")
        releases[scope] = release
    if "automation.json" in allowed:
        raw = contract._read_regular(output / "automation.json", 2 * 1024 * 1024, "immutable release metadata")
        meta = contract.strict_json(raw, 2 * 1024 * 1024, "immutable release metadata")
        require(type(meta) is dict and set(meta) == {"schema", "plan", "bundles"} and contract.canonical_json(meta) == raw and meta["schema"] == "lapkb-automatic-release-bundle-v1" and meta["plan"] == plan and type(meta["bundles"]) is dict and set(meta["bundles"]) == set(scopes), "Immutable retry metadata/source plan differs")
        for scope, release in releases.items():
            require(meta["bundles"][scope] == {"inventory": release["inventory"], "inventoryDigest": release["inventoryDigest"], "receiptSha256": hashlib.sha256(release["receiptBytes"]).hexdigest()}, "Immutable retry signed bytes differ from the retained receipt/inventory")
    return releases
