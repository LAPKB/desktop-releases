"""Strict, shared LAPKB release contract for caller, pickup, and publisher.

The module accepts no uploaded trust roots. Production trust and package profiles
come only from a protected local configuration; incomplete configuration fails
closed. Signed-app metadata is an authenticated build claim, not independent
archive inspection. Only explicit Launcher Windows policy permits manual
checksum/provenance metadata, without any signature or updater claim.
"""
from __future__ import annotations

import base64
import binascii
import datetime as _datetime
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import urlsplit

APP_IDS = ("launcher", "papir", "bestdose", "bdautodial", "checkerboard")
CHANNELS = ("stable", "beta")
TARGETS = (
    "darwin-aarch64", "darwin-x86_64", "windows-aarch64",
    "windows-x86_64", "linux-aarch64", "linux-x86_64",
)
COVERAGES = {"full-six": TARGETS, "windows-x64": ("windows-x86_64",),
             "macos-arm64": ("darwin-aarch64",),
             "launcher-desktop": ("darwin-aarch64", "windows-x86_64")}
WINDOWS_MINIMUMS = {"launcher": "0.1.9", "papir": "0.1.5", "bdautodial": "0.2.4", "bestdose": "1.0.11", "checkerboard": "0.8.2"}
WINDOWS_PRODUCTS = {"launcher": "LAPKB Launcher", **{app: name for app, name in {
    "papir": "Papir", "bdautodial": "BDautodial", "bestdose": "BestDose", "checkerboard": "Checkmate"}.items()}}
BUNDLE_IDS = {
    "launcher": "org.lapkb.launcher",
    "papir": "com.papir.app",
    "bestdose": "org.lapkb.bestdose",
    "bdautodial": "com.bdautodial.desktop",
    "checkerboard": "org.lapkb.checkmate",
}
DISPLAY_NAMES = {
    "launcher": "Launcher", "papir": "Papir", "bestdose": "BestDose",
    "bdautodial": "BDautodial", "checkerboard": "Checkmate",
}
VERIFIER_PATH = Path("/usr/local/libexec/lapkb-release-verifier")
CONFIG_PATH = Path("/etc/lapkb/publisher.json")

MAX_CONFIG_BYTES = 256 * 1024
MAX_ATTESTATION_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_RELEASE_BYTES = 8 * 1024 * 1024 * 1024
MAX_FILES = 64
_HEX = re.compile(r"^[0-9a-f]{64}$")
_VERSION_BODY = r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
_VERSION = re.compile("^" + _VERSION_BODY + "$")
_ATTESTATION_NAME = re.compile(r"^build-attestation-" + _VERSION_BODY + r"(?:-macos-arm64)?\.json$")
_RECEIPT_NAME = re.compile(r"^release-receipt-" + _VERSION_BODY + r"(?:-macos-arm64)?\.json$")
_KEY_ID = re.compile(r"^[0-9A-F]{16}$")
_EXT = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-]{0,63}$")
_IDENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ContractError(ValueError):
    """A release or trusted publisher policy violates the contract."""


@dataclass(frozen=True)
class Policy:
    root: str
    origin: str
    pickup_repository: str
    checkmate_minimum_version: tuple[int, int, int]
    legacy_aliases: dict[str, dict[str, str | None]]
    apps: dict


def _pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json(data: bytes, maximum: int, label: str):
    if type(data) is not bytes or len(data) > maximum:
        raise ContractError(f"{label} exceeds its size limit")
    try:
        text = data.decode("utf-8", "strict")
        value = json.loads(
            text, object_pairs_hook=_pairs_no_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ContractError(f"invalid JSON number in {label}")),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"{label} is not valid UTF-8 JSON") from error
    return value


def canonical_json(value) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ContractError("release metadata cannot be canonically encoded") from error


def _object(value, keys, label):
    if type(value) is not dict or set(value) != set(keys):
        raise ContractError(f"{label} has an unexpected shape")
    return value


def _version(value, label="version"):
    if (type(value) is not str or len(value) > 32 or not _VERSION.fullmatch(value)
            or any(len(part) > 10 for part in value.split("."))):
        raise ContractError(f"{label} must be a canonical three-part version")
    parts = tuple(int(part) for part in value.split("."))
    if any(part > 2**31 - 1 for part in parts):
        raise ContractError(f"{label} component is out of range")
    return parts


def _nonempty(value, label, maximum=256):
    if type(value) is not str or not value or len(value) > maximum or "\x00" in value:
        raise ContractError(f"{label} must be a bounded non-empty string")
    return value


def _trusted_public_key_id(text: str) -> str:
    if type(text) is not str or len(text.encode("utf-8")) > 4096:
        raise ContractError("configured release public key is invalid")
    lines = text.splitlines()
    if (len(lines) != 2 or not lines[0].startswith("untrusted comment: minisign public key")
            or not lines[1] or any(ch.isspace() for ch in lines[1])):
        raise ContractError("configured release public key is invalid")
    try:
        raw = base64.b64decode(lines[1], validate=True)
    except (binascii.Error, ValueError):
        raise ContractError("configured release public key is invalid") from None
    if len(raw) != 42 or raw[:2] not in (b"Ed", b"ED"):
        raise ContractError("configured release public key is invalid")
    return f"{int.from_bytes(raw[2:10], 'little'):016X}"


def _safe_origin(value):
    if type(value) is not str or len(value) > 512:
        raise ContractError("publisher origin is not configured")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")
            or parsed.hostname.lower() != parsed.hostname):
        raise ContractError("publisher origin must be an exact HTTPS origin")
    try:
        port = parsed.port
    except ValueError as error:
        raise ContractError("publisher origin has an invalid port") from error
    if port is not None and not 1 <= port <= 65535:
        raise ContractError("publisher origin has an invalid port")
    if port == 443:
        raise ContractError("publisher origin must omit the default HTTPS port")
    authority = parsed.hostname
    if ":" in authority:
        authority = f"[{authority}]"
    if port is not None:
        authority += f":{port}"
    normalized = f"https://{authority}"
    if value != normalized:
        raise ContractError("publisher origin is not canonical")
    return normalized


def _validate_profile(profile):
    _object(profile, ("id", "extension", "kind", "roles", "required"), "package profile")
    _nonempty(profile["id"], "package profile id", 64)
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", profile["id"]):
        raise ContractError("package profile id is invalid")
    extension = profile["extension"]
    if (type(extension) is not str or not _EXT.fullmatch(extension)
            or any(part in ("", ".", "..") for part in extension.split("."))):
        raise ContractError("package profile extension is invalid")
    _nonempty(profile["kind"], "package kind", 64)
    roles = profile["roles"]
    if (type(roles) is not list or not roles or any(type(role) is not str for role in roles)
            or roles != sorted(set(roles)) or not set(roles) <= {"installer", "updater"}):
        raise ContractError("package profile roles are invalid")
    if type(profile["required"]) is not bool:
        raise ContractError("package profile required must be a boolean")
    return


def validate_policy(value) -> Policy:
    _object(value, ("schema", "root", "origin", "pickupRepository", "checkmateMinimumVersion",
                    "legacyAliases", "apps"), "publisher configuration")
    if value["schema"] != "lapkb-publisher-trust-v1":
        raise ContractError("publisher configuration schema is not supported")
    root = value["root"]
    if type(root) is not str or not root.startswith("/") or root == "/" or "\x00" in root:
        raise ContractError("publisher root must be an absolute configured path")
    components = root.split("/")
    if (any(component in ("", ".", "..") for component in components[1:])
            or root != os.path.normpath(root)):
        raise ContractError("publisher root must be canonical")
    origin = _safe_origin(value["origin"])
    pickup_repository = value["pickupRepository"]
    if (type(pickup_repository) is not str
            or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", pickup_repository)):
        raise ContractError("approved GitHub release repository is invalid")
    minimum = _version(value["checkmateMinimumVersion"], "Checkmate minimum version")

    aliases = value["legacyAliases"]
    if type(aliases) is not dict or set(aliases) != set(APP_IDS):
        raise ContractError("legacy alias mapping must explicitly cover all applications")
    all_aliases = []
    normalized_aliases = {}
    for app, channels in aliases.items():
        if (type(channels) is not dict or not channels or not set(channels) <= set(CHANNELS)):
            raise ContractError(f"legacy alias mapping for {app} must name configured known channels")
        normalized_aliases[app] = {}
        for channel, alias in channels.items():
            if alias is not None and (type(alias) is not str or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", alias)
                                      or alias in ("downloads", "catalog", "index")):
                raise ContractError(f"legacy alias for {app}/{channel} is invalid")
            if alias is not None:
                all_aliases.append(alias)
            normalized_aliases[app][channel] = alias
    if len(set(all_aliases)) != len(all_aliases):
        raise ContractError("legacy aliases must be unique")
    aliases = normalized_aliases

    apps = value["apps"]
    if type(apps) is not dict or set(apps) != set(APP_IDS):
        raise ContractError("trusted release policy must explicitly cover all five applications")
    normalized_apps = {}
    for app in APP_IDS:
        entry = apps[app]
        required = {"sourceRepository", "branch", "bundleIdentifier", "executable", "channels"}
        if type(entry) is not dict or not required <= set(entry) or set(entry) - (required | {"allowedCoverages", "retainedManualRecords", "retainedSourceRecords"}):
            raise ContractError(f"{app} policy has an unexpected shape")
        coverages = entry.get("allowedCoverages", ["full-six"])
        if (type(coverages) is not list or not coverages
                or any(type(item) is not str or item not in COVERAGES for item in coverages)
                or coverages != sorted(set(coverages))):
            raise ContractError(f"{app} receiver-approved coverage is invalid")
        if "launcher-desktop" in coverages and (app != "launcher" or coverages != ["launcher-desktop"]):
            raise ContractError("Launcher desktop coverage is only approved as the exact two-target Launcher scope")
        if "macos-arm64" in coverages and (app == "launcher" or set(coverages) != {"macos-arm64", "windows-x64"}):
            raise ContractError("app desktop publication requires both explicit Mac ARM64 and Windows x64 scopes")
        retained_sources = entry.get("retainedSourceRecords", [])
        if (type(retained_sources) is not list or len(retained_sources) > 1024
                or any(type(h) is not str or not _HEX.fullmatch(h) for h in retained_sources)
                or retained_sources != sorted(set(retained_sources))
                or "retainedSourceRecords" in entry and not retained_sources):
            raise ContractError("retained source records must be sorted exact whole durable-record hashes")
        retained = entry.get("retainedManualRecords", {})
        if (type(retained) is not dict or len(retained) > 2
                or "retainedManualRecords" in entry and (not retained or app != "launcher" or "launcher-desktop" not in coverages)
                or any(v not in ("0.1.9", "0.1.10") or type(h) is not str or not _HEX.fullmatch(h)
                       for v, h in retained.items())):
            raise ContractError("retained manual Launcher records must be exact bounded historical hashes")
        source_repository = entry["sourceRepository"]
        if (type(source_repository) is not str
                or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", source_repository)):
            raise ContractError(f"{app} approved source repository is invalid")
        branch = _nonempty(entry["branch"], f"{app} approved branch", 128)
        if any(ord(char) < 0x21 or char in "\\" for char in branch):
            raise ContractError(f"{app} approved branch is invalid")
        if entry["bundleIdentifier"] != BUNDLE_IDS[app]:
            raise ContractError(f"{app} bundle identity differs from the approved identity")
        executable = _nonempty(entry["executable"], f"{app} executable", 128)
        if not _IDENT.fullmatch(executable):
            raise ContractError(f"{app} executable identity is invalid")
        if app == "checkerboard" and executable != "checkmate-desktop":
            raise ContractError("Checkmate executable identity must be checkmate-desktop")
        channels = entry["channels"]
        if (type(channels) is not dict or not channels or not set(channels) <= set(CHANNELS)
                or set(channels) != set(aliases[app])):
            raise ContractError(f"{app} must explicitly configure matching known channels and aliases")
        if set(coverages) & {"launcher-desktop", "macos-arm64"} and set(channels) != {"stable"}:
            raise ContractError("Launcher desktop bootstrap is approved only for stable")
        normalized_channels = {}
        required_targets = {target for coverage in coverages for target in COVERAGES[coverage]}
        for channel, channel_policy in channels.items():
            required_channel = {"publicKey", "keyId", "profiles"}
            if (type(channel_policy) is not dict or not required_channel <= set(channel_policy)
                    or set(channel_policy) - (required_channel | {"manualTargets", "macFeedUrl"})):
                raise ContractError(f"{app}/{channel} policy has an unexpected shape")
            manual_targets = channel_policy.get("manualTargets", [])
            if (type(manual_targets) is not list or manual_targets not in ([], ["windows-x86_64"])
                    or manual_targets and (app != "launcher" or channel != "stable"
                                          or coverages != ["windows-x64"])):
                raise ContractError("manual/checksum policy is only supported for Launcher stable Windows x64")
            public_key = channel_policy["publicKey"]
            key_id = channel_policy["keyId"]
            if manual_targets:
                if public_key is not None or key_id is not None:
                    raise ContractError("manual Launcher must not claim an updater public key")
            elif (type(key_id) is not str or not _KEY_ID.fullmatch(key_id)
                  or _trusted_public_key_id(public_key) != key_id):
                raise ContractError(f"{app}/{channel} public key ID does not match trusted key")
            profiles_by_target = channel_policy["profiles"]
            if type(profiles_by_target) is not dict or set(profiles_by_target) != required_targets:
                raise ContractError(f"{app}/{channel} must configure exactly its approved coverage targets")
            normalized_profiles = {}
            for target in sorted(required_targets):
                profiles = profiles_by_target[target]
                if type(profiles) is not list or not profiles or len(profiles) > 8:
                    raise ContractError(f"{app}/{channel}/{target} package profiles are missing")
                ids, extensions = set(), set()
                for profile in profiles:
                    _validate_profile(profile)
                    if profile["id"] in ids or profile["extension"].lower() in extensions:
                        raise ContractError(f"{app}/{channel}/{target} profile is duplicated")
                    ids.add(profile["id"])
                    extensions.add(profile["extension"].lower())
                if not any("installer" in profile["roles"] for profile in profiles):
                    raise ContractError(f"{app}/{channel}/{target} has no installer profile")
                expected_updaters = 0 if target in manual_targets else 1
                if sum("updater" in profile["roles"] for profile in profiles) != expected_updaters:
                    raise ContractError(f"{app}/{channel}/{target} has an invalid updater profile count")
                # 6c65efc9's BestDose MSI-only note was a packaging preference,
                # not a produced MSI/enterprise constraint. The owner selected
                # the existing current-user NSIS experience for this release.
                if target == "windows-x86_64" and set(coverages) & {"windows-x64", "launcher-desktop"}:
                    expected_roles = ["installer"] if manual_targets else ["installer", "updater"]
                    if (len(profiles) != 1 or profiles[0]["extension"] != "exe"
                            or profiles[0]["kind"] != "nsis"
                            or profiles[0]["roles"] != expected_roles
                            or profiles[0]["required"] is not True):
                        raise ContractError("Windows x64 app release requires the signed NSIS installer/updater profile")
                if set(coverages) & {"launcher-desktop", "macos-arm64"} and target == "darwin-aarch64":
                    updater = next(profile for profile in profiles if "updater" in profile["roles"])
                    if (len(profiles) > 3 or updater["extension"] != "app.tar.gz"
                            or updater["kind"] != "app-tar-gz" or updater["required"] is not True):
                        raise ContractError("Launcher Mac updater requires its genuine signed app.tar.gz profile")
                normalized_profiles[target] = profiles
            mac_feed = channel_policy.get("macFeedUrl")
            if "macos-arm64" in coverages:
                _nonempty(mac_feed, f"{app} existing Mac feed URL", 1024)
                parsed = urlsplit(mac_feed)
                _safe_origin(f"{parsed.scheme}://{parsed.netloc}")
                canonical_path = f"/downloads/{app}/{channel}/latest.json"
                alias_path = f"/{aliases[app][channel]}/latest.json" if aliases[app][channel] else None
                if (parsed.username or parsed.password or parsed.query or parsed.fragment
                        or parsed.path not in (canonical_path, alias_path)
                        or parsed.path == canonical_path and f"{parsed.scheme}://{parsed.netloc}" != origin):
                    raise ContractError("existing Mac feed must be the canonical feed or its configured legacy alias")
            elif "macFeedUrl" in channel_policy:
                raise ContractError("Mac feed URL is only configured for honest app Mac coverage")
            normalized_channels[channel] = {
                "publicKey": public_key, "keyId": key_id, "profiles": normalized_profiles,
                "manualTargets": manual_targets,
            }
            if mac_feed is not None:
                normalized_channels[channel]["macFeedUrl"] = mac_feed
        normalized_apps[app] = {
            "sourceRepository": source_repository, "branch": branch,
            "bundleIdentifier": entry["bundleIdentifier"],
            "executable": executable, "channels": normalized_channels,
            "allowedCoverages": coverages,
        }
        if retained:
            normalized_apps[app]["retainedManualRecords"] = retained
        if retained_sources:
            normalized_apps[app]["retainedSourceRecords"] = retained_sources
    return Policy(root, origin, pickup_repository, minimum, aliases, normalized_apps)


def retained_policy(policy, record):
    """Derive historical authority only from an explicitly pinned whole record.

    Fresh attestations, uploads and journal scope objects cannot match this shape.
    A source pin restores only that record's retired branch, never a branch list,
    uploaded key, changed bytes, package identity or general release authority.
    The independent historical manual pin retains its existing narrow trust.
    """
    fields = {"app", "channel", "version", "versionTuple", "source", "inventory",
              "inventoryDigest", "receipt", "receiptSha256", "buildAttestationSha256",
              "manifestSha256", "coverage", "feed", "targets", "distribution"}
    if type(record) is not dict or set(record) != fields or record.get("app") not in policy.apps:
        return policy
    app = record["app"]
    entry = policy.apps[app]
    digest = hashlib.sha256(canonical_json(record)).hexdigest()
    manual_pin = (app == "launcher" and record.get("channel") == "stable"
        and record.get("coverage") == "windows-x64" and record.get("distribution") == "manual-checksum"
        and type(record.get("version")) is str
        and entry.get("retainedManualRecords", {}).get(record["version"]) == digest)
    source_pin = digest in entry.get("retainedSourceRecords", [])
    if not manual_pin and not source_pin:
        return policy
    restored = {**entry}
    if source_pin:
        source = _object(record["source"], ("repository", "branch", "commit", "tag"), "retained source")
        if source["repository"] != entry["sourceRepository"]:
            raise ContractError("retained source repository differs from configured application")
        branch = _nonempty(source["branch"], "retained source branch", 128)
        if any(ord(c) < 0x21 or c == "\\" for c in branch):
            raise ContractError("retained source branch is invalid")
        restored["branch"] = branch
    if manual_pin:
        restored.update(allowedCoverages=["windows-x64"], channels={"stable": {
            "publicKey": None, "keyId": None, "manualTargets": ["windows-x86_64"],
            "profiles": {"windows-x86_64": [{"id": "nsis", "extension": "exe", "kind": "nsis",
                "required": True, "roles": ["installer"]}]}}})
    return replace(policy, apps={**policy.apps, app: restored})


def _read_protected_file(path: Path, maximum: int, *, private=False):
    """Read a local, protected policy or reviewed administrative input."""
    path = Path(path)
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)) or path == Path("/"):
        raise ContractError("trusted publisher configuration path is not canonical")
    parts = path.parts[1:]
    if not parts:
        raise ContractError("trusted publisher configuration path is invalid")
    dir_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                     | getattr(os, "O_NOFOLLOW", 0))
    try:
        for component in parts[:-1]:
            next_fd = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0), dir_fd=dir_fd)
            os.close(dir_fd)
            dir_fd = next_fd
            info = os.fstat(dir_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or (info.st_mode & 0o022 and not (info.st_mode & stat.S_ISVTX and info.st_uid == 0))):
                raise ContractError("trusted publisher configuration ancestor is unsafe")
        try:
            fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=dir_fd)
        except OSError as error:
            raise ContractError("trusted publisher configuration is unavailable") from error
        try:
            opened = os.fstat(fd)
            if (not stat.S_ISREG(opened.st_mode) or opened.st_uid not in (0, os.geteuid())
                    or opened.st_nlink != 1 or opened.st_mode & 0o022
                    or (private and stat.S_IMODE(opened.st_mode) != 0o600)
                    or opened.st_size > maximum):
                raise ContractError("trusted publisher configuration ownership or permissions are unsafe")
            data = bytearray()
            path_info = os.stat(parts[-1], dir_fd=dir_fd, follow_symlinks=False)
            if (path_info.st_dev, path_info.st_ino) != (opened.st_dev, opened.st_ino):
                raise ContractError("protected publisher input changed while opening")
            while len(data) <= maximum:
                chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            after = os.fstat(fd)
            if (opened.st_size, opened.st_mode, opened.st_nlink, opened.st_mtime_ns, opened.st_ctime_ns) != (
                    after.st_size, after.st_mode, after.st_nlink, after.st_mtime_ns, after.st_ctime_ns):
                raise ContractError("protected publisher input changed while reading")
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)
    if len(data) > maximum or len(data) != opened.st_size:
        raise ContractError("protected publisher input changed or exceeds its size limit")
    return bytes(data)


def load_policy(path: Path = CONFIG_PATH) -> Policy:
    data = _read_protected_file(path, MAX_CONFIG_BYTES)
    return validate_policy(strict_json(data, MAX_CONFIG_BYTES, "publisher configuration"))


def _sha256_file(path: Path, expected_size: int | None = None, maximum=MAX_FILE_BYTES):
    try:
        st = path.lstat()
    except OSError as error:
        raise ContractError("release file is missing") from error
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise ContractError("release inventory contains a link or special file")
    if st.st_size <= 0 or st.st_size > maximum:
        raise ContractError("release file size is outside the allowed bounds")
    if expected_size is not None and st.st_size != expected_size:
        raise ContractError("attested release file size does not match the file")
    digest = hashlib.sha256()
    total = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_size != st.st_size
                or (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino)):
            raise ContractError("release file changed while opening")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ContractError("release file exceeds its size limit")
            digest.update(chunk)
    finally:
        os.close(fd)
    if total != st.st_size:
        raise ContractError("release file changed while hashing")
    return total, digest.hexdigest()


def _read_regular(path: Path, maximum: int, label: str):
    size, _ = _sha256_file(path, maximum=maximum)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        chunks = bytearray()
        while len(chunks) <= maximum:
            data = os.read(fd, min(65536, maximum + 1 - len(chunks)))
            if not data:
                break
            chunks.extend(data)
    finally:
        os.close(fd)
    if size != len(chunks) or len(chunks) > maximum:
        raise ContractError(f"{label} changed while reading")
    return bytes(chunks)


def _signature_text(data: bytes, label: str) -> str:
    if len(data) == 0 or len(data) > MAX_SIGNATURE_BYTES or b"\r" in data:
        raise ContractError(f"{label} is malformed or oversized")
    try:
        text = data.decode("ascii", "strict")
    except UnicodeError as error:
        raise ContractError(f"{label} is not ASCII minisign data") from error
    lines = text.splitlines()
    if len(lines) != 4 or any(not line for line in lines) or not lines[0].startswith("untrusted comment: ") or not lines[2].startswith("trusted comment: "):
        raise ContractError(f"{label} is not a complete minisign signature")
    if text not in ("\n".join(lines), "\n".join(lines) + "\n"):
        raise ContractError(f"{label} has noncanonical line endings")
    return text


def verify_minisign(payload: Path, signature_text: str, public_key: str,
                     verifier: Path = VERIFIER_PATH, scratch: Path | None = None):
    verifier = Path(verifier)
    if not verifier.is_file() or not os.access(verifier, os.X_OK):
        raise ContractError(
            "required LAPKB release verifier is missing; build host/verifier with its locked offline dependencies and install the binary at "
            + str(VERIFIER_PATH)
        )
    temp_dir = Path(scratch) if scratch is not None else None
    fd, sig_path = tempfile.mkstemp(prefix=".signature-", dir=temp_dir)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(signature_text.encode("ascii"))
            stream.flush()
            os.fsync(stream.fileno())
        try:
            result = subprocess.run(
                [str(verifier), "verify", sig_path, str(payload)],
                input=public_key.encode("utf-8"), stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, timeout=300, check=False,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, close_fds=True,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ContractError("LAPKB release verifier could not complete") from error
        if result.returncode != 0:
            raise ContractError("release signature verification failed")
    finally:
        try:
            os.unlink(sig_path)
        except FileNotFoundError:
            pass


def _validate_source(source, policy: Policy, app, channel, version):
    _object(source, ("repository", "branch", "commit", "tag"), "attested source")
    if source["repository"] != policy.apps[app]["sourceRepository"]:
        raise ContractError("attested source repository is not approved for this application")
    if source["branch"] != policy.apps[app]["branch"]:
        raise ContractError("attested source branch is not approved")
    commit = source["commit"]
    if type(commit) is not str or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit):
        raise ContractError("attested source commit is invalid")
    if source["tag"] != f"publish-{app}-{channel}-{version}":
        raise ContractError("attested source tag does not identify this release")


def _validate_optional_release_text(attestation):
    if "notes" in attestation:
        notes = attestation["notes"]
        if type(notes) is not str or len(notes.encode("utf-8")) > 16 * 1024 or "\x00" in notes:
            raise ContractError("release notes exceed the allowed bounds")
    if "pub_date" in attestation:
        value = attestation["pub_date"]
        if type(value) is not str or len(value) > 40 or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z", value):
            raise ContractError("release publication date is not canonical UTC")
        try:
            _datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ContractError("release publication date is invalid") from error


def _validate_build(build):
    build = _object(build, ("runId", "runAttempt", "profile"), "build identity")
    if (type(build["runId"]) is not str or not re.fullmatch(r"[1-9][0-9]{0,19}", build["runId"])
            or type(build["runAttempt"]) is not int or not 1 <= build["runAttempt"] <= 1000
            or build["profile"] != "public-staging"):
        raise ContractError("build source/run/attempt/profile identity is incomplete")


def _validate_windows_payload(target_entry, app, version, executable):
    _validate_build(target_entry["build"])
    payload = _object(target_entry["windowsPayload"],
        ("schema", "productName", "executable", "architecture", "version", "installMode", "files"), "Windows payload")
    if (payload["schema"] != "lapkb-windows-payload-v1" or payload["productName"] != WINDOWS_PRODUCTS[app]
            or payload["executable"] != executable + ".exe" or payload["architecture"] != "x86_64"
            or payload["version"] != version or payload["installMode"] != "currentUser"):
        raise ContractError("Windows NSIS payload identity/scope does not match policy")
    files = payload["files"]
    if type(files) is not list or not 1 <= len(files) <= 4096:
        raise ContractError("Windows payload inventory is missing or oversized")
    previous, seen, total = "", set(), 0
    reserved = re.compile(r"^(con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)", re.I)
    for item in files:
        _object(item, ("path", "size", "sha256"), "Windows payload file")
        path = item["path"]
        if (type(path) is not str or not path or len(path.encode("utf-8")) > 1024
                or path <= previous or path.lower() in seen
                or any(ord(c) < 32 or ord(c) == 127 or c in '\\:<>"|?*' for c in path)
                or any(part in ("", ".", "..") or part.endswith((".", " ")) or reserved.match(part) for part in path.split("/"))):
            raise ContractError("Windows payload inventory contains an unsafe/duplicate path")
        if (type(item["size"]) is not int or not 0 <= item["size"] <= 1024 * 1024 * 1024
                or type(item["sha256"]) is not str or not _HEX.fullmatch(item["sha256"])):
            raise ContractError("Windows payload inventory has an invalid final size/hash")
        previous = path
        seen.add(path.lower())
        total += item["size"]
        if total > 1024 * 1024 * 1024:
            raise ContractError("Windows payload exceeds the installed-size bound")
    if not any(item["path"] == executable + ".exe" and item["size"] > 0 for item in files):
        raise ContractError("Windows payload does not bind the real installed executable")


def metadata_names(version, coverage):
    """Mac app metadata shares a directory/version with its Windows metadata.

    Keep every existing Windows/Launcher filename unchanged. Only the newly
    qualified independent Mac app scope needs a non-colliding immutable leaf.
    """
    _version(version)
    suffix = "-macos-arm64" if coverage == "macos-arm64" else ""
    return (f"build-attestation-{version}{suffix}.json", f"release-receipt-{version}{suffix}.json")


def feed_for_coverage(coverage):
    if type(coverage) is not str or coverage not in COVERAGES:
        raise ContractError("unsupported release coverage")
    return "latest-windows.json" if coverage == "windows-x64" else "latest.json"


def release_mode(policy, app, channel, coverage):
    """Resolve the fixed receiver policy, never a producer-selected trust mode."""
    feed_for_coverage(coverage)
    if (type(app) is not str or type(channel) is not str
            or app not in policy.apps or channel not in policy.apps[app]["channels"]
            or coverage not in policy.apps[app]["allowedCoverages"]):
        raise ContractError("application/channel/coverage is not configured by this receiver")
    manual = policy.apps[app]["channels"][channel]["manualTargets"]
    return "manual-checksum" if manual and tuple(manual) == COVERAGES[coverage] else "signed"


def validate_publication_result(result, policy, release=None):
    """Bind the receiver response to its fixed configured scope and exact input."""
    keys = {"status", "app", "channel", "version", "coverage", "feed", "targets",
            "distribution", "inventory", "inventoryDigest"}
    if type(result) is not dict or set(result) != keys or result["status"] not in ("published", "identical-retry"):
        raise ContractError("publisher response has an unexpected shape/status")
    _version(result["version"])
    if (result["feed"] != feed_for_coverage(result["coverage"])
            or result["targets"] != sorted(COVERAGES[result["coverage"]])
            or result["distribution"] != release_mode(policy, result["app"], result["channel"], result["coverage"])):
        raise ContractError("publisher response coverage/feed/target/distribution differs from receiver policy")
    inventory = result["inventory"]
    if type(inventory) is not list or not 1 <= len(inventory) <= MAX_FILES:
        raise ContractError("publisher response inventory is malformed")
    names, total = [], 0
    for item in inventory:
        _object(item, ("name", "size", "sha256"), "publisher response inventory entry")
        if (type(item["name"]) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,191}", item["name"])
                or type(item["size"]) is not int or not 1 <= item["size"] <= MAX_FILE_BYTES
                or type(item["sha256"]) is not str or not _HEX.fullmatch(item["sha256"])):
            raise ContractError("publisher response inventory contains invalid names/sizes/hashes")
        names.append(item["name"])
        total += item["size"]
    if (names != sorted(set(names)) or set(names) & {"latest.json", "latest-windows.json"} != {result["feed"]}
            or total > MAX_RELEASE_BYTES
            or result["inventoryDigest"] != hashlib.sha256(canonical_json(inventory)).hexdigest()):
        raise ContractError("publisher response inventory digest/order/feed is inconsistent")
    if release is not None and any(result[key] != release[key] for key in keys - {"status"}):
        raise ContractError("publisher response differs from the exact validated release identity/inventory")
    return result


def _expected_manifest(policy, app, channel, version, attestation):
    coverage = attestation.get("coverage", "full-six")
    manual = release_mode(policy, app, channel, coverage) == "manual-checksum"
    result = {"version": version}
    if manual:
        result.update(schema="lapkb-manual-download-v1", app=app, channel=channel,
                      coverage=coverage, distribution="manual-checksum")
    if "notes" in attestation:
        result["notes"] = attestation["notes"]
    if "pub_date" in attestation:
        result["pub_date"] = attestation["pub_date"]
    platforms = {}
    for target in COVERAGES[coverage]:
        artifact = next(item for item in attestation["targets"][target]["artifacts"]
                        if ("installer" if manual else "updater") in item["roles"])
        if coverage == "macos-arm64":
            # The existing Mac reader confines archives to its compiled feed's
            # exact origin/directory (Papir uses the retained /papir alias).
            parent = policy.apps[app]["channels"][channel]["macFeedUrl"].rsplit("/", 1)[0]
            url = f"{parent}/{artifact['name']}"
        else:
            url = f"{policy.origin}/downloads/{app}/{channel}/{artifact['name']}"
        platforms[target] = ({"url": url, "sha256": artifact["sha256"],
                              "size": artifact["size"], "kind": artifact["kind"]}
                             if manual else {"url": url, "signature": artifact["updaterSignature"]})
    result["installers" if manual else "platforms"] = platforms
    return canonical_json(result)


def _expected_receipt(policy, app, channel, version, attestation, manifest_bytes):
    """The single deterministic receipt builder, shared by preparation/validation."""
    coverage = attestation.get("coverage", "full-six")
    manual = release_mode(policy, app, channel, coverage) == "manual-checksum"
    receipt = {
        "schema": "release-receipt-v1", "app": app, "channel": channel, "version": version,
        "source": attestation["source"],
        "buildAttestationSha256": hashlib.sha256(canonical_json(attestation)).hexdigest(),
        "manifestSha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "signatureKeyId": policy.apps[app]["channels"][channel]["keyId"], "targets": {},
    }
    if coverage != "full-six":
        receipt.update(coverage=coverage, feed=feed_for_coverage(coverage))
    if manual:
        receipt["distribution"] = "manual-checksum"
    for target, entry in attestation["targets"].items():
        records = entry["artifacts"]
        receipt["targets"][target] = {
            "packageIdentity": entry["packageIdentity"],
            "roles": {"installer": sorted(i["name"] for i in records if "installer" in i["roles"]),
                      "updater": next((i["name"] for i in records if "updater" in i["roles"]), None)},
            "artifacts": [{k: i[k] for k in ("name", "kind", "roles", "size", "sha256", "signatureKeyId")}
                          for i in records],
        }
        if target == "windows-x86_64" and coverage in ("windows-x64", "launcher-desktop"):
            receipt["targets"][target].update(build=entry["build"], windowsPayload=entry["windowsPayload"])
            if not manual:
                receipt["targets"][target]["installerSignature"] = next(
                    i["updaterSignature"] for i in records if "updater" in i["roles"])
        elif coverage in ("launcher-desktop", "macos-arm64"):
            receipt["targets"][target]["build"] = entry["build"]
    return receipt


def validate_release(app: str, channel: str, files: dict[str, Path], policy: Policy,
                     verifier: Path = VERIFIER_PATH, scratch: Path | None = None):
    """Validate the exact complete release inventory and return normalized data.

    ``files`` maps safe leaf names to private staging files. No upload data can
    choose a filesystem destination or a trust key.
    """
    if (app not in APP_IDS or channel not in CHANNELS
            or app not in policy.apps or channel not in policy.apps[app]["channels"]):
        raise ContractError("unsupported or unconfigured application/release channel")
    if type(files) is not dict or not 1 <= len(files) <= MAX_FILES:
        raise ContractError("release file inventory count is invalid")
    for name, path in files.items():
        if type(name) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,191}", name) or name in (".", ".."):
            raise ContractError("release contains an unsafe file name")
        if not isinstance(path, Path):
            raise ContractError("release staging inventory is invalid")

    attestation_files = [name for name in files if _ATTESTATION_NAME.fullmatch(name)]
    receipt_files = [name for name in files if _RECEIPT_NAME.fullmatch(name)]
    feeds = set(files) & {"latest.json", "latest-windows.json"}
    if len(feeds) != 1:
        raise ContractError("release must contain exactly one fixed coverage feed")
    feed = next(iter(feeds))
    if len(attestation_files) != 1 or len(receipt_files) != 1 or feed not in files:
        raise ContractError("release is missing versioned signed metadata or the Tauri manifest")
    # latest.json is also the honest two-target Launcher feed. The explicit
    # attested coverage is checked against fixed receiver policy and signatures;
    # it is never inferred as a fabricated six-platform build.
    preliminary = strict_json(_read_regular(files[attestation_files[0]], MAX_ATTESTATION_BYTES,
        "build attestation"), MAX_ATTESTATION_BYTES, "build attestation")
    input_coverage = preliminary.get("coverage", "full-six") if type(preliminary) is dict else None
    manual = release_mode(policy, app, channel, input_coverage) == "manual-checksum"
    attestation_name = attestation_files[0]
    receipt_name = receipt_files[0]
    metadata_version = attestation_name[len("build-attestation-"):-len(".json")].removesuffix("-macos-arm64")
    if (attestation_name, receipt_name) != metadata_names(metadata_version, input_coverage):
        raise ContractError("attestation/receipt filenames do not match the exact version and coverage")
    attestation_signature_name = attestation_name + ".sig"
    receipt_signature_name = receipt_name + ".sig"
    required_meta = {attestation_name, receipt_name, feed}
    if not manual:
        required_meta.update((attestation_signature_name, receipt_signature_name))
    if not required_meta <= set(files):
        raise ContractError("release is missing a detached signature or the Tauri manifest")
    metadata_limits = [(attestation_name, MAX_ATTESTATION_BYTES),
                       (receipt_name, MAX_RECEIPT_BYTES), (feed, MAX_MANIFEST_BYTES)]
    if not manual:
        metadata_limits.extend(((attestation_signature_name, MAX_SIGNATURE_BYTES),
                                (receipt_signature_name, MAX_SIGNATURE_BYTES)))
    for filename, maximum in metadata_limits:
        _sha256_file(files[filename], maximum=maximum)

    app_policy = policy.apps[app]
    channel_policy = app_policy["channels"][channel]
    public_key = channel_policy["publicKey"]
    key_id = channel_policy["keyId"]
    attestation_bytes = _read_regular(files[attestation_name], MAX_ATTESTATION_BYTES,
                                      "build attestation")
    attestation = strict_json(attestation_bytes, MAX_ATTESTATION_BYTES, "build attestation")
    if type(attestation) is not dict or canonical_json(attestation) != attestation_bytes:
        raise ContractError("build attestation must use canonical JSON bytes")
    if not manual:
        att_sig_data = _read_regular(files[attestation_signature_name], MAX_SIGNATURE_BYTES,
                                    "build attestation signature")
        att_sig = _signature_text(att_sig_data, "build attestation signature")
        verify_minisign(files[attestation_name], att_sig, public_key, verifier, scratch)

    attestation_required = {"schema", "app", "channel", "version", "source", "targets"}
    allowed_attestation = attestation_required | {"notes", "pub_date", "coverage"}
    if manual:
        allowed_attestation.add("distribution")
    if type(attestation) is not dict or not attestation_required <= set(attestation) or set(attestation) - allowed_attestation:
        raise ContractError("build attestation has an unexpected shape")
    if attestation["schema"] != "lapkb-build-attestation-v1" or attestation["app"] != app or attestation["channel"] != channel:
        raise ContractError("build attestation identity does not match the requested release")
    version = attestation["version"]
    version_tuple = _version(version)
    if version != metadata_version:
        raise ContractError("signed metadata filenames do not match the attested version")
    if app == "checkerboard" and version_tuple < policy.checkmate_minimum_version:
        raise ContractError("Checkmate release is below the configured minimum protected version")
    _validate_source(attestation["source"], policy, app, channel, version)
    _validate_optional_release_text(attestation)
    coverage = attestation.get("coverage", "full-six")
    if (type(coverage) is not str or coverage not in COVERAGES
            or coverage not in app_policy["allowedCoverages"]):
        raise ContractError("release coverage was not explicitly approved by this receiver")
    mode = release_mode(policy, app, channel, coverage)
    if app == "launcher" and manual and version_tuple > (0, 1, 10):
        raise ContractError("new Launcher updates require signed bootstrap trust from 0.1.11")
    if app == "launcher" and mode == "signed" and version_tuple < (0, 1, 11):
        raise ContractError("fresh signed Launcher releases must start at bootstrap 0.1.11")
    if manual != (mode == "manual-checksum") or (manual and attestation.get("distribution") != mode):
        raise ContractError("release distribution does not match explicit receiver policy")
    if (coverage in ("windows-x64", "macos-arm64") and (channel != "stable"
            or version_tuple < _version(WINDOWS_MINIMUMS[app]))):
        raise ContractError("Desktop app channel/version is not qualified")
    if coverage in ("windows-x64", "launcher-desktop", "macos-arm64"):
        # Match the existing bounded Launcher reader, without changing any
        # consumed Mac protocol bytes or its historical acceptance policy.
        if (len(attestation["source"]["commit"]) != 40
                or len(attestation.get("notes", "").encode("utf-8")) > 4096):
            raise ContractError("Windows source/notes exceed the Launcher reader contract")
    if feed != feed_for_coverage(coverage):
        raise ContractError("release feed does not match its approved coverage")
    required_targets = COVERAGES[coverage]
    targets = attestation["targets"]
    if type(targets) is not dict or set(targets) != set(required_targets):
        raise ContractError("release attestation does not contain exactly its declared target coverage")

    inventory = set(required_meta)
    total_size = 0
    normalized_targets = {}
    artifact_names = set()
    for target in required_targets:
        windows_proof = target == "windows-x86_64" and coverage in ("windows-x64", "launcher-desktop")
        target_keys = (("packageIdentity", "artifacts", "build", "windowsPayload") if windows_proof
                       else ("packageIdentity", "artifacts", "build") if coverage in ("launcher-desktop", "macos-arm64")
                       else ("packageIdentity", "artifacts"))
        target_entry = _object(targets[target], target_keys, f"{target} metadata")
        identity = _object(target_entry["packageIdentity"],
                           ("bundleIdentifier", "displayName", "executable", "architecture", "version"),
                           f"{target} package identity")
        expected_identity = {
            "bundleIdentifier": BUNDLE_IDS[app],
            "displayName": WINDOWS_PRODUCTS[app] if coverage in ("windows-x64", "launcher-desktop") else DISPLAY_NAMES[app],
            "executable": app_policy["executable"], "architecture": target.split("-")[-1],
            "version": version,
        }
        if identity != expected_identity:
            raise ContractError(f"{target} package identity, architecture, or version is not approved")
        if windows_proof:
            _validate_windows_payload(target_entry, app, version, app_policy["executable"])
        elif coverage in ("launcher-desktop", "macos-arm64"):
            _validate_build(target_entry["build"])
        records = target_entry["artifacts"]
        if type(records) is not list or not records or len(records) > 8:
            raise ContractError(f"{target} package inventory is invalid")
        record_names = []
        for record in records:
            if type(record) is not dict or type(record.get("name")) is not str:
                raise ContractError(f"{target} package record has no valid name")
            record_names.append(record["name"])
        if record_names != sorted(record_names):
            raise ContractError(f"{target} package inventory must be sorted by name")
        profiles = channel_policy["profiles"][target]
        used_profiles = set()
        normal_artifacts = []
        installer_count = 0
        updater_count = 0
        for item in records:
            _object(item, ("name", "kind", "roles", "size", "sha256", "signatureKeyId", "updaterSignature"),
                    f"{target} package record")
            name = item["name"]
            if type(name) is not str or not name.startswith(f"{app}-{version}-{target}-"):
                raise ContractError(f"{target} package name does not match its release identity")
            if name in artifact_names or name in required_meta:
                raise ContractError("duplicate file name in release inventory")
            artifact_names.add(name)
            final_component = name.rsplit(".", 1)
            if len(final_component) != 2:
                raise ContractError(f"{target} package extension is not configured")
            # Multi-part extensions are matched from the configured suffix, not guessed.
            profile = next((entry for entry in profiles
                            if name.endswith("." + entry["extension"])), None)
            if profile is None:
                raise ContractError(f"{target} package format is not configured")
            profile_id = profile["id"]
            if profile_id in used_profiles:
                raise ContractError(f"{target} package profile is duplicated")
            used_profiles.add(profile_id)
            if item["kind"] != profile["kind"] or item["roles"] != profile["roles"]:
                raise ContractError(f"{target} package roles or kind differ from trusted profile")
            if type(item["roles"]) is not list or item["roles"] != sorted(set(item["roles"])):
                raise ContractError(f"{target} package roles are malformed")
            size = item["size"]
            if (type(size) is not int or size < 1 or size > MAX_FILE_BYTES
                    or (coverage in ("windows-x64", "macos-arm64") and size > 256 * 1024 * 1024)
                    or (coverage == "launcher-desktop" and size > 128 * 1024 * 1024)):
                raise ContractError(f"{target} package size is out of range")
            if type(item["sha256"]) is not str or not _HEX.fullmatch(item["sha256"]):
                raise ContractError(f"{target} package digest is invalid")
            if name != f"{app}-{version}-{target}-{item['sha256']}.{profile['extension']}":
                raise ContractError(f"{target} package file name does not bind its final bytes")
            if name not in files:
                raise ContractError("release is missing an attested package file")
            actual_size, actual_digest = _sha256_file(files[name], expected_size=size)
            if actual_digest != item["sha256"]:
                raise ContractError("release package bytes do not match the signed attestation")
            total_size += actual_size
            if total_size > MAX_RELEASE_BYTES:
                raise ContractError("release aggregate size exceeds the configured bound")
            roles = item["roles"]
            updater = "updater" in roles
            if updater:
                updater_count += 1
                if item["signatureKeyId"] != key_id or type(item["updaterSignature"]) is not str:
                    raise ContractError("updater signature key does not match configured trust")
                if coverage in ("windows-x64", "launcher-desktop", "macos-arm64") and len(item["updaterSignature"]) > 16 * 1024:
                    raise ContractError("Windows installer signature exceeds the Launcher reader bound")
                try:
                    signature_bytes = base64.b64decode(item["updaterSignature"], validate=True)
                except (binascii.Error, ValueError):
                    raise ContractError("updater signature is malformed") from None
                if base64.b64encode(signature_bytes).decode("ascii") != item["updaterSignature"]:
                    raise ContractError("updater signature encoding is not canonical")
                signature_text = _signature_text(signature_bytes, "updater signature")
                verify_minisign(files[name], signature_text, public_key, verifier, scratch)
            elif item["signatureKeyId"] is not None or item["updaterSignature"] is not None:
                raise ContractError("installer-only artifact unexpectedly carries updater trust")
            if "installer" in roles:
                installer_count += 1
            normal_artifacts.append({
                "name": name, "kind": item["kind"], "roles": list(roles),
                "size": size, "sha256": item["sha256"],
                "signatureKeyId": key_id if updater else None,
                "updaterSignature": item["updaterSignature"],
            })
            inventory.add(name)
        if any(profile["required"] and profile["id"] not in used_profiles for profile in profiles):
            raise ContractError(f"{target} is missing a required configured package profile")
        if installer_count < 1 or updater_count != (0 if manual else 1):
            raise ContractError(f"{target} installer/updater coverage differs from receiver policy")
        normalized_targets[target] = {
            "packageIdentity": identity, "artifacts": normal_artifacts,
        }
        if windows_proof:
            normalized_targets[target].update(build=target_entry["build"], windowsPayload=target_entry["windowsPayload"])
        elif coverage in ("launcher-desktop", "macos-arm64"):
            normalized_targets[target]["build"] = target_entry["build"]

    if set(files) != inventory:
        raise ContractError("release contains missing or unexpected files")
    expected_latest = _expected_manifest(
        policy, app, channel, version,
        {**attestation, "targets": normalized_targets},
    )
    manifest_bytes = _read_regular(files[feed], MAX_MANIFEST_BYTES, "Tauri manifest")
    manifest = strict_json(manifest_bytes, MAX_MANIFEST_BYTES, "Tauri manifest")
    if coverage in ("launcher-desktop", "macos-arm64") and len(manifest_bytes) > 64 * 1024:
        raise ContractError("Launcher updater feed exceeds its bounded native reader")
    if canonical_json(manifest) != manifest_bytes or manifest_bytes != expected_latest:
        raise ContractError("release feed is not the exact canonical manifest derived from the release")

    receipt = _expected_receipt(policy, app, channel, version,
                                {**attestation, "targets": normalized_targets}, manifest_bytes)
    expected_receipt = canonical_json(receipt)
    if coverage in ("windows-x64", "launcher-desktop", "macos-arm64") and len(expected_receipt) > 1024 * 1024:
        raise ContractError("Windows receipt exceeds the Launcher reader bound")
    actual_receipt = _read_regular(files[receipt_name], MAX_RECEIPT_BYTES,
                                   "release receipt")
    supplied_receipt = strict_json(actual_receipt, MAX_RECEIPT_BYTES, "release receipt")
    if canonical_json(supplied_receipt) != actual_receipt or actual_receipt != expected_receipt:
        raise ContractError("release receipt does not bind the validated release")
    if not manual:
        receipt_sig_data = _read_regular(files[receipt_signature_name], MAX_SIGNATURE_BYTES,
                                        "release receipt signature")
        if coverage in ("windows-x64", "launcher-desktop", "macos-arm64") and len(base64.b64encode(receipt_sig_data)) > 16 * 1024:
            raise ContractError("Windows receipt signature exceeds the Launcher reader bound")
        receipt_sig = _signature_text(receipt_sig_data, "release receipt signature")
        verify_minisign(files[receipt_name], receipt_sig, public_key, verifier, scratch)

    names = sorted(set(files))
    inventory_records = []
    for name in names:
        size, digest = _sha256_file(files[name], maximum=MAX_FILE_BYTES)
        inventory_records.append({"name": name, "size": size, "sha256": digest})
    return {
        "app": app, "channel": channel, "version": version,
        "versionTuple": version_tuple, "source": attestation["source"],
        "attestation": attestation, "receipt": receipt,
        "manifestBytes": manifest_bytes, "receiptBytes": actual_receipt,
        "files": files, "inventory": inventory_records,
        "inventoryDigest": hashlib.sha256(canonical_json(inventory_records)).hexdigest(),
        "legacy": None if coverage == "windows-x64" else policy.legacy_aliases[app][channel],
        "coverage": coverage, "feed": feed, "targets": sorted(required_targets),
        "distribution": mode,
    }
