#!/usr/bin/env python3
"""Pull complete configured GitHub release bundles through the single core.

Four Windows apps remain signed; manual Launcher is explicitly checksum-only.

Trust, public root, approved source branches, package profiles and legacy
aliases live in /etc/lapkb/publisher.json. This private pickup configuration
only enables polling of that same repository. Processed state is recorded only
after the canonical publisher succeeds.
"""
from __future__ import annotations

import fcntl
import hashlib
import http.client
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import publish_remote  # noqa: E402
import release_contract as contract  # noqa: E402
from release_contract import ContractError  # noqa: E402
from publish_remote import PublicationError  # noqa: E402

HOME = Path.home()
CONFIG = HOME / ".config" / "lapkb" / "pickup.json"
TOKEN = HOME / ".config" / "lapkb" / "pickup-token"
STATE = HOME / ".local" / "state" / "lapkb" / "pickup-state.json"
LOCK = HOME / ".local" / "state" / "lapkb" / "pickup-state.lock"
API_ORIGIN = "https://api.github.com"
API_PAGE_BYTES = 4 * 1024 * 1024
MAX_PAGES = 1000
MAX_TOKEN_BYTES = 8192
TAG = re.compile(
    r"^publish-(launcher|papir|bestdose|bdautodial|checkerboard)-(stable|beta)-"
    r"((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$"
)
ASSET_CDNS = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _open_dir_chain(path: Path, *, create=False, private_final=False):
    if not path.is_absolute():
        raise ContractError("pickup state path must be absolute")
    fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                 | getattr(os, "O_NOFOLLOW", 0))
    try:
        for component in path.parts[1:]:
            if component in ("", ".", ".."):
                raise ContractError("pickup state path is not canonical")
            created = False
            try:
                next_fd = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                  | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise ContractError("pickup state directory is missing") from None
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                else:
                    created = True
                    os.fsync(fd)
                next_fd = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                  | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            if created and create:
                os.fchmod(next_fd, 0o700)
                os.fsync(next_fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or (info.st_mode & 0o022 and not (info.st_mode & stat.S_ISVTX and info.st_uid == 0))
                    or (private_final and component == path.parts[-1] and info.st_mode & 0o077)):
                raise ContractError("pickup state path has unsafe ownership or permissions")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _read_private_file(path: Path, maximum: int, *, optional=False):
    parent_fd = _open_dir_chain(path.parent, private_final=True)
    try:
        try:
            fd = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        except FileNotFoundError:
            if optional:
                return None
            raise ContractError(f"required pickup file is missing: {path.name}") from None
        except OSError as error:
            raise ContractError(f"pickup file cannot be opened safely: {path.name}") from error
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > maximum):
                raise ContractError(f"pickup file ownership, permissions, or size is unsafe: {path.name}")
            data = bytearray()
            while len(data) <= maximum:
                chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) != info.st_size or len(data) > maximum:
                raise ContractError(f"pickup file changed while reading: {path.name}")
            return bytes(data)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _load_pickup_config(policy):
    data = _read_private_file(CONFIG, 64 * 1024)
    value = contract.strict_json(data, 64 * 1024, "pickup configuration")
    if (type(value) is not dict or set(value) != {"schema", "enabled", "repository"}
            or value["schema"] != "lapkb-pickup-v1" or type(value["enabled"]) is not bool
            or value["enabled"] is not True or value["repository"] != policy.pickup_repository):
        raise ContractError("private pickup configuration is missing, disabled, or differs from approved source trust")
    if contract.canonical_json(value) != data:
        raise ContractError("pickup configuration must use canonical JSON")
    return value


def _token():
    data = _read_private_file(TOKEN, MAX_TOKEN_BYTES, optional=True)
    if data is None:
        return ""
    try:
        value = data.decode("ascii", "strict").strip()
    except UnicodeError as error:
        raise ContractError("pickup token file is not valid ASCII") from error
    if value and (len(value) > MAX_TOKEN_BYTES or not re.fullmatch(r"[A-Za-z0-9_]+", value)):
        raise ContractError("pickup token file has invalid contents")
    return value


def _http_opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def _read_http_body(response, maximum, expected_size=None):
    length = response.headers.get("Content-Length")
    if length is not None:
        if not re.fullmatch(r"[0-9]+", length) or int(length) > maximum:
            raise ContractError("GitHub response length is invalid")
    body = bytearray()
    while True:
        try:
            chunk = response.read(min(1024 * 1024, maximum + 1 - len(body)))
        except (OSError, http.client.HTTPException):
            raise ContractError("GitHub response was truncated") from None
        if not chunk:
            break
        body.extend(chunk)
        if len(body) > maximum:
            raise ContractError("GitHub response exceeds its size limit")
    if length is not None and len(body) != int(length):
        raise ContractError("GitHub response was truncated")
    if expected_size is not None and len(body) != expected_size:
        raise ContractError("GitHub asset size differs from its release metadata")
    return bytes(body)


def api_get(url, token, maximum=API_PAGE_BYTES):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "api.github.com" or parsed.username or parsed.password or parsed.fragment:
        raise ContractError("pickup attempted a request outside the fixed GitHub API")
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "LAPKB-Pickup/2.0"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, headers=headers)
    try:
        response = _http_opener().open(request, timeout=60)
    except urllib.error.HTTPError as error:
        code = error.code
        error.close()
        raise ContractError(f"GitHub API returned HTTP {code}") from None
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
        raise ContractError("pickup could not reach the GitHub API") from None
    with response:
        if response.status != 200 or response.geturl() != url:
            raise ContractError("GitHub API returned an unexpected status or origin")
        return _read_http_body(response, maximum)


def list_releases(repository, token):
    result = []
    encoded_repository = urllib.parse.quote(repository, safe="/")
    for page in range(1, MAX_PAGES + 1):
        url = f"{API_ORIGIN}/repos/{encoded_repository}/releases?per_page=100&page={page}"
        raw = api_get(url, token)
        value = contract.strict_json(raw, API_PAGE_BYTES, "GitHub releases response")
        if type(value) is not list or len(value) > 100:
            raise ContractError("GitHub releases response has an unexpected shape")
        result.extend(value)
        if len(value) < 100:
            return result
    raise ContractError("GitHub release pagination exceeded the explicit page bound")


def _release_tag(release):
    if type(release) is not dict or type(release.get("tag_name")) is not str:
        return None
    match = TAG.fullmatch(release["tag_name"])
    if match is None:
        return None
    app, channel, version = match.groups()
    contract._version(version)
    return app, channel, version


def _asset_identity(release, repository):
    assets = release.get("assets")
    if type(assets) is not list or not 1 <= len(assets) <= contract.MAX_FILES:
        raise ContractError("staged GitHub release asset inventory count is invalid")
    identities = []
    names, ids = set(), set()
    total = 0
    for asset in assets:
        required = {"id", "name", "size", "url", "digest"}
        if type(asset) is not dict or not required <= set(asset):
            raise ContractError("GitHub release asset metadata is incomplete")
        asset_id, name, size = asset["id"], asset["name"], asset["size"]
        if type(asset_id) is not int or asset_id <= 0 or type(size) is not int or not 1 <= size <= contract.MAX_FILE_BYTES:
            raise ContractError("GitHub release asset ID or size is invalid")
        if type(name) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,191}", name):
            raise ContractError("GitHub release asset name is unsafe")
        if name in names or asset_id in ids:
            raise ContractError("GitHub release contains duplicate asset names or IDs")
        names.add(name)
        ids.add(asset_id)
        total += size
        if total > contract.MAX_RELEASE_BYTES:
            raise ContractError("GitHub release aggregate asset size exceeds its bound")
        api_url = f"{API_ORIGIN}/repos/{repository}/releases/assets/{asset_id}"
        if asset["url"] != api_url:
            raise ContractError("GitHub release asset URL is not the exact approved API path")
        digest = asset["digest"]
        if digest is not None:
            if type(digest) is not str or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
                raise ContractError("GitHub release asset digest is malformed")
        identities.append({"id": asset_id, "name": name, "size": size, "digest": digest})
    identities.sort(key=lambda item: item["name"])
    return identities


def _asset_scope(policy, app, channel, assets):
    feeds = {item["name"] for item in assets} & {"latest.json", "latest-windows.json"}
    if len(feeds) != 1:
        raise ContractError("staged release must identify exactly one fixed coverage feed")
    feed = next(iter(feeds))
    coverage = "windows-x64" if feed == "latest-windows.json" else "full-six"
    return {"coverage": coverage, "feed": contract.feed_for_coverage(coverage),
            "targets": sorted(contract.COVERAGES[coverage]),
            "distribution": contract.release_mode(policy, app, channel, coverage)}


def _release_identity(release, app, channel, version, assets, policy):
    release_id = release.get("id")
    prerelease = release.get("prerelease")
    if type(release_id) is not int or release_id <= 0 or type(prerelease) is not bool:
        raise ContractError("GitHub release identity is malformed")
    if release.get("draft") is not False or prerelease != (channel == "beta"):
        raise ContractError("GitHub release draft/prerelease state does not match its configured channel")
    identity = {"releaseId": release_id, "app": app, "channel": channel,
                "version": version, "assets": assets, **_asset_scope(policy, app, channel, assets)}
    return {**identity, "assetsIdentitySha256": hashlib.sha256(
        contract.canonical_json(identity)
    ).hexdigest()}


def _validate_asset_redirect(location):
    if type(location) is not str or len(location) > 16 * 1024:
        raise ContractError("GitHub asset redirect is invalid")
    parsed = urllib.parse.urlsplit(location)
    try:
        port = parsed.port
    except ValueError as error:
        raise ContractError("GitHub asset redirect has an invalid port") from error
    if (parsed.scheme != "https" or parsed.hostname not in ASSET_CDNS or parsed.username
            or parsed.password or parsed.fragment or port not in (None, 443)
            or not parsed.path.startswith("/github-production-release-asset/")):
        raise ContractError("GitHub asset redirect is outside the approved HTTPS CDN")
    if not parsed.query or len(parsed.query) > 12 * 1024:
        raise ContractError("GitHub asset redirect query is invalid")
    return location


def download_asset(asset, token, destination: Path):
    api_url = asset["url"]
    parsed_api = urllib.parse.urlsplit(api_url)
    if (parsed_api.scheme != "https" or parsed_api.hostname != "api.github.com"
            or parsed_api.username or parsed_api.password or parsed_api.query or parsed_api.fragment):
        raise ContractError("GitHub asset URL is outside the fixed API")
    expected_response_url = api_url
    request = urllib.request.Request(
        api_url,
        headers={"Accept": "application/octet-stream", "User-Agent": "LAPKB-Pickup/2.0",
                 **({"Authorization": "Bearer " + token} if token else {})},
    )
    try:
        response = _http_opener().open(request, timeout=600)
    except urllib.error.HTTPError as error:
        code = error.code
        location = error.headers.get("Location") if code in (301, 302, 303, 307, 308) else None
        error.close()
        if location is None:
            raise ContractError(f"GitHub asset API returned HTTP {code}") from None
        cdn_url = _validate_asset_redirect(location)
        expected_response_url = cdn_url
        # No Authorization header is forwarded to the CDN or any other origin.
        request = urllib.request.Request(
            cdn_url, headers={"Accept": "application/octet-stream", "User-Agent": "LAPKB-Pickup/2.0"}
        )
        try:
            response = _http_opener().open(request, timeout=600)
        except urllib.error.HTTPError as redirected:
            code = redirected.code
            redirected.close()
            raise ContractError(f"GitHub asset CDN returned HTTP {code}") from None
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
            raise ContractError("pickup could not reach the approved GitHub asset CDN") from None
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
        raise ContractError("pickup could not reach the GitHub asset API") from None

    digest = hashlib.sha256()
    total = 0
    try:
        with response:
            if response.status != 200 or response.geturl() != expected_response_url:
                raise ContractError("GitHub asset response status or origin was unexpected")
            length = response.headers.get("Content-Length")
            if length is not None and (not re.fullmatch(r"[0-9]+", length)
                                       or int(length) != asset["size"]):
                raise ContractError("GitHub asset content length differs from its release metadata")
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                while True:
                    try:
                        chunk = response.read(min(1024 * 1024, asset["size"] + 1 - total))
                    except (OSError, http.client.HTTPException):
                        raise ContractError("GitHub asset download was truncated") from None
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > asset["size"]:
                        raise ContractError("GitHub asset exceeds its declared size")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        count = os.write(fd, view)
                        view = view[count:]
                if total != asset["size"]:
                    raise ContractError("GitHub asset download was truncated")
                os.fchmod(fd, 0o600)
                declared = asset["digest"]
                if declared is not None and digest.hexdigest() != declared.removeprefix("sha256:"):
                    raise ContractError("GitHub asset digest differs from its release metadata")
                os.fsync(fd)
            finally:
                os.close(fd)
    except BaseException:
        try:
            destination.unlink()
        except FileNotFoundError:
            pass
        raise
    return {"size": total, "sha256": digest.hexdigest()}


def _load_state(state_dir_fd, policy):
    try:
        fd = os.open(STATE.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=state_dir_fd)
    except FileNotFoundError:
        return {"schema": "lapkb-pickup-state-v1", "published": {}}
    except OSError as error:
        raise ContractError("pickup processed state cannot be opened safely") from error
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 8 * 1024 * 1024):
            raise ContractError("pickup processed state ownership or permissions are unsafe")
        data = bytearray()
        while len(data) <= 8 * 1024 * 1024:
            chunk = os.read(fd, min(65536, 8 * 1024 * 1024 + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        os.close(fd)
    if len(data) != info.st_size:
        raise ContractError("pickup processed state changed while reading")
    value = contract.strict_json(bytes(data), 8 * 1024 * 1024, "pickup processed state")
    if (type(value) is not dict or set(value) != {"schema", "published"}
            or value["schema"] != "lapkb-pickup-state-v1" or type(value["published"]) is not dict
            or contract.canonical_json(value) != bytes(data)):
        raise ContractError("pickup processed state has an unexpected shape or encoding")
    for tag, entry in value["published"].items():
        tag_match = TAG.fullmatch(tag)
        if tag_match is None or type(entry) is not dict:
            raise ContractError("pickup processed state contains an invalid release identity")
        expected = {"releaseId", "app", "channel", "version", "assets", "assetsIdentitySha256", "inventoryDigest",
                    "coverage", "feed", "targets", "distribution"}
        if set(entry) != expected or type(entry["assets"]) is not list:
            raise ContractError("pickup processed release record has an unexpected shape")
        app, channel, version = tag_match.group(1), tag_match.group(2), ".".join(tag_match.groups()[2:])
        if (type(entry["releaseId"]) is not int or entry["releaseId"] <= 0
                or entry["app"] != app or entry["channel"] != channel or entry["version"] != version
                or len(entry["assets"]) > contract.MAX_FILES):
            raise ContractError("pickup processed release identity is inconsistent")
        names, ids = set(), set()
        for asset in entry["assets"]:
            if type(asset) is not dict or set(asset) != {"id", "name", "size", "digest"}:
                raise ContractError("pickup processed asset identity is malformed")
            if (type(asset["id"]) is not int or asset["id"] <= 0
                    or type(asset["name"]) is not str
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,191}", asset["name"])
                    or type(asset["size"]) is not int or not 1 <= asset["size"] <= contract.MAX_FILE_BYTES
                    or asset["digest"] is not None and (type(asset["digest"]) is not str
                        or not re.fullmatch(r"sha256:[0-9a-f]{64}", asset["digest"]))):
                raise ContractError("pickup processed asset identity is invalid")
            if asset["name"] in names or asset["id"] in ids:
                raise ContractError("pickup processed asset identity is duplicated")
            names.add(asset["name"])
            ids.add(asset["id"])
        scope = _asset_scope(policy, app, channel, entry["assets"])
        if any(entry[key] != scope[key] for key in scope):
            raise ContractError("pickup processed coverage/feed/target/distribution identity is inconsistent")
        identity = {key: entry[key] for key in ("releaseId", "app", "channel", "version", "assets",
                                              "coverage", "feed", "targets", "distribution")}
        if (entry["assets"] != sorted(entry["assets"], key=lambda item: item["name"])
                or entry["assetsIdentitySha256"] != hashlib.sha256(contract.canonical_json(identity)).hexdigest()):
            raise ContractError("pickup processed asset identity digest is inconsistent")
        for key in ("assetsIdentitySha256", "inventoryDigest"):
            if type(entry[key]) is not str or not re.fullmatch(r"[0-9a-f]{64}", entry[key]):
                raise ContractError("pickup processed release digest is invalid")
    return value


def _write_state(state_dir_fd, state):
    data = contract.canonical_json(state)
    if len(data) > 8 * 1024 * 1024:
        raise ContractError("pickup processed state exceeds its size limit")
    temp = f".pickup-state-{os.getpid()}-{os.urandom(12).hex()}"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                 0o600, dir_fd=state_dir_fd)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            view = view[count:]
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(temp, dir_fd=state_dir_fd)
        except FileNotFoundError:
            pass
        raise
    os.close(fd)
    try:
        try:
            info = os.stat(STATE.name, dir_fd=state_dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            info = None
        if info is not None and (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                                 or info.st_nlink != 1 or info.st_mode & 0o077):
            raise ContractError("pickup state target has unsafe ownership or permissions")
        os.replace(temp, STATE.name, src_dir_fd=state_dir_fd, dst_dir_fd=state_dir_fd)
        os.fsync(state_dir_fd)
    except BaseException:
        try:
            os.unlink(temp, dir_fd=state_dir_fd)
        except FileNotFoundError:
            pass
        raise


def _cleanup_state_temps(state_dir_fd):
    changed = False
    pattern = re.compile(r"^\.pickup-state-([0-9]+)-[0-9a-f]{24}$")
    for name in os.listdir(state_dir_fd):
        match = pattern.fullmatch(name)
        if match is None:
            continue
        try:
            os.kill(int(match.group(1)), 0)
            continue
        except ProcessLookupError:
            pass
        except PermissionError:
            continue
        info = os.stat(name, dir_fd=state_dir_fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077):
            raise ContractError("pickup temporary state file is unsafe")
        os.unlink(name, dir_fd=state_dir_fd)
        changed = True
    if changed:
        os.fsync(state_dir_fd)


def _state_lock(state_dir_fd):
    fd = -1
    for attempt in range(20):
        try:
            fd = os.open(LOCK.name, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                         0o600, dir_fd=state_dir_fd)
            break
        except FileNotFoundError:
            # See the publisher lock: concurrent O_CREAT|O_NOFOLLOW on macOS
            # may briefly report ENOENT for the process that lost creation.
            if attempt == 19:
                raise ContractError("pickup state lock cannot be opened safely") from None
            time.sleep(0.005)
        except OSError as error:
            raise ContractError("pickup state lock cannot be opened safely") from error
    if fd < 0:
        raise ContractError("pickup state lock cannot be opened safely")
    try:
        info = os.fstat(fd)
        path_info = os.stat(LOCK.name, dir_fd=state_dir_fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or info.st_mode & 0o077
                or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
            raise ContractError("pickup state lock ownership or permissions are unsafe")
        os.fchmod(fd, 0o600)
        os.fsync(fd)
        os.fsync(state_dir_fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except BaseException:
        os.close(fd)
        raise


def main():
    policy = contract.load_policy()
    _load_pickup_config(policy)
    token = _token()
    state_dir_fd = _open_dir_chain(STATE.parent, create=True, private_final=True)
    lock_fd = _state_lock(state_dir_fd)
    try:
        _cleanup_state_temps(state_dir_fd)
        publish_remote.recover_publications(policy)
        state = _load_state(state_dir_fd, policy)
        releases = list_releases(policy.pickup_repository, token)
        found = {}
        for release in releases:
            identity = _release_tag(release)
            if identity is None:
                continue
            app, channel, version = identity
            tag = release["tag_name"]
            if tag in found:
                raise ContractError("GitHub release pagination returned a duplicate tag")
            assets = _asset_identity(release, policy.pickup_repository)
            remote_identity = _release_identity(release, app, channel, version, assets, policy)
            prior = state["published"].get(tag)
            if prior is not None:
                if any(prior.get(key) != remote_identity[key] for key in
                       ("releaseId", "app", "channel", "version", "assets", "assetsIdentitySha256",
                        "coverage", "feed", "targets", "distribution")):
                    raise ContractError("processed GitHub tag changed its release or asset identity")
            found[tag] = (release, identity, assets, remote_identity)
        missing = set(state["published"]) - set(found)
        if missing:
            raise ContractError("a previously processed GitHub release tag disappeared")

        pending = [item for tag, item in found.items() if tag not in state["published"]]
        pending.sort(key=lambda item: (item[1][0], item[1][1], contract._version(item[1][2])))
        if not pending:
            print(json.dumps({"status": "idle", "repository": policy.pickup_repository,
                              "processed": len(state["published"])}, sort_keys=True))
            return 0

        for release, (app, channel, version), assets, remote_identity in pending:
            staging_name, staging_path = publish_remote.create_staging(policy)
            files = {}
            downloaded_inventory = []
            try:
                for asset in release["assets"]:
                    name = asset["name"]
                    target = staging_path / name
                    actual = download_asset(asset, token, target)
                    downloaded_inventory.append({"name": name, **actual})
                    files[name] = target
                result = publish_remote.publish_files(
                    policy, app, channel, files, staging_name,
                )
                contract.validate_publication_result(result, policy)
                expected_keys = ("app", "channel", "version", "coverage", "feed", "targets", "distribution")
                if (any(result[key] != remote_identity[key] for key in expected_keys)
                        or result["inventory"] != sorted(downloaded_inventory, key=lambda item: item["name"])):
                    raise ContractError("publisher result differs from this exact downloaded pickup release")
                state["published"][release["tag_name"]] = {
                    **remote_identity, "inventoryDigest": result["inventoryDigest"],
                }
                _write_state(state_dir_fd, state)
                print(json.dumps({"status": result["status"], "tag": release["tag_name"],
                                  "app": app, "channel": channel, "version": version,
                                  **{key: result[key] for key in ("coverage", "feed", "targets", "distribution")},
                                  "inventoryDigest": state["published"][release["tag_name"]]["inventoryDigest"]},
                                 sort_keys=True, separators=(",", ":")))
            finally:
                publish_remote.remove_staging(policy, staging_name)
        return 0
    finally:
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
        os.close(state_dir_fd)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ContractError, PublicationError, OSError) as error:
        print(json.dumps({"status": "error", "message": str(error)},
                         sort_keys=True, separators=(",", ":")), file=sys.stderr)
        sys.exit(1)
