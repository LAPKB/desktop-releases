"""Validate and send one complete release bundle through the shared publisher.

The bundle contains the complete maintained attestation/receipt, fixed coverage
feed and every configured installer/updater asset. Four Windows apps require
signatures; explicit manual Launcher policy makes no signature claim. The caller cannot
choose the publication root, trust key, URL, legacy alias, or remote flags.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "host"))
import publish_remote  # noqa: E402
import release_contract as contract  # noqa: E402
from release_contract import ContractError  # noqa: E402

REMOTE_COMMAND = "python3 /home/siel/bin/publish_remote.py --receive-v1"
MAX_HTTP_BYTES = contract.MAX_FILE_BYTES


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _required(name):
    value = os.environ.get(name)
    if not value:
        raise ContractError(f"{name} is required")
    return value


def _owned_regular_file(path, *, private=False):
    path = Path(path)
    if (not path.is_absolute() or str(path) != os.path.normpath(str(path))
            or path == Path("/") or ".." in path.parts):
        raise ContractError("publisher SSH credential path must be canonical and absolute")
    parent_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0))
    file_fd = None
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
            info = os.fstat(parent_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or (info.st_mode & 0o022 and not (info.st_mode & stat.S_ISVTX and info.st_uid == 0))):
                raise ContractError("publisher SSH credential path has an unsafe directory")
        file_fd = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        info = os.fstat(file_fd)
        path_info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if ((not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
             or info.st_mode & 0o022 or (private and info.st_mode & 0o077))
                or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
            raise ContractError("publisher SSH credential file ownership or permissions are unsafe")
        return path
    except OSError as error:
        raise ContractError("publisher SSH credential file is unavailable or unsafe") from error
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(parent_fd)


def _valid_host(value, name="LAPKB_PUBLISH_HOST"):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}", value):
        raise ContractError(f"{name} is invalid")
    return value


def _ssh_command():
    key = _owned_regular_file(_required("LAPKB_PUBLISH_KEY"), private=True)
    known_hosts = _owned_regular_file(_required("LAPKB_PUBLISH_KNOWN_HOSTS"))
    user = _required("LAPKB_PUBLISH_USER")
    host = _valid_host(_required("LAPKB_PUBLISH_HOST"))
    host_key_alias = os.environ.get("LAPKB_PUBLISH_HOST_KEY_ALIAS")
    if host_key_alias is not None:
        _valid_host(host_key_alias, "LAPKB_PUBLISH_HOST_KEY_ALIAS")
    port_text = os.environ.get("LAPKB_PUBLISH_PORT", "22")
    if not re.fullmatch(r"[0-9]{1,5}", port_text) or not 1 <= int(port_text) <= 65535:
        raise ContractError("LAPKB_PUBLISH_PORT is invalid")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", user):
        raise ContractError("LAPKB_PUBLISH_USER is invalid")
    command = [
        "/usr/bin/ssh", "-F", "/dev/null", "-i", str(key), "-p", port_text,
        "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
        "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={known_hosts}",
        "-o", "GlobalKnownHostsFile=/dev/null", "-o", "UpdateHostKeys=no",
        "-o", "VerifyHostKeyDNS=no", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
        "-o", "ProxyCommand=none", "-o", "ProxyJump=none", "-o", "ControlMaster=no",
        "-o", "ControlPath=none", "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
    ]
    if host_key_alias is not None:
        command.extend(["-o", f"HostKeyAlias={host_key_alias}"])
    return command + [f"{user}@{host}", REMOTE_COMMAND]


def _secure_bundle_dir(path):
    path = Path(path)
    if not path.is_absolute():
        path = Path.cwd() / path
    if str(path) != os.path.normpath(str(path)) or path == Path("/"):
        raise ContractError("release bundle directory must be a canonical directory path")
    components = path.parts[1:]
    fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        for component in components:
            next_fd = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or (info.st_mode & 0o022 and not (info.st_mode & stat.S_ISVTX and info.st_uid == 0))):
                raise ContractError("release bundle path contains an unsafe directory")
        final = os.fstat(fd)
        if final.st_uid != os.geteuid() or final.st_mode & 0o022:
            raise ContractError("release bundle directory must be owned by the caller and not group/other writable")
        return fd, path
    except BaseException:
        os.close(fd)
        raise


def _copy_bundle_to_private_stage(bundle_fd, bundle_path):
    stage = Path(tempfile.mkdtemp(prefix=".lapkb-release-stage-"))
    os.chmod(stage, 0o700)
    names = os.listdir(bundle_fd)
    if not 1 <= len(names) <= contract.MAX_FILES:
        raise ContractError("release bundle has an invalid file count")
    files = {}
    total = 0
    try:
        for name in sorted(names):
            if type(name) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,191}", name):
                raise ContractError("release bundle contains an unsafe file name")
            info = os.stat(name, dir_fd=bundle_fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_size < 1 or info.st_size > contract.MAX_FILE_BYTES):
                raise ContractError("release bundle contains a link, special file, or oversized asset")
            total += info.st_size
            if total > contract.MAX_RELEASE_BYTES:
                raise ContractError("release bundle aggregate size exceeds its bound")
            source_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=bundle_fd)
            destination = stage / name
            destination_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                     | getattr(os, "O_NOFOLLOW", 0), 0o600)
            digest = hashlib.sha256()
            copied = 0
            try:
                opened = os.fstat(source_fd)
                if ((opened.st_dev, opened.st_ino, opened.st_size) !=
                        (info.st_dev, info.st_ino, info.st_size)):
                    raise ContractError("release bundle changed while opening")
                while True:
                    chunk = os.read(source_fd, 1024 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > info.st_size:
                        raise ContractError("release bundle changed while copying")
                    digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        count = os.write(destination_fd, view)
                        view = view[count:]
                if copied != info.st_size:
                    raise ContractError("release bundle changed while copying")
                os.fchmod(destination_fd, 0o600)
                os.fsync(destination_fd)
            finally:
                os.close(source_fd)
                os.close(destination_fd)
            files[name] = destination
        directory_fd = os.open(stage, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                               | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return stage, files
    except BaseException:
        shutil.rmtree(stage)
        raise


def _opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def _fetch_exact(url, policy, maximum, expected=None):
    expected_url = url
    parsed = urlsplit(url)
    origin = urlsplit(policy.origin)
    if (parsed.scheme != "https" or parsed.netloc != origin.netloc or parsed.username
            or parsed.password or parsed.fragment or parsed.query):
        raise ContractError("served publisher URL is outside the approved HTTPS origin")
    request = urllib.request.Request(url, headers={"User-Agent": "LAPKB-Release/2.0"})
    try:
        response = _opener().open(request, timeout=120)
    except urllib.error.HTTPError as error:
        code = error.code
        error.close()
        if code in (301, 302, 303, 307, 308):
            raise ContractError("publisher verification refused an HTTP redirect") from None
        raise ContractError(f"publisher verification returned HTTP {code}") from None
    except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException):
        raise ContractError("publisher verification could not reach the approved origin") from None
    with response:
        if getattr(response, "status", None) != 200:
            raise ContractError("publisher origin did not return a complete HTTP 200 response")
        if response.geturl() != expected_url:
            raise ContractError("publisher verification response origin changed")
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            if not re.fullmatch(r"[0-9]+", content_length) or int(content_length) > maximum:
                raise ContractError("publisher response length is invalid")
        digest = hashlib.sha256()
        body = bytearray() if expected is None else None
        total = 0
        while True:
            try:
                chunk = response.read(min(1024 * 1024, maximum + 1 - total))
            except (OSError, http.client.HTTPException):
                raise ContractError("publisher response was truncated") from None
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ContractError("publisher response exceeds its size limit")
            digest.update(chunk)
            if body is not None:
                body.extend(chunk)
        if content_length is not None and total != int(content_length):
            raise ContractError("publisher response was truncated")
        if expected is not None and (total, digest.hexdigest()) != (expected["size"], expected["sha256"]):
            raise ContractError("served release asset differs from the validated local bytes")
        return bytes(body) if body is not None else {"size": total, "sha256": digest.hexdigest()}


def _verify_served(policy, release, result):
    contract.validate_publication_result(result, policy, release)
    expected_inventory = release["inventory"]
    feed = contract.feed_for_coverage(release["coverage"])
    prefix = f"{policy.origin}/downloads/{release['app']}/{release['channel']}"
    for item in expected_inventory:
        name = item["name"]
        served = _fetch_exact(f"{prefix}/{name}", policy,
                              contract.MAX_MANIFEST_BYTES if name == feed else MAX_HTTP_BYTES,
                              None if name == feed else item)
        if name == feed and served != release["manifestBytes"]:
            raise ContractError("served fixed coverage feed differs from the exact canonical manifest")
    alias = release["legacy"]
    if alias is not None:
        legacy_manifest = _fetch_exact(f"{policy.origin}/{alias}/latest.json", policy,
                                       contract.MAX_MANIFEST_BYTES)
        if legacy_manifest != release["manifestBytes"]:
            raise ContractError("legacy feed does not serve identical canonical manifest bytes")
        package_names = {
            artifact["name"]: artifact
            for target in release["receipt"]["targets"].values()
            for artifact in target["artifacts"]
        }
        for item in package_names.values():
            _fetch_exact(f"{policy.origin}/{alias}/{item['name']}", policy,
                         MAX_HTTP_BYTES, {"size": item["size"], "sha256": item["sha256"]})


def _run_remote(command, app, channel, files):
    stdout_file = tempfile.TemporaryFile()
    stderr_file = tempfile.TemporaryFile()
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stdout_file,
                                   stderr=stderr_file, close_fds=True)
    except OSError as error:
        stdout_file.close()
        stderr_file.close()
        raise ContractError("could not start the pinned SSH publisher") from error
    try:
        publish_remote.write_payload(process.stdin, app, channel, files)
        process.stdin.close()
        returncode = process.wait(timeout=1800)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        stdout_file.close()
        stderr_file.close()
        raise ContractError("SSH publisher transport timed out") from None
    except BaseException:
        try:
            process.stdin.close()
        except OSError:
            pass
        process.kill()
        process.wait()
        stdout_file.close()
        stderr_file.close()
        raise
    stdout_file.seek(0)
    stdout = stdout_file.read(128 * 1024 + 1)
    stderr_file.seek(0)
    stderr = stderr_file.read(128 * 1024 + 1)
    stdout_file.close()
    stderr_file.close()
    if len(stdout) > 128 * 1024 or len(stderr) > 128 * 1024:
        raise ContractError("SSH publisher returned oversized output")
    if returncode != 0:
        message = stderr.decode("utf-8", "replace").strip()
        if "?" in message and "http" in message.lower():
            message = "publisher rejected release; inspect the protected host log"
        raise ContractError(message[-512:] or f"SSH publisher exited with status {returncode}")
    try:
        result = contract.strict_json(stdout.strip(), 128 * 1024, "publisher response")
    except ContractError as error:
        raise ContractError("SSH publisher response was not valid JSON") from error
    if (type(result) is not dict or result.get("app") != app or result.get("channel") != channel
            or result.get("status") not in ("published", "identical-retry")):
        raise ContractError("SSH publisher response identity or status is invalid")
    return result


def publish(app, channel, bundle_dir, verifier=contract.VERIFIER_PATH):
    config_path = Path(os.environ.get("LAPKB_PUBLISHER_CONFIG", contract.CONFIG_PATH))
    policy = contract.load_policy(config_path)
    bundle_fd, _ = _secure_bundle_dir(bundle_dir)
    stage = None
    try:
        stage, files = _copy_bundle_to_private_stage(bundle_fd, Path(bundle_dir))
    finally:
        os.close(bundle_fd)
    try:
        release = contract.validate_release(app, channel, files, policy, verifier=verifier, scratch=stage)
        command = _ssh_command()
        result = _run_remote(command, app, channel, files)
        contract.validate_publication_result(result, policy, release)
        _verify_served(policy, release, result)
        response = {
            "app": app, "channel": channel, "version": release["version"],
            "coverage": release["coverage"], "feed": release["feed"],
            "targets": release["targets"], "distribution": release["distribution"],
            "status": result["status"], "inventoryDigest": release["inventoryDigest"],
            "files": len(release["inventory"]),
        }
        print(json.dumps(response, sort_keys=True, separators=(",", ":")))
        return response
    finally:
        shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", required=True, choices=contract.APP_IDS)
    parser.add_argument("--channel", required=True, choices=contract.CHANNELS)
    parser.add_argument("--bundle-dir", required=True)
    args = parser.parse_args()
    try:
        verifier = contract.VERIFIER_PATH
        configured_verifier = os.environ.get("LAPKB_PUBLISHER_VERIFIER")
        if configured_verifier is not None:
            verifier = _owned_regular_file(configured_verifier, private=True)
        publish(args.app, args.channel, args.bundle_dir, verifier=verifier)
    except (ContractError, OSError) as error:
        print(f"publisher failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
