#!/usr/bin/env python3
"""Private CI candidate storage; HTTP is the upload transport.

Each completed upload lives at <root>/<app>/<source-sha>/<target>/<archive-sha>/.
Uploads never replace other targets or previously retained bytes. Chunk retries
and finalization are idempotent. The CLI supports administrative list/remove.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
import posixpath
import shutil
import stat
import sys
import tarfile
import tempfile
import time
from typing import NoReturn

ROOT = "/home/siel/lapkb-ci-candidates"
APPLICATIONS = ("papir", "launcher", "bdautodial", "bestdose", "checkmate")
TARGETS = (
    "aarch64-apple-darwin", "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu",
    "aarch64-pc-windows-msvc", "x86_64-pc-windows-msvc",
)
MAX_FILES = 5000
MAX_FILE_BYTES = 2 * 1024**3
MAX_TOTAL_BYTES = 4 * 1024**3
MAX_CHUNK_BYTES = 32 * 1024**2
MAX_CHUNKS = MAX_TOTAL_BYTES // MAX_CHUNK_BYTES
RECEIPT = ".candidate-receipt.json"


class CandidateError(Exception):
    """A rejected request or a filesystem failure, with an HTTP status."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


def fail(message: str, status: int = 400) -> NoReturn:
    raise CandidateError(message, status)


def valid_hex(value: str, length: int) -> bool:
    return len(value) == length and all(c in "0123456789abcdef" for c in value)


def private_directory(path: str, create: bool = False) -> str:
    if create:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
    try:
        info = os.lstat(path)
    except OSError as error:
        raise CandidateError("candidate directory cannot be inspected", 500) from error
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        fail("candidate directory is not private and receiver-owned", 500)
    return path


def directory_names(path: str) -> list:
    try:
        return sorted(os.listdir(path))
    except OSError as error:
        raise CandidateError("candidate directory cannot be listed", 500) from error


def remove_tree(path: str) -> None:
    try:
        shutil.rmtree(path)
    except OSError as error:
        raise CandidateError("candidate directory cannot be removed", 500) from error


def modified_at(path: str) -> float:
    try:
        return os.lstat(path).st_mtime
    except OSError as error:
        raise CandidateError("upload directory cannot be inspected", 500) from error


def unlink_temporary(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise CandidateError("temporary upload file cannot be removed", 500) from error


def validate(app: str, sha: str, target: str, archive_sha: str) -> None:
    if app not in APPLICATIONS:
        fail("unsupported application")
    if not valid_hex(sha, 40):
        fail("source SHA must be 40 lowercase hexadecimal characters")
    if target not in TARGETS:
        fail("unsupported build target")
    if not valid_hex(archive_sha, 64):
        fail("archive SHA256 must be 64 lowercase hexadecimal characters")


@contextmanager
def application_lock(app: str):
    if app not in APPLICATIONS:
        fail("unsupported application")
    private_directory(ROOT)
    locks = private_directory(os.path.join(ROOT, ".locks"), create=True)
    descriptor = os.open(os.path.join(locks, app), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            fail("candidate lock is not private and receiver-owned", 500)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


def target_directory(app: str, sha: str, target: str, create: bool = False) -> str:
    path = ROOT
    for component in (app, sha, target):
        path = private_directory(os.path.join(path, component), create=create)
    return path


def pending_directory(parent: str, archive_sha: str) -> str:
    # Interrupted transfers are temporary, not retained candidates. Remove only
    # receiver-owned staging directories untouched for more than one day.
    now = time.time()
    for name in directory_names(parent):
        if not name.startswith(".upload-") or not valid_hex(name[8:], 64):
            continue
        path = os.path.join(parent, name)
        private_directory(path)
        if now - modified_at(path) > 86400:
            remove_tree(path)
    return private_directory(os.path.join(parent, ".upload-" + archive_sha), create=True)


def load_receipt(directory: str) -> dict:
    try:
        with open(os.path.join(directory, RECEIPT), encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as error:
        raise CandidateError("stored candidate receipt cannot be read", 500) from error


def copy_bytes(stream, destination: str, expected: int) -> str:
    digest = hashlib.sha256()
    remaining = expected
    descriptor = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        while remaining:
            chunk = stream.read(min(remaining, 1024 * 1024))
            if not chunk:
                fail("truncated upload")
            output.write(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def write_chunk(app: str, sha: str, target: str, archive_sha: str,
                index: int, chunk_sha: str, stream, size: int) -> None:
    validate(app, sha, target, archive_sha)
    if not 0 <= index < MAX_CHUNKS or not 0 < size <= MAX_CHUNK_BYTES:
        fail("chunk is out of bounds")
    if not valid_hex(chunk_sha, 64):
        fail("invalid chunk SHA256")
    with application_lock(app):
        parent = target_directory(app, sha, target, create=True)
        pending = pending_directory(parent, archive_sha)
        destination = os.path.join(pending, f"{index:04d}")
        descriptor, temporary = tempfile.mkstemp(prefix=".chunk-", dir=pending)
        os.close(descriptor)
        unlink_temporary(temporary)
        try:
            if copy_bytes(stream, temporary, size) != chunk_sha:
                fail("chunk SHA256 mismatch")
            if os.path.lexists(destination):
                info = os.lstat(destination)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    fail("stored chunk is not a regular file", 500)
                with open(destination, "rb") as handle:
                    previous = hashlib.file_digest(handle, "sha256").hexdigest()
                if previous != chunk_sha:
                    fail("chunk retry differs from the received bytes", 409)
            else:
                os.rename(temporary, destination)
            os.utime(pending, None)
        finally:
            unlink_temporary(temporary)


def safe_member(member: tarfile.TarInfo, seen: set) -> str:
    name = member.name
    if (not name or name.startswith("/") or "\\" in name
            or ".." in name.split("/") or len(name) > 1024
            or len(name.split("/")) > 64 or any(ord(c) < 32 for c in name)):
        fail("unsafe archive path")
    if not (member.isfile() or member.isdir()):
        fail("archive contains a link or special file")
    normalized = posixpath.normpath(name)
    if normalized == ".":
        if not member.isdir():
            fail("archive root is not a directory")
        return normalized
    if normalized == RECEIPT or normalized in seen:
        fail("reserved or duplicate archive path")
    if len(seen) >= MAX_FILES or not 0 <= member.size <= MAX_FILE_BYTES:
        fail("archive exceeds its file-count or per-file size bound")
    seen.add(normalized)
    return normalized


def extract_archive(path: str, incoming: str) -> tuple:
    seen = set()
    inventory = []
    total = 0
    with tarfile.open(path, mode="r|gz") as archive:
        for member in archive:
            name = safe_member(member, seen)
            if name == ".":
                continue
            destination = os.path.join(incoming, name)
            current = incoming
            for component in name.split("/")[:-1]:
                current = private_directory(os.path.join(current, component), create=True)
            if member.isdir():
                private_directory(destination, create=True)
                continue
            total += member.size
            if total > MAX_TOTAL_BYTES:
                fail("archive exceeds the expanded size bound")
            source = archive.extractfile(member)
            if source is None:
                fail("archive member has no data")
            with source:
                digest = copy_bytes(source, destination, member.size)
            os.chmod(destination, 0o700 if member.mode & 0o111 else 0o600)
            inventory.append({"path": name, "bytes": member.size, "sha256": digest})
    if not inventory:
        fail("candidate archive contains no files")
    return total, inventory


def finish(app: str, sha: str, target: str, archive_sha: str,
           count: int, expected_bytes: int, run: str, attempt: str) -> dict:
    validate(app, sha, target, archive_sha)
    if not 1 <= count <= MAX_CHUNKS or not 0 < expected_bytes <= MAX_TOTAL_BYTES:
        fail("archive is out of bounds")
    if not run.isdigit() or len(run) > 20 or not attempt.isdigit() or len(attempt) > 6:
        fail("invalid workflow run or attempt")
    with application_lock(app):
        parent = target_directory(app, sha, target)
        destination = os.path.join(parent, archive_sha)
        pending = os.path.join(parent, ".upload-" + archive_sha)
        if os.path.lexists(destination):
            private_directory(destination)
            receipt = load_receipt(destination)
            if receipt["archiveBytes"] != expected_bytes:
                fail("finalization retry differs from retained candidate", 409)
            if os.path.lexists(pending):
                private_directory(pending)
                remove_tree(pending)
            return receipt
        private_directory(pending)
        if directory_names(pending) != [f"{index:04d}" for index in range(count)]:
            fail("upload is missing chunks or contains unexpected chunks")
        incoming = tempfile.mkdtemp(prefix=".incoming-", dir=parent)
        packed = os.path.join(incoming, ".upload.tar.gz")
        try:
            digest = hashlib.sha256()
            received = 0
            with open(packed, "xb") as output:
                os.chmod(packed, 0o600)
                for index in range(count):
                    path = os.path.join(pending, f"{index:04d}")
                    info = os.lstat(path)
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                            or not 0 < info.st_size <= MAX_CHUNK_BYTES):
                        fail("invalid stored chunk")
                    with open(path, "rb") as source:
                        while data := source.read(1024 * 1024):
                            received += len(data)
                            if received > expected_bytes:
                                fail("archive size mismatch")
                            digest.update(data)
                            output.write(data)
            if received != expected_bytes or digest.hexdigest() != archive_sha:
                fail("archive size or SHA256 mismatch")
            # Extraction is confined to another directory so archive members
            # can never collide with or overwrite the compressed input.
            extracted = os.path.join(incoming, "files")
            private_directory(extracted, create=True)
            total, inventory = extract_archive(packed, extracted)
            receipt = {
                "app": app, "sourceSha": sha, "target": target,
                "archiveSha256": archive_sha, "archiveBytes": received,
                "bytes": total, "files": len(inventory), "inventory": inventory,
                "workflowRun": run, "workflowAttempt": attempt,
                "storedAt": datetime.now(timezone.utc).isoformat(),
            }
            with open(os.path.join(extracted, RECEIPT), "x", encoding="utf-8") as output:
                os.chmod(output.name, 0o600)
                json.dump(receipt, output, sort_keys=True)
                output.write("\n")
            os.rename(extracted, destination)
            remove_tree(pending)
            return receipt
        except (tarfile.TarError, EOFError) as error:
            raise CandidateError("invalid compressed tar archive") from error
        finally:
            remove_tree(incoming)


def abort(app: str, sha: str, target: str, archive_sha: str) -> None:
    validate(app, sha, target, archive_sha)
    with application_lock(app):
        parent = target_directory(app, sha, target)
        pending = os.path.join(parent, ".upload-" + archive_sha)
        if os.path.lexists(pending):
            private_directory(pending)
            remove_tree(pending)


def remove(app: str, sha: str) -> None:
    if not valid_hex(sha, 40):
        fail("source SHA must be 40 lowercase hexadecimal characters")
    with application_lock(app):
        app_directory = private_directory(os.path.join(ROOT, app))
        path = private_directory(os.path.join(app_directory, sha))
        remove_tree(path)


def listing() -> list:
    result = []
    private_directory(ROOT)
    for app in APPLICATIONS:
        with application_lock(app):
            app_directory = os.path.join(ROOT, app)
            if not os.path.lexists(app_directory):
                continue
            private_directory(app_directory)
            for sha in directory_names(app_directory):
                if not valid_hex(sha, 40):
                    continue
                wave = private_directory(os.path.join(app_directory, sha))
                for target in TARGETS:
                    parent = os.path.join(wave, target)
                    if not os.path.lexists(parent):
                        continue
                    private_directory(parent)
                    for archive_sha in directory_names(parent):
                        if not valid_hex(archive_sha, 64):
                            continue
                        directory = private_directory(os.path.join(parent, archive_sha))
                        receipt = load_receipt(directory)
                        result.append({key: value for key, value in receipt.items() if key != "inventory"})
    return result


def main(argv: list) -> None:
    if argv == ["list"]:
        print(json.dumps(listing(), sort_keys=True))
    elif len(argv) == 3 and argv[0] == "remove":
        remove(argv[1], argv[2])
        print("removed candidate wave")
    else:
        fail("usage: lapkb-ci-candidates list | remove <app> <source-sha>")


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (CandidateError, OSError) as error:
        print(f"candidate store: {error}", file=sys.stderr)
        raise SystemExit(1)
