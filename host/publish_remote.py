"""One confined, durable publication path for SSH and on-origin pickup.

The caller supplies only a bounded release frame. Root, trust, package profiles,
origin and legacy aliases are fixed by /etc/lapkb/publisher.json on the origin.
All entry points call release_contract.validate_release before promotion.
"""
from __future__ import annotations

import base64
import binascii
import datetime
import fcntl
import hashlib
import html
import json
import os
import re
import secrets
import stat
import struct
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import quote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_contract as contract  # noqa: E402
from release_contract import ContractError, Policy  # noqa: E402

FRAME_MAGIC = b"LAPBPUB1"
FRAME_PREFIX = struct.Struct(">8sI")
MAX_HEADER_BYTES = 64 * 1024
STATE_NAME = ".lapkb-publisher"
STATE_FILE = "state.json"
LOCK_FILE = ".lapkb-publisher.lock"
JOURNAL_FILE = "journal.json"
STATE_SCHEMA = "lapkb-publisher-state-v1"
JOURNAL_SCHEMA = "lapkb-publisher-journal-v1"
PLAN_SCHEMA = "lapkb-publisher-plan-v1"
MAX_STATE_BYTES = 32 * 1024 * 1024
MAX_CATALOG_BYTES = 8 * 1024 * 1024
MAX_INDEX_BYTES = 4 * 1024 * 1024
MAX_JOURNAL_BYTES = 4096
MAX_HISTORY = 2048
_PUBLIC_MODE = 0o644
_PRIVATE_MODE = 0o600
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_FILE_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,191}$")
_TEMP_NAME = re.compile(r"^\.lapkb-pubtmp-([0-9]+)-([0-9a-f]{32})$")
_STAGE_NAME = re.compile(r"^stage-([0-9]+)-([0-9a-f]{32})$")
_TXN_NAME = re.compile(r"^txn-[0-9a-f]{32}$")


class PublicationError(RuntimeError):
    """A safe publication cannot continue without operator review or retry."""


def _canonical(value):
    return contract.canonical_json(value)


def _fsync(fd):
    os.fsync(fd)


def _secure_directory_info(info, *, root=False):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()):
        raise PublicationError("publisher path contains an untrusted directory")
    if root:
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise PublicationError("configured public root must be owned by the publisher and not group/other writable")
    elif info.st_mode & 0o022 and not (info.st_mode & stat.S_ISVTX and info.st_uid == 0):
        raise PublicationError("publisher path ancestor is writable by other users")


class RootFS:
    """An open directory descriptor for the one trusted public root."""

    def __init__(self, root: str):
        self.path = Path(root)
        self.fd = self._open_root(root)

    @staticmethod
    def _open_root(root):
        if not root.startswith("/") or root == "/" or root.startswith("//"):
            raise PublicationError("configured public root is not an acceptable absolute path")
        components = root[1:].split("/")
        if any(not part or part in (".", "..") for part in components):
            raise PublicationError("configured public root is not canonical")
        fd = os.open("/", _DIR_FLAGS)
        try:
            _secure_directory_info(os.fstat(fd))
            for index, component in enumerate(components):
                next_fd = os.open(component, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = next_fd
                _secure_directory_info(os.fstat(fd), root=index == len(components) - 1)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def directory(self, components, *, create=False, private=False):
        if self.fd is None:
            raise PublicationError("publisher root is closed")
        fd = os.dup(self.fd)
        try:
            for component in components:
                if (type(component) is not str or not component or component in (".", "..")
                        or "/" in component or "\x00" in component):
                    raise PublicationError("publisher path component is unsafe")
                created = False
                try:
                    next_fd = os.open(component, _DIR_FLAGS, dir_fd=fd)
                except FileNotFoundError:
                    if not create:
                        raise PublicationError("required publisher directory is missing") from None
                    try:
                        os.mkdir(component, 0o700 if private else 0o755, dir_fd=fd)
                    except FileExistsError:
                        # Another publisher may have created this component
                        # while both were opening the persistent lock path.
                        pass
                    else:
                        created = True
                        _fsync(fd)
                    next_fd = os.open(component, _DIR_FLAGS, dir_fd=fd)
                if created:
                    os.fchmod(next_fd, 0o700 if private else 0o755)
                    _fsync(next_fd)
                os.close(fd)
                fd = next_fd
                info = os.fstat(fd)
                _secure_directory_info(info)
                if private and info.st_mode & 0o077:
                    raise PublicationError("private publisher state directory permissions are unsafe")
            result = fd
            fd = -1
            return result
        finally:
            if fd >= 0:
                os.close(fd)


@contextmanager
def _publication_lock(fs: RootFS):
    lock_fd = None
    state_fd = None
    try:
        try:
            for attempt in range(20):
                try:
                    lock_fd = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                                      _PRIVATE_MODE, dir_fd=fs.fd)
                    break
                except FileNotFoundError:
                    # macOS can transiently return ENOENT to one process when
                    # another creates the same openat(O_CREAT|O_NOFOLLOW) name.
                    if attempt == 19:
                        raise
                    time.sleep(0.005)
        except OSError as error:
            raise PublicationError("publisher lock file cannot be opened safely") from error
        if lock_fd is None:
            raise PublicationError("publisher lock file cannot be opened safely")
        info = os.fstat(lock_fd)
        path_info = os.stat(LOCK_FILE, dir_fd=fs.fd, follow_symlinks=False)
        if ((not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
             or info.st_mode & 0o077)
                or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
            raise PublicationError("publisher lock file ownership or permissions are unsafe")
        os.fchmod(lock_fd, _PRIVATE_MODE)
        _fsync(lock_fd)
        os.fsync(fs.fd)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        state_fd = fs.directory([STATE_NAME], create=True, private=True)
        yield state_fd
    finally:
        if state_fd is not None:
            os.close(state_fd)
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)


def _stat_at(dir_fd, name, *, required=False):
    try:
        info = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        if required:
            raise PublicationError(f"publisher file is missing: {name}") from None
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
            or info.st_mode & 0o022):
        raise PublicationError(f"publisher file is not a safe regular file: {name}")
    return info


def _read_at(dir_fd, name, maximum, *, required=True):
    info = _stat_at(dir_fd, name, required=required)
    if info is None:
        return None
    if info.st_size < 0 or info.st_size > maximum:
        raise PublicationError(f"publisher file exceeds its size limit: {name}")
    fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    try:
        opened = os.fstat(fd)
        if ((opened.st_dev, opened.st_ino, opened.st_size) !=
                (info.st_dev, info.st_ino, info.st_size) or not stat.S_ISREG(opened.st_mode)):
            raise PublicationError(f"publisher file changed while opening: {name}")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        if len(data) != info.st_size or len(data) > maximum:
            raise PublicationError(f"publisher file changed while reading: {name}")
        return bytes(data)
    finally:
        os.close(fd)


def _hash_at(dir_fd, name, maximum=contract.MAX_FILE_BYTES, *, allow_empty=False):
    info = _stat_at(dir_fd, name, required=True)
    if info.st_size < (0 if allow_empty else 1) or info.st_size > maximum:
        raise PublicationError(f"publisher file size is invalid: {name}")
    fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
            raise PublicationError(f"publisher file changed while opening: {name}")
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise PublicationError(f"publisher file exceeds its size limit: {name}")
            digest.update(chunk)
        if total != info.st_size:
            raise PublicationError(f"publisher file changed while hashing: {name}")
    finally:
        os.close(fd)
    return total, digest.hexdigest()


def _copy_fd(source_fd, destination_fd, maximum):
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(source_fd, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise PublicationError("staged publisher file exceeds its size limit")
        view = memoryview(chunk)
        while view:
            written = os.write(destination_fd, view)
            view = view[written:]
        digest.update(chunk)
    return total, digest.hexdigest()


def _copy_source_to_fd(source: Path, destination_fd, maximum):
    try:
        before = source.lstat()
    except OSError as error:
        raise PublicationError("staged release file is unavailable") from error
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size <= 0 or before.st_size > maximum:
        raise PublicationError("staged release file is not a bounded regular file")
    source_fd = os.open(source, _FILE_FLAGS)
    try:
        opened = os.fstat(source_fd)
        if ((opened.st_dev, opened.st_ino, opened.st_size) !=
                (before.st_dev, before.st_ino, before.st_size)):
            raise PublicationError("staged release file changed while opening")
        total, digest = _copy_fd(source_fd, destination_fd, maximum)
        if total != before.st_size:
            raise PublicationError("staged release file changed while copying")
        return total, digest
    finally:
        os.close(source_fd)


def _write_temp(dir_fd, data, mode):
    name = f".lapkb-pubtmp-{os.getpid()}-{secrets.token_hex(16)}"
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                 mode, dir_fd=dir_fd)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            view = view[count:]
        os.fchmod(fd, mode)
        _fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(name, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        raise
    os.close(fd)
    return name


def _cleanup_file_temps(dir_fd):
    changed = False
    for candidate in os.listdir(dir_fd):
        match = _TEMP_NAME.fullmatch(candidate)
        if match is None or _pid_alive(int(match.group(1))):
            continue
        info = os.stat(candidate, dir_fd=dir_fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink < 1 or info.st_mode & 0o022):
            raise PublicationError("publisher temporary file has unsafe ownership or type")
        os.unlink(candidate, dir_fd=dir_fd)
        changed = True
    if changed:
        _fsync(dir_fd)


def _replace_at(dir_fd, name, data, mode=_PUBLIC_MODE):
    if not _SAFE_NAME.fullmatch(name):
        raise PublicationError("publisher destination name is unsafe")
    _cleanup_file_temps(dir_fd)
    _stat_at(dir_fd, name)
    temp = _write_temp(dir_fd, data, mode)
    try:
        os.replace(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        _fsync(dir_fd)
    except BaseException:
        try:
            os.unlink(temp, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        raise


def _promote_immutable(source: Path, target_fd: int, name: str, size: int, digest: str):
    if not _SAFE_NAME.fullmatch(name):
        raise PublicationError("immutable asset name is unsafe")
    _cleanup_file_temps(target_fd)
    current = _stat_at(target_fd, name)
    if current is not None:
        actual_size, actual_digest = _hash_at(target_fd, name)
        if (actual_size, actual_digest) != (size, digest):
            raise PublicationError(f"immutable release asset conflicts with existing bytes: {name}")
        return False
    temp = f".lapkb-pubtmp-{os.getpid()}-{secrets.token_hex(16)}"
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                 _PRIVATE_MODE, dir_fd=target_fd)
    try:
        actual_size, actual_digest = _copy_source_to_fd(source, fd, contract.MAX_FILE_BYTES)
        if (actual_size, actual_digest) != (size, digest):
            raise PublicationError("staged release file changed before immutable promotion")
        os.fchmod(fd, _PUBLIC_MODE)
        _fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(temp, dir_fd=target_fd)
        except FileNotFoundError:
            pass
        raise
    os.close(fd)
    try:
        os.link(temp, name, src_dir_fd=target_fd, dst_dir_fd=target_fd, follow_symlinks=False)
        _fsync(target_fd)
    except FileExistsError:
        actual_size, actual_digest = _hash_at(target_fd, name)
        if (actual_size, actual_digest) != (size, digest):
            raise PublicationError(f"immutable release asset conflicts with existing bytes: {name}")
        return False
    finally:
        try:
            os.unlink(temp, dir_fd=target_fd)
        except FileNotFoundError:
            pass
        _fsync(target_fd)
    return True


def _copy_immutable_alias(source: Path, alias_fd: int, name: str, size: int, digest: str):
    return _promote_immutable(source, alias_fd, name, size, digest)


def _pid_alive(pid):
    if pid == os.getpid():
        return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _remove_stage_dir(parent_fd, name):
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise PublicationError("owned temporary directory has unsafe ownership or type")
    fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
    try:
        for entry in os.listdir(fd):
            child = os.stat(entry, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(child.st_mode):
                _remove_stage_dir(fd, entry)
            elif (stat.S_ISREG(child.st_mode) and child.st_uid == os.geteuid()
                  and child.st_nlink >= 1 and not child.st_mode & 0o022):
                os.unlink(entry, dir_fd=fd)
            else:
                raise PublicationError("owned temporary directory contains an unexpected file type")
        _fsync(fd)
    finally:
        os.close(fd)
    os.rmdir(name, dir_fd=parent_fd)
    _fsync(parent_fd)


def _cleanup_owned_temporary_state(state_fd, keep_stage=None, keep_txn=None):
    for name in os.listdir(state_fd):
        if name == keep_stage or name == keep_txn or name in (LOCK_FILE, JOURNAL_FILE, STATE_FILE):
            continue
        stage = _STAGE_NAME.fullmatch(name)
        txn = _TXN_NAME.fullmatch(name)
        if stage:
            if _pid_alive(int(stage.group(1))):
                continue
            _remove_stage_dir(state_fd, name)
        elif txn:
            # A transaction is created and used only while the persistent lock
            # is held. A journaled transaction is passed as keep_txn.
            _remove_stage_dir(state_fd, name)
        elif _TEMP_NAME.fullmatch(name):
            info = os.stat(name, dir_fd=state_fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o022):
                raise PublicationError("publisher temporary file is unsafe")
            pid = int(_TEMP_NAME.fullmatch(name).group(1))
            if not _pid_alive(pid):
                os.unlink(name, dir_fd=state_fd)
                _fsync(state_fd)


def create_staging(policy: Policy) -> tuple[str, Path]:
    """Create private, unique on-root staging for frames and pickup downloads."""
    with RootFS(policy.root) as fs:
        with _publication_lock(fs) as state_fd:
            # Only recovery may remove a journaled transaction or its input.
            if _read_at(state_fd, JOURNAL_FILE, MAX_JOURNAL_BYTES, required=False) is None:
                _cleanup_owned_temporary_state(state_fd)
            name = f"stage-{os.getpid()}-{secrets.token_hex(16)}"
            os.mkdir(name, 0o700, dir_fd=state_fd)
            stage_fd = os.open(name, _DIR_FLAGS, dir_fd=state_fd)
            try:
                os.fchmod(stage_fd, 0o700)
                _fsync(stage_fd)
            finally:
                os.close(stage_fd)
            _fsync(state_fd)
            stage_path = policy_path(policy, STATE_NAME, name)
            return name, stage_path


def policy_path(policy, *parts):
    return Path(policy.root).joinpath(*parts)


def remove_staging(policy: Policy, name: str):
    if not _STAGE_NAME.fullmatch(name):
        raise PublicationError("temporary staging name is invalid")
    with RootFS(policy.root) as fs:
        with _publication_lock(fs) as state_fd:
            journal_bytes = _read_at(state_fd, JOURNAL_FILE, MAX_JOURNAL_BYTES, required=False)
            if journal_bytes is not None:
                # Do not guess whether a malformed or newer journal refers to
                # this input. Recovery owns the decision while the journal exists.
                return
            try:
                _remove_stage_dir(state_fd, name)
            except FileNotFoundError:
                pass


def _read_exact(stream, size, label):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.read(min(1024 * 1024, size - len(chunks)))
        if not chunk:
            raise PublicationError(f"publisher frame is truncated while reading {label}")
        chunks.extend(chunk)
    return bytes(chunks)


def read_payload(stream, stage_dir: Path):
    """Read one exact bounded frame, spooling file bodies instead of RAM."""
    prefix = _read_exact(stream, FRAME_PREFIX.size, "header")
    magic, header_size = FRAME_PREFIX.unpack(prefix)
    if magic != FRAME_MAGIC or not 1 <= header_size <= MAX_HEADER_BYTES:
        raise PublicationError("publisher frame header is invalid or oversized")
    header_bytes = _read_exact(stream, header_size, "header")
    header = contract.strict_json(header_bytes, MAX_HEADER_BYTES, "publisher frame header")
    if (type(header) is not dict or set(header) != {"schema", "app", "channel", "files"}
            or _canonical(header) != header_bytes):
        raise PublicationError("publisher frame header is not canonical")
    if (header["schema"] != "lapkb-publish-frame-v1"
            or type(header["app"]) is not str or header["app"] not in contract.APP_IDS
            or type(header["channel"]) is not str or header["channel"] not in contract.CHANNELS):
        raise PublicationError("publisher frame release identity is invalid")
    entries = header["files"]
    if type(entries) is not list or not 1 <= len(entries) <= contract.MAX_FILES:
        raise PublicationError("publisher frame file count is invalid")
    names, total = set(), 0
    files = {}
    entry_names = []
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"name", "size", "sha256"}:
            raise PublicationError("publisher frame file record has an unexpected shape")
        name, size, digest = entry["name"], entry["size"], entry["sha256"]
        if type(name) is not str or not _SAFE_NAME.fullmatch(name) or name in (".", "..") or name in names:
            raise PublicationError("publisher frame contains an unsafe or duplicate file name")
        if type(size) is not int or size < 1 or size > contract.MAX_FILE_BYTES:
            raise PublicationError("publisher frame file size is out of range")
        if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise PublicationError("publisher frame file digest is invalid")
        names.add(name)
        entry_names.append(name)
        total += size
        if total > contract.MAX_RELEASE_BYTES:
            raise PublicationError("publisher frame aggregate size exceeds its bound")
        path = stage_dir / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        sha = hashlib.sha256()
        written = 0
        try:
            while written < size:
                chunk = _read_exact(stream, min(1024 * 1024, size - written), name)
                sha.update(chunk)
                view = memoryview(chunk)
                while view:
                    count = os.write(fd, view)
                    view = view[count:]
                written += len(chunk)
            if sha.hexdigest() != digest:
                raise PublicationError(f"publisher frame digest does not match: {name}")
            os.fchmod(fd, _PRIVATE_MODE)
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            raise
        os.close(fd)
        files[name] = path
    if entry_names != sorted(entry_names):
        raise PublicationError("publisher frame files are not in canonical name order")
    extra = stream.read(1)
    if extra:
        raise PublicationError("publisher frame has trailing bytes")
    stage_fd = os.open(stage_dir, _DIR_FLAGS)
    try:
        _fsync(stage_fd)
    finally:
        os.close(stage_fd)
    return header["app"], header["channel"], files


def write_payload(stream, app, channel, files):
    """Write a complete frame from validated local files, using bounded reads."""
    entries, total = [], 0
    if type(files) is not dict or not 1 <= len(files) <= contract.MAX_FILES:
        raise ContractError("release file inventory count is invalid")
    for name in sorted(files):
        if type(name) is not str or not _SAFE_NAME.fullmatch(name):
            raise ContractError("release contains an unsafe file name")
        size, digest = contract._sha256_file(Path(files[name]))
        total += size
        if total > contract.MAX_RELEASE_BYTES:
            raise ContractError("release aggregate size exceeds its bound")
        entries.append({"name": name, "size": size, "sha256": digest})
    header = {"schema": "lapkb-publish-frame-v1", "app": app, "channel": channel, "files": entries}
    encoded = _canonical(header)
    if len(encoded) > MAX_HEADER_BYTES:
        raise ContractError("publisher frame header exceeds its size limit")
    stream.write(FRAME_PREFIX.pack(FRAME_MAGIC, len(encoded)))
    stream.write(encoded)
    for entry in entries:
        path = Path(files[entry["name"]])
        fd = os.open(path, _FILE_FLAGS)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != entry["size"]:
                raise ContractError("release file changed before transport")
            digest = hashlib.sha256()
            sent = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                stream.write(chunk)
                digest.update(chunk)
                sent += len(chunk)
            if sent != entry["size"] or digest.hexdigest() != entry["sha256"]:
                raise ContractError("release file changed during transport")
        finally:
            os.close(fd)


def _version_tuple(version):
    return contract._version(version)


def _record_from_release(release):
    receipt_bytes = release["receiptBytes"]
    attestation_digest = hashlib.sha256(
        contract.canonical_json(release["attestation"])
    ).hexdigest()
    manifest_digest = hashlib.sha256(release["manifestBytes"]).hexdigest()
    return {
        "app": release["app"], "channel": release["channel"], "version": release["version"],
        "coverage": release["coverage"], "feed": release["feed"],
        "targets": release["targets"], "distribution": release["distribution"],
        "versionTuple": list(release["versionTuple"]), "source": release["source"],
        "inventory": release["inventory"], "inventoryDigest": release["inventoryDigest"],
        "receipt": release["receipt"], "receiptSha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "buildAttestationSha256": attestation_digest, "manifestSha256": manifest_digest,
    }


def _scope_key(record):
    return (record["app"], record["channel"], record["coverage"], record["feed"],
            tuple(record["targets"]))


def _validate_scope(record, policy):
    try:
        coverage = record["coverage"]
        if (record["feed"] != contract.feed_for_coverage(coverage)
                or record["targets"] != sorted(contract.COVERAGES[coverage])
                or record["distribution"] != contract.release_mode(
                    policy, record["app"], record["channel"], coverage)):
            raise PublicationError("publisher coverage/feed/target/distribution identity differs from policy")
    except (KeyError, TypeError, ContractError) as error:
        raise PublicationError("publisher release scope is not configured") from error


def _historical_path(path):
    if (type(path) is not str or len(path) > 1024 or path.startswith("/")
            or any(not _SAFE_NAME.fullmatch(part) or part in (".", "..")
                   for part in path.split("/"))):
        raise PublicationError("historical inventory contains an unsafe public path")
    return path.split("/")


def _public_inventory(fs):
    """Observe the complete root through no-follow descriptors; never adopt it."""
    entries = {".": {"kind": "directory", "mode": stat.S_IMODE(os.fstat(fs.fd).st_mode)}}

    def visit(fd, prefix):
        initial_names = sorted(os.listdir(fd))
        for name in initial_names:
            if not prefix and name in (STATE_NAME, LOCK_FILE):
                continue
            path = "/".join(prefix + [name])
            _historical_path(path)
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISDIR(info.st_mode):
                _secure_directory_info(info)
                child_fd = os.open(name, _DIR_FLAGS, dir_fd=fd)
                try:
                    opened = os.fstat(child_fd)
                    if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                        raise PublicationError("historical directory changed during inventory")
                    entries[path] = {"kind": "directory", "mode": mode}
                    visit(child_fd, prefix + [name])
                finally:
                    os.close(child_fd)
            else:
                size, digest = _hash_at(fd, name, allow_empty=True)
                entries[path] = {"kind": "file", "mode": mode, "size": size, "sha256": digest}
            if len(entries) > 16384:
                raise PublicationError("historical public inventory exceeds its bound")
        if sorted(os.listdir(fd)) != initial_names:
            raise PublicationError("historical directory changed during inventory")

    visit(fs.fd, [])
    return entries


def _validate_historical(value, policy):
    if value is None:
        return
    fields = {"schema", "root", "origin", "observedAt", "inventory", "catalog", "current",
              "feeds", "inventorySha256", "reviewSha256"}
    if (type(value) is not dict or set(value) != fields
            or value["schema"] != "lapkb-observed-history-v1"
            or value["root"] != policy.root or value["origin"] != policy.origin):
        raise PublicationError("observed historical state has an unexpected identity/shape")
    try:
        observed = datetime.datetime.fromisoformat(value["observedAt"].replace("Z", "+00:00"))
        if observed.utcoffset() != datetime.timedelta(0):
            raise ValueError()
    except (AttributeError, TypeError, ValueError):
        raise PublicationError("historical observation time must be UTC") from None
    inventory = value["inventory"]
    if type(inventory) is not dict or not 1 <= len(inventory) <= 16384 or "." not in inventory:
        raise PublicationError("observed historical inventory is incomplete")
    for path, item in inventory.items():
        parts = [] if path == "." else _historical_path(path)
        if parts and parts[0] in (STATE_NAME, LOCK_FILE):
            raise PublicationError("historical input must not contain publisher private state")
        if (type(item) is not dict or item.get("kind") not in ("file", "directory")
                or type(item.get("mode")) is not int or not 0 <= item["mode"] <= 0o777
                or item["mode"] & 0o022):
            raise PublicationError("observed historical entry mode/type is unsafe")
        expected = {"kind", "mode"} if item["kind"] == "directory" else {"kind", "mode", "size", "sha256"}
        if set(item) != expected or (not parts and item["kind"] != "directory"):
            raise PublicationError("observed historical entry has an unexpected shape")
        if parts:
            parent = "/".join(parts[:-1]) or "."
            if inventory.get(parent, {}).get("kind") != "directory":
                raise PublicationError("historical inventory parent is missing")
        if item["kind"] == "file" and (type(item["size"]) is not int
                or not 0 <= item["size"] <= contract.MAX_FILE_BYTES
                or type(item["sha256"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise PublicationError("observed historical entry size/hash is invalid")
    if value["inventorySha256"] != hashlib.sha256(_canonical(inventory)).hexdigest():
        raise PublicationError("historical inventory digest is inconsistent")
    if type(value["reviewSha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", value["reviewSha256"]):
        raise PublicationError("historical review input digest is invalid")
    catalog = value["catalog"]
    if (type(catalog) is not dict or set(catalog) != {"schema", "apps"}
            or catalog["schema"] != "lapkb-downloads-v1" or type(catalog["apps"]) is not dict
            or not set(catalog["apps"]) <= set(contract.APP_IDS)):
        raise PublicationError("historical catalog has an unexpected shape")
    for app, app_entry in catalog["apps"].items():
        if type(app_entry) is not dict or set(app_entry) != {"channels"} or type(app_entry["channels"]) is not dict:
            raise PublicationError("historical catalog application is malformed")
        for channel, entry in app_entry["channels"].items():
            if (channel not in contract.CHANNELS or type(entry) is not dict
                    or set(entry) != {"version", "files"} or type(entry["files"]) is not dict):
                raise PublicationError("historical catalog channel is malformed")
            _version_tuple(entry["version"])
            for name, artifact in entry["files"].items():
                _historical_path(name)
                if ("/" in name or type(artifact) is not dict or set(artifact) != {"size", "sha256"}
                        or type(artifact["size"]) is not int or type(artifact["sha256"]) is not str):
                    raise PublicationError("historical catalog artifact is malformed")
                retained = inventory.get(f"downloads/{app}/{channel}/{name}")
                if (retained is None or retained["kind"] != "file"
                        or artifact != {k: retained[k] for k in ("size", "sha256")}):
                    raise PublicationError("historical catalog asset is not bound to the exact inventory")
    current, feeds = value["current"], value["feeds"]
    if type(current) is not list or type(feeds) is not dict or len(current) > 60:
        raise PublicationError("historical current/feed inventory is invalid")
    keys = []
    for item in current:
        if (type(item) is not dict or set(item) != {"app", "channel", "target", "version", "feed", "artifact"}
                or any(type(item[key]) is not str for key in ("app", "channel", "target", "version", "feed", "artifact"))
                or item["app"] not in contract.APP_IDS or item["channel"] not in contract.CHANNELS
                or item["target"] not in contract.TARGETS or item["feed"] != "latest.json"):
            raise PublicationError("historical current identity is malformed")
        app, channel, target = item["app"], item["channel"], item["target"]
        _version_tuple(item["version"])
        catalog_entry = catalog["apps"].get(app, {}).get("channels", {}).get(channel, {})
        if (catalog_entry.get("version") != item["version"]
                or item["artifact"] not in catalog_entry.get("files", {})):
            raise PublicationError("historical current asset/version is absent from the observed catalog")
        feed_path = f"downloads/{app}/{channel}/latest.json"
        document = feeds.get(feed_path)
        if (type(document) is not dict or document.get("version") != item["version"]
                or type(document.get("platforms")) is not dict
                or target not in document["platforms"] or feed_path not in inventory):
            raise PublicationError("historical current target/version is absent from its observed feed")
        platform = document["platforms"][target]
        try:
            url_text = platform.get("url", "") if type(platform) is dict else ""
            url = urlsplit(url_text) if type(url_text) is str else None
        except ValueError:
            raise PublicationError("historical feed URL is malformed") from None
        if (url is None or url.scheme != "https" or not url.hostname or url.username or url.password
                or url.query or url.fragment or url.path.rsplit("/", 1)[-1] != item["artifact"]):
            raise PublicationError("historical feed does not identify the inventoried archive")
        # A legacy URL may differ in origin; it is observed, not new trusted provenance.
        allowed_paths = {f"/downloads/{app}/{channel}/{item['artifact']}"}
        alias = policy.legacy_aliases[app].get(channel)
        if alias is not None:
            allowed_paths.add(f"/{alias}/{item['artifact']}")
        if url.path not in allowed_paths:
            raise PublicationError("historical feed archive path is not canonical or its retained legacy mirror")
        keys.append((app, channel, target))
    if keys != sorted(set(keys)):
        raise PublicationError("historical current target identities are duplicated or unsorted")
    expected_feeds = {f"downloads/{item['app']}/{item['channel']}/latest.json" for item in current}
    public_feeds = {path for path in inventory if re.fullmatch(
        r"downloads/(launcher|papir|bestdose|bdautodial|checkerboard)/(stable|beta)/latest\.json", path)}
    if set(feeds) != expected_feeds or expected_feeds != public_feeds:
        raise PublicationError("historical input must explicitly cover every retained canonical feed")
    for path, document in feeds.items():
        targets = {item["target"] for item in current
                   if path == f"downloads/{item['app']}/{item['channel']}/latest.json"}
        if set(document["platforms"]) != targets:
            raise PublicationError("historical current inventory is not the exact observed feed target set")


def _verify_historical(fs, state, policy):
    historical = state["historical"]
    if historical is None:
        return
    replaced = {f"downloads/{r['app']}/{r['channel']}/{r['feed']}" for r in state["history"]}
    for record in state["history"]:
        alias = policy.legacy_aliases[record["app"]].get(record["channel"])
        if record["coverage"] != "windows-x64" and alias is not None:
            replaced.add(f"{alias}/latest.json")
    if state["history"]:
        replaced.update(("downloads/catalog.json", "downloads/index.html"))
    for path, expected in historical["inventory"].items():
        if path in replaced:
            continue
        if expected["kind"] == "directory":
            fd = os.dup(fs.fd) if path == "." else fs.directory(_historical_path(path))
            try:
                if stat.S_IMODE(os.fstat(fd).st_mode) != expected["mode"]:
                    raise PublicationError("retained historical directory mode changed")
            finally:
                os.close(fd)
        else:
            parts = _historical_path(path)
            fd = fs.directory(parts[:-1])
            try:
                info = _stat_at(fd, parts[-1], required=True)
                if (stat.S_IMODE(info.st_mode) != expected["mode"]
                        or _hash_at(fd, parts[-1], allow_empty=True) != (expected["size"], expected["sha256"])):
                    raise PublicationError("retained historical file bytes/mode changed: " + path)
            finally:
                os.close(fd)


def initialize_history(policy: Policy, inventory_path: Path, expected_sha256: str):
    """Explicit local administrative operation. Receive/pickup never call this.

    A fresh protected review input binds the complete root, catalog and observed
    feed targets. Only private state is created; public files/modes are untouched.
    """
    data = contract._read_protected_file(inventory_path, MAX_STATE_BYTES, private=True)
    if (type(expected_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
            or hashlib.sha256(data).hexdigest() != expected_sha256):
        raise PublicationError("historical review input does not match its approved SHA-256")
    reviewed = contract.strict_json(data, MAX_STATE_BYTES, "historical review input")
    if (type(reviewed) is not dict or set(reviewed) != {
            "schema", "root", "origin", "observedAt", "inventory", "catalog", "current"}
            or reviewed["schema"] != "lapkb-historical-inventory-v1" or _canonical(reviewed) != data):
        raise PublicationError("historical review input has an unexpected shape/encoding")
    historical = {**reviewed, "schema": "lapkb-observed-history-v1", "feeds": {},
                  "inventorySha256": hashlib.sha256(_canonical(reviewed["inventory"])).hexdigest(),
                  "reviewSha256": expected_sha256}
    try:
        observed = datetime.datetime.fromisoformat(reviewed["observedAt"].replace("Z", "+00:00"))
        age = datetime.datetime.now(datetime.timezone.utc) - observed
        if observed.utcoffset() != datetime.timedelta(0) or not datetime.timedelta(minutes=-5) <= age <= datetime.timedelta(hours=24):
            raise ValueError()
    except (AttributeError, TypeError, ValueError):
        raise PublicationError("historical review requires a fresh UTC host inventory (within 24 hours)") from None
    with RootFS(policy.root) as fs:
        with _publication_lock(fs) as state_fd:
            if (_read_at(state_fd, JOURNAL_FILE, MAX_JOURNAL_BYTES, required=False) is not None
                    or _read_at(state_fd, STATE_FILE, MAX_STATE_BYTES, required=False) is not None):
                raise PublicationError("historical initialization requires no existing state or journal")
            before = _public_inventory(fs)
            if before != reviewed["inventory"]:
                raise PublicationError("fresh complete public path/byte/mode inventory differs from the reviewed input")
            downloads_fd = fs.directory(["downloads"])
            try:
                catalog_bytes = _read_at(downloads_fd, "catalog.json", MAX_CATALOG_BYTES)
                if contract.strict_json(catalog_bytes, MAX_CATALOG_BYTES, "historical catalog") != reviewed["catalog"]:
                    raise PublicationError("live historical catalog differs from the reviewed entries")
            finally:
                os.close(downloads_fd)
            if type(reviewed["current"]) is not list:
                raise PublicationError("historical current inventory must be explicit")
            for item in reviewed["current"]:
                if type(item) is not dict or not {"app", "channel", "feed"} <= set(item):
                    raise PublicationError("historical current entry is malformed")
                path = f"downloads/{item['app']}/{item['channel']}/{item['feed']}"
                parts = _historical_path(path)
                fd = fs.directory(parts[:-1])
                try:
                    historical["feeds"][path] = contract.strict_json(
                        _read_at(fd, parts[-1], contract.MAX_MANIFEST_BYTES),
                        contract.MAX_MANIFEST_BYTES, "observed historical feed")
                finally:
                    os.close(fd)
            _validate_historical(historical, policy)
            if _public_inventory(fs) != before:
                raise PublicationError("public root changed during protected history initialization")
            state = {"schema": STATE_SCHEMA, "history": [], "historical": historical}
            state_bytes = _canonical(state)
            _validate_state(state_bytes, policy)
            _write_new(state_fd, STATE_FILE, state_bytes, _PRIVATE_MODE)
            _checkpoint("history-initialized")
            return {"status": "history-initialized", "inventorySha256": historical["inventorySha256"],
                    "reviewSha256": expected_sha256, "entries": len(before)}


def _validate_state(data, policy):
    state = contract.strict_json(data, MAX_STATE_BYTES, "publisher state")
    if type(state) is not dict or set(state) != {"schema", "history", "historical"} or state["schema"] != STATE_SCHEMA:
        raise PublicationError("publisher state has an unsupported shape")
    if contract.canonical_json(state) != data:
        raise PublicationError("publisher state is not canonical")
    _validate_historical(state["historical"], policy)
    history = state["history"]
    if type(history) is not list or len(history) > MAX_HISTORY:
        raise PublicationError("publisher release history exceeds its bound")
    seen = set()
    prev = None
    for record in history:
        fields = {"app", "channel", "version", "versionTuple", "source", "inventory",
                  "inventoryDigest", "receipt", "receiptSha256", "buildAttestationSha256", "manifestSha256",
                  "coverage", "feed", "targets", "distribution"}
        if type(record) is not dict or set(record) != fields:
            raise PublicationError("publisher release history record has an unexpected shape")
        app, channel, version = record["app"], record["channel"], record["version"]
        if (type(app) is not str or app not in contract.APP_IDS
                or type(channel) is not str or channel not in contract.CHANNELS
                or type(version) is not str):
            raise PublicationError("publisher history contains an unsupported release identity")
        version_tuple = _version_tuple(version)
        if record["versionTuple"] != list(version_tuple) or any(type(x) is not int for x in record["versionTuple"]):
            raise PublicationError("publisher history version tuple is invalid")
        _validate_scope(record, policy)
        key = _history_sort(record)
        if key in seen or (prev is not None and key <= prev):
            raise PublicationError("publisher history ordering or uniqueness is invalid")
        seen.add(key)
        prev = key
        contract._validate_source(record["source"], policy, app, channel, version)
        inventory = record["inventory"]
        if type(inventory) is not list or not 1 <= len(inventory) <= contract.MAX_FILES:
            raise PublicationError("publisher history inventory is invalid")
        names = []
        total = 0
        for item in inventory:
            if type(item) is not dict or set(item) != {"name", "size", "sha256"}:
                raise PublicationError("publisher history inventory entry has an unexpected shape")
            name, size, digest = item["name"], item["size"], item["sha256"]
            if type(name) is not str or not _SAFE_NAME.fullmatch(name):
                raise PublicationError("publisher history contains an unsafe file name")
            if type(size) is not int or not 1 <= size <= contract.MAX_FILE_BYTES:
                raise PublicationError("publisher history file size is invalid")
            if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise PublicationError("publisher history digest is invalid")
            names.append(name)
            total += size
        if names != sorted(set(names)) or total > contract.MAX_RELEASE_BYTES:
            raise PublicationError("publisher history inventory order or size is invalid")
        if (type(record["inventoryDigest"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", record["inventoryDigest"])
                or hashlib.sha256(contract.canonical_json(inventory)).hexdigest() != record["inventoryDigest"]):
            raise PublicationError("publisher history inventory digest is invalid")
        for name in ("receiptSha256", "buildAttestationSha256", "manifestSha256"):
            if type(record[name]) is not str or not re.fullmatch(r"[0-9a-f]{64}", record[name]):
                raise PublicationError("publisher history metadata digest is invalid")
        receipt = record["receipt"]
        receipt_fields = {"schema", "app", "channel", "version", "source",
                          "buildAttestationSha256", "manifestSha256", "signatureKeyId", "targets"}
        if record["coverage"] == "windows-x64":
            receipt_fields.update(("coverage", "feed"))
        if record["distribution"] == "manual-checksum":
            receipt_fields.add("distribution")
        if type(receipt) is not dict or set(receipt) != receipt_fields:
            raise PublicationError("publisher history receipt has an unexpected shape")
        if (receipt["schema"] != "release-receipt-v1" or receipt["app"] != app
                or receipt["channel"] != channel or receipt["version"] != version
                or receipt["source"] != record["source"]
                or receipt["buildAttestationSha256"] != record["buildAttestationSha256"]
                or receipt["manifestSha256"] != record["manifestSha256"]
                or receipt["signatureKeyId"] != policy.apps[app]["channels"][channel]["keyId"]):
            raise PublicationError("publisher history receipt identity is inconsistent")
        for digest_name in ("buildAttestationSha256", "manifestSha256"):
            if (type(receipt[digest_name]) is not str
                    or not re.fullmatch(r"[0-9a-f]{64}", receipt[digest_name])):
                raise PublicationError("publisher history receipt digest is invalid")
        if (type(receipt["targets"]) is not dict or sorted(receipt["targets"]) != record["targets"]
                or receipt.get("coverage", "full-six") != record["coverage"]
                or receipt.get("feed", "latest.json") != record["feed"]
                or receipt.get("distribution", "signed") != record["distribution"]
                or hashlib.sha256(_canonical(receipt)).hexdigest() != record["receiptSha256"]):
            raise PublicationError("publisher history receipt scope/digest is invalid")
        by_name = {item["name"]: item for item in inventory}
        metadata_names = {f"build-attestation-{version}.json", f"release-receipt-{version}.json", record["feed"]}
        if record["distribution"] == "signed":
            metadata_names.update((f"build-attestation-{version}.json.sig", f"release-receipt-{version}.json.sig"))
        for name, digest in ((f"build-attestation-{version}.json", record["buildAttestationSha256"]),
                             (f"release-receipt-{version}.json", record["receiptSha256"]),
                             (record["feed"], record["manifestSha256"])):
            if by_name.get(name, {}).get("sha256") != digest:
                raise PublicationError("publisher history metadata is absent from its exact inventory")
        artifacts_seen = set()
        for target, target_record in receipt["targets"].items():
            fields = {"packageIdentity", "roles", "artifacts"}
            if record["coverage"] == "windows-x64":
                fields.update(("build", "windowsPayload"))
                if record["distribution"] == "signed":
                    fields.add("installerSignature")
            if type(target_record) is not dict or set(target_record) != fields:
                raise PublicationError("publisher history target record is malformed")
            identity = {"bundleIdentifier": contract.BUNDLE_IDS[app],
                        "displayName": contract.WINDOWS_PRODUCTS[app] if record["coverage"] == "windows-x64" else contract.DISPLAY_NAMES[app],
                        "executable": policy.apps[app]["executable"], "architecture": target.split("-")[-1],
                        "version": version}
            if target_record["packageIdentity"] != identity:
                raise PublicationError("publisher history package identity is inconsistent")
            if record["coverage"] == "windows-x64":
                contract._validate_windows_payload(target_record, app, version, identity["executable"])
            artifacts = target_record["artifacts"]
            if type(artifacts) is not list or not 1 <= len(artifacts) <= 8:
                raise PublicationError("publisher history artifact inventory is invalid")
            installers, updaters, used = [], [], set()
            for artifact in artifacts:
                if type(artifact) is not dict or set(artifact) != {"name", "kind", "roles", "size", "sha256", "signatureKeyId"}:
                    raise PublicationError("publisher history artifact is malformed")
                name = artifact["name"]
                if (type(name) is not str or name in artifacts_seen
                        or type(artifact["size"]) is not int or artifact["size"] < 1
                        or artifact["size"] > (256 * 1024 * 1024 if record["coverage"] == "windows-x64" else contract.MAX_FILE_BYTES)
                        or type(artifact["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])):
                    raise PublicationError("publisher history artifact identity/size/hash is invalid")
                profiles = policy.apps[app]["channels"][channel]["profiles"][target]
                profile = next((p for p in profiles if name.endswith("." + p["extension"])), None)
                if (profile is None or profile["id"] in used or artifact["kind"] != profile["kind"]
                        or artifact["roles"] != profile["roles"]
                        or name != f"{app}-{version}-{target}-{artifact['sha256']}.{profile['extension']}"
                        or by_name.get(name) != {k: artifact[k] for k in ("name", "size", "sha256")}):
                    raise PublicationError("publisher history artifact differs from configured profile/inventory")
                used.add(profile["id"])
                artifacts_seen.add(name)
                updater = "updater" in artifact["roles"]
                if artifact["signatureKeyId"] != (receipt["signatureKeyId"] if updater else None):
                    raise PublicationError("publisher history artifact updater trust is inconsistent")
                if "installer" in artifact["roles"]:
                    installers.append(name)
                if updater:
                    updaters.append(name)
            if (any(p["required"] and p["id"] not in used for p in profiles)
                    or len(updaters) != (0 if record["distribution"] == "manual-checksum" else 1)
                    or not installers or target_record["roles"] != {
                        "installer": sorted(installers), "updater": updaters[0] if updaters else None}):
                raise PublicationError("publisher history installer/updater roles are inconsistent")
            if record["coverage"] == "windows-x64" and record["distribution"] == "signed":
                signature = target_record["installerSignature"]
                if type(signature) is not str or not 1 <= len(signature) <= 16 * 1024:
                    raise PublicationError("publisher history installer signature is malformed")
                try:
                    signature_bytes = base64.b64decode(signature, validate=True)
                    if base64.b64encode(signature_bytes).decode("ascii") != signature:
                        raise ValueError()
                    contract._signature_text(signature_bytes, "historical release installer signature")
                except (binascii.Error, ValueError):
                    raise PublicationError("publisher history installer signature encoding is malformed") from None
            if [a["name"] for a in artifacts] != sorted(a["name"] for a in artifacts):
                raise PublicationError("publisher history artifact order is invalid")
        if set(by_name) != metadata_names | artifacts_seen:
            raise PublicationError("publisher history inventory contains missing or unexpected files")
    return state


def _load_state(state_fd, policy):
    data = _read_at(state_fd, STATE_FILE, MAX_STATE_BYTES, required=False)
    if data is None:
        return None
    return _validate_state(data, policy)


def _history_sort(record):
    return (*_scope_key(record), tuple(record["versionTuple"]))


def _latest_by_app_channel(state):
    current = {}
    for record in state["history"]:
        key = _scope_key(record)
        if key not in current or tuple(record["versionTuple"]) > tuple(current[key]["versionTuple"]):
            current[key] = record
    return current


def _read_release_from_disk(policy, fs, state_record, verifier=contract.VERIFIER_PATH):
    app, channel = state_record["app"], state_record["channel"]
    directory = fs.directory(["downloads", app, channel])
    try:
        files = {}
        for item in state_record["inventory"]:
            name = item["name"]
            files[name] = policy_path(policy, "downloads", app, channel, name)
            size, digest = _hash_at(directory, name)
            if (size, digest) != (item["size"], item["sha256"]):
                raise PublicationError(f"published asset differs from durable history: {name}")
        release = contract.validate_release(app, channel, files, policy, verifier=verifier)
        if _record_from_release(release) != state_record:
            raise PublicationError("published release does not match its durable history record")
        return release
    except ContractError as error:
        raise PublicationError(str(error)) from error
    finally:
        os.close(directory)


def _verify_alias(policy, fs, release, *, check_manifest=True):
    alias = release["legacy"]
    if alias is None:
        return
    alias_fd = fs.directory([alias])
    try:
        if check_manifest:
            manifest = _read_at(alias_fd, "latest.json", contract.MAX_MANIFEST_BYTES)
            if manifest != release["manifestBytes"]:
                raise PublicationError("configured legacy feed does not contain identical canonical manifest bytes")
        for target_record in release["receipt"]["targets"].values():
            for artifact in target_record["artifacts"]:
                name = artifact["name"]
                if "installer" not in artifact["roles"] and "updater" not in artifact["roles"]:
                    continue
                size, digest = _hash_at(alias_fd, name)
                if (size, digest) != (artifact["size"], artifact["sha256"]):
                    raise PublicationError(f"legacy release asset differs from canonical bytes: {name}")
    finally:
        os.close(alias_fd)


def _current_releases(policy, fs, state, override=None,
                      verifier=contract.VERIFIER_PATH):
    releases = {}
    current = _latest_by_app_channel(state)
    for key, record in current.items():
        is_override = override is not None and key == _scope_key(override)
        if is_override:
            release = override
            if _record_from_release(release) != record:
                raise PublicationError("pending release differs from the journaled state")
        else:
            release = _read_release_from_disk(policy, fs, record, verifier=verifier)
        _verify_alias(policy, fs, release, check_manifest=not is_override)
        releases[key] = release
    return releases


def _render_catalog(releases, state):
    historical = state["historical"]
    apps = json.loads(_canonical(historical["catalog"]["apps"])) if historical else {}
    for entry in apps.values():
        for channel_entry in entry["channels"].values():
            channel_entry["targets"] = {}
    if historical:
        for item in historical["current"]:
            entry = apps[item["app"]]["channels"][item["channel"]]
            entry["targets"][item["target"]] = {
                "version": item["version"], "feed": item["feed"],
                "distribution": "observed-history", "files": [item["artifact"]],
            }
    # Preserve every validated historical package, not just the current feed.
    for record in state["history"]:
        entry = apps.setdefault(record["app"], {"channels": {}})["channels"].setdefault(
            record["channel"], {"files": {}, "targets": {}})
        for target, target_record in record["receipt"]["targets"].items():
            for artifact in target_record["artifacts"]:
                metadata = {"sha256": artifact["sha256"], "size": artifact["size"],
                            "target": target, "kind": artifact["kind"], "roles": artifact["roles"],
                            "version": record["version"], "distribution": record["distribution"]}
                previous = entry["files"].get(artifact["name"])
                if previous is not None and previous != metadata:
                    raise PublicationError("catalog archive conflicts with retained history")
                entry["files"][artifact["name"]] = metadata
    for release in releases.values():
        entry = apps[release["app"]]["channels"][release["channel"]]
        for target, target_record in release["receipt"]["targets"].items():
            current = entry["targets"].get(target)
            if current is None or _version_tuple(release["version"]) > _version_tuple(current["version"]):
                entry["targets"][target] = {
                    "version": release["version"], "feed": release["feed"],
                    "distribution": release["distribution"],
                    "files": sorted(a["name"] for a in target_record["artifacts"] if "installer" in a["roles"]),
                }
            elif (release["version"] == current["version"]
                  and (current["feed"] != release["feed"] or current["distribution"] != release["distribution"])):
                raise PublicationError("current target has conflicting equal-version feed identities")
    for entry in apps.values():
        for channel_entry in entry["channels"].values():
            versions = {item["version"] for item in channel_entry["targets"].values()}
            # Keep the legacy single version only when it is actually true for all targets.
            channel_entry.pop("version", None)
            if len(versions) == 1:
                channel_entry["version"] = next(iter(versions))
    return _canonical({"schema": "lapkb-downloads-v1", "apps": apps}) + b"\n"


def _human_size(size):
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _render_index(catalog):
    links, archives = [], []
    for app, app_entry in sorted(catalog["apps"].items()):
        for channel, entry in sorted(app_entry["channels"].items()):
            current_names = set()
            for target, current in sorted(entry["targets"].items()):
                for name in current["files"]:
                    artifact = entry["files"][name]
                    current_names.add(name)
                    signed_status = ("Minisign-verified installer" if "updater" in artifact.get("roles", [])
                                     else "authenticated release metadata / installer checksum")
                    status = {"signed": signed_status,
                              "manual-checksum": "manual / checksum only; no updater signature or self-update",
                              "observed-history": "retained historical feed; not newly re-attested"}[current["distribution"]]
                    kind = artifact.get("kind", "historical archive")
                    label = (f"{contract.DISPLAY_NAMES[app]} {current['version']} — {channel} — {target} — "
                             f"{kind} — {_human_size(artifact['size'])} — {status}")
                    links.append(_download_link(app, channel, name, label, artifact["sha256"]))
            for name, artifact in sorted(entry["files"].items()):
                if name in current_names:
                    continue
                status = ("retained release archive" if "distribution" in artifact
                          else "retained historical archive; no new signature/provenance claim")
                label = f"{contract.DISPLAY_NAMES[app]} — {channel} — {name} — {status}"
                archives.append(_download_link(app, channel, name, label, artifact["sha256"]))
    body = "\n".join(links) if links else "<li>No downloads are published yet.</li>"
    archive_body = "\n".join(archives) if archives else "<li>No older catalog archives.</li>"
    page = f'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LAPKB downloads</title>
<style>
:root {{ color-scheme: light dark; }}
body {{ font: 16px/1.5 -apple-system, system-ui, sans-serif; margin: 0 auto; max-width: 52rem; padding: 3rem 1.25rem; }}
h1 {{ font-size: 1.6rem; margin: 0 0 .25rem; }}
p.lede {{ margin: 0 0 2rem; opacity: .75; }}
ul {{ list-style: none; margin: 0; padding: 0; }}
li {{ padding: .9rem 0; border-top: 1px solid rgba(128,128,128,.35); }}
li a {{ text-decoration: none; font-weight: 600; }}
li a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>
<h1>LAPKB downloads</h1>
<p class="lede">Current downloads by target. Manual/checksum and observed historical entries are labeled separately; a checksum is not a signature.</p>
<ul>
{body}
</ul>
<h2>Retained archives</h2>
<ul>
{archive_body}
</ul>
</body>
</html>
'''
    return page.encode("utf-8")


def _download_link(app, channel, name, label, digest):
    href = f"/downloads/{quote(app, safe='-')}/{quote(channel, safe='-')}/{quote(name, safe='-._')}"
    return ("<li><a href=\"" + html.escape(href, quote=True) + "\">" + html.escape(label, quote=True)
            + "</a><br><small>SHA-256: " + html.escape(digest, quote=True) + "</small></li>")


def _outputs(releases, state):
    catalog = _render_catalog(releases, state)
    index = _render_index(json.loads(catalog))
    if len(catalog) > MAX_CATALOG_BYTES or len(index) > MAX_INDEX_BYTES:
        raise PublicationError("generated catalog or downloads page exceeds its size limit")
    return catalog, index


def _bootstrap_check(fs, policy):
    directories = ["downloads"]
    directories.extend(sorted({alias for channels in policy.legacy_aliases.values()
                               for alias in channels.values() if alias is not None}))
    for name in directories:
        try:
            directory_fd = fs.directory([name])
        except PublicationError as error:
            if "required publisher directory is missing" in str(error):
                continue
            raise
        try:
            if os.listdir(directory_fd):
                raise PublicationError(
                    "existing public downloads or legacy feeds require a reviewed bootstrap/migration; "
                    "automatic adoption is disabled"
                )
        finally:
            os.close(directory_fd)


def _check_live_outputs(fs, releases, state):
    # Protected initialization deliberately retains the original page/catalog bytes.
    if state["historical"] is not None and not state["history"]:
        return
    downloads_fd = fs.directory(["downloads"])
    try:
        expected_catalog, expected_index = _outputs(releases, state)
        if _read_at(downloads_fd, "catalog.json", MAX_CATALOG_BYTES) != expected_catalog:
            raise PublicationError("published catalog differs from validated release history")
        if _read_at(downloads_fd, "index.html", MAX_INDEX_BYTES) != expected_index:
            raise PublicationError("published downloads page differs from validated release history")
    finally:
        os.close(downloads_fd)


def _validate_committed_state(fs, policy, state, verifier=contract.VERIFIER_PATH):
    if state is None:
        _bootstrap_check(fs, policy)
        return {}
    _verify_historical(fs, state, policy)
    for record in state["history"]:
        directory = fs.directory(["downloads", record["app"], record["channel"]])
        try:
            for item in record["inventory"]:
                if item["name"] != record["feed"] and _hash_at(directory, item["name"]) != (item["size"], item["sha256"]):
                    raise PublicationError("retained release asset differs from durable history")
        finally:
            os.close(directory)
    releases = _current_releases(policy, fs, state, verifier=verifier)
    _check_live_outputs(fs, releases, state)
    return releases


def _read_state_bytes(state_fd, policy):
    data = _read_at(state_fd, STATE_FILE, MAX_STATE_BYTES, required=False)
    if data is None:
        return None
    return data, _validate_state(data, policy)


def _make_plan_files(state, release, releases):
    catalog, index = _outputs(releases, state)
    state_bytes = _canonical(state)
    plan_files = {
        release["feed"]: release["manifestBytes"],
        "state.json": state_bytes,
        "catalog.json": catalog,
        "index.html": index,
    }
    if len(state_bytes) > MAX_STATE_BYTES:
        raise PublicationError("publisher release history exceeds its size limit")
    return plan_files


def _make_transaction(state_fd, app, channel, release, state, plan_files, staging_name):
    txn_name = f"txn-{secrets.token_hex(16)}"
    os.mkdir(txn_name, 0o700, dir_fd=state_fd)
    _fsync(state_fd)
    txn_fd = os.open(txn_name, _DIR_FLAGS, dir_fd=state_fd)
    try:
        descriptors = {}
        for name, data in plan_files.items():
            maximum = {
                release["feed"]: contract.MAX_MANIFEST_BYTES,
                "state.json": MAX_STATE_BYTES,
                "catalog.json": MAX_CATALOG_BYTES,
                "index.html": MAX_INDEX_BYTES,
            }[name]
            if len(data) > maximum:
                raise PublicationError(f"pending publication file exceeds its bound: {name}")
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                         _PRIVATE_MODE, dir_fd=txn_fd)
            try:
                view = memoryview(data)
                while view:
                    count = os.write(fd, view)
                    view = view[count:]
                _fsync(fd)
            finally:
                os.close(fd)
            descriptors[name] = {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        plan = {
            "schema": PLAN_SCHEMA, "app": app, "channel": channel,
            "version": release["version"], "inventoryDigest": release["inventoryDigest"],
            "coverage": release["coverage"], "feed": release["feed"],
            "targets": release["targets"], "distribution": release["distribution"],
            "legacyAlias": release["legacy"], "files": descriptors,
        }
        plan_bytes = _canonical(plan)
        fd = os.open("plan.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                     _PRIVATE_MODE, dir_fd=txn_fd)
        try:
            view = memoryview(plan_bytes)
            while view:
                count = os.write(fd, view)
                view = view[count:]
            _fsync(fd)
        finally:
            os.close(fd)
        _fsync(txn_fd)
        _checkpoint("transaction")
    finally:
        os.close(txn_fd)
    if not _STAGE_NAME.fullmatch(staging_name):
        raise PublicationError("publication staging name is invalid")
    journal = {
        "schema": JOURNAL_SCHEMA, "transaction": txn_name, "staging": staging_name,
        "app": app, "channel": channel, "version": release["version"],
        "coverage": release["coverage"], "feed": release["feed"],
        "targets": release["targets"], "distribution": release["distribution"],
        "inventoryDigest": release["inventoryDigest"],
    }
    journal_bytes = _canonical(journal)
    if len(journal_bytes) > MAX_JOURNAL_BYTES:
        raise PublicationError("publication journal exceeds its bound")
    _write_new(state_fd, JOURNAL_FILE, journal_bytes, _PRIVATE_MODE)
    return txn_name


def _write_new(dir_fd, name, data, mode):
    if not _SAFE_NAME.fullmatch(name):
        raise PublicationError("publisher internal name is unsafe")
    _cleanup_file_temps(dir_fd)
    if _stat_at(dir_fd, name) is not None:
        raise PublicationError("publisher internal file already exists")
    temp = _write_temp(dir_fd, data, mode)
    try:
        os.link(temp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd, follow_symlinks=False)
        _fsync(dir_fd)
    finally:
        try:
            os.unlink(temp, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
        _fsync(dir_fd)


def _read_transaction(state_fd, txn_name, policy):
    if not _TXN_NAME.fullmatch(txn_name):
        raise PublicationError("publication journal points outside owned transaction state")
    txn_fd = os.open(txn_name, _DIR_FLAGS, dir_fd=state_fd)
    try:
        info = os.fstat(txn_fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PublicationError("publication transaction directory permissions are unsafe")
        plan_bytes = _read_at(txn_fd, "plan.json", 4096)
        plan = contract.strict_json(plan_bytes, 4096, "publication transaction plan")
        if type(plan) is not dict or contract.canonical_json(plan) != plan_bytes:
            raise PublicationError("publication transaction plan is not canonical")
        expected = {"schema", "app", "channel", "version", "inventoryDigest", "legacyAlias", "files",
                    "coverage", "feed", "targets", "distribution"}
        if set(plan) != expected or plan["schema"] != PLAN_SCHEMA:
            raise PublicationError("publication transaction plan has an unexpected shape")
        if (type(plan["app"]) is not str or plan["app"] not in contract.APP_IDS
                or type(plan["channel"]) is not str or plan["channel"] not in contract.CHANNELS
                or type(plan["version"]) is not str):
            raise PublicationError("publication transaction identity is invalid")
        _version_tuple(plan["version"])
        if (type(plan["inventoryDigest"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", plan["inventoryDigest"])):
            raise PublicationError("publication transaction digest is invalid")
        if plan["legacyAlias"] is not None and type(plan["legacyAlias"]) is not str:
            raise PublicationError("publication transaction legacy alias is invalid")
        _validate_scope(plan, policy)
        expected_files = {plan["feed"], "state.json", "catalog.json", "index.html"}
        if type(plan["files"]) is not dict or set(plan["files"]) != expected_files:
            raise PublicationError("publication transaction file set is incomplete")
        if set(os.listdir(txn_fd)) != expected_files | {"plan.json"}:
            raise PublicationError("publication transaction contains unexpected files")
        limits = {plan["feed"]: contract.MAX_MANIFEST_BYTES, "state.json": MAX_STATE_BYTES,
                  "catalog.json": MAX_CATALOG_BYTES, "index.html": MAX_INDEX_BYTES}
        contents = {}
        for name, maximum in limits.items():
            value = _read_at(txn_fd, name, maximum)
            item = plan["files"][name]
            if type(item) is not dict or set(item) != {"size", "sha256"}:
                raise PublicationError("publication transaction digest record is malformed")
            if (type(item["size"]) is not int or item["size"] != len(value)
                    or type(item["sha256"]) is not str
                    or item["sha256"] != hashlib.sha256(value).hexdigest()):
                raise PublicationError("publication transaction file digest does not match")
            contents[name] = value
        return plan, contents
    finally:
        os.close(txn_fd)


def _release_for_transaction(policy, fs, state_fd, plan, contents, staging_name,
                              verifier=contract.VERIFIER_PATH):
    app, channel = plan["app"], plan["channel"]
    _validate_scope(plan, policy)
    expected_alias = None if plan["coverage"] == "windows-x64" else policy.legacy_aliases[app][channel]
    if plan["legacyAlias"] != expected_alias:
        raise PublicationError("publication transaction legacy alias differs from trusted config")
    state_bytes = contents["state.json"]
    state = _validate_state(state_bytes, policy)
    entry = next((item for item in state["history"]
                  if _scope_key(item) == _scope_key(plan)
                  and item["version"] == plan["version"]), None)
    if entry is None or entry["inventoryDigest"] != plan["inventoryDigest"]:
        raise PublicationError("pending state does not contain its journaled release")
    prior = _load_state(state_fd, policy)
    if prior != state:
        expected_prior = {**state, "history": [record for record in state["history"] if record != entry]}
        if prior is None:
            if expected_prior != {"schema": STATE_SCHEMA, "history": [], "historical": None}:
                raise PublicationError("journal recovery may not adopt historical state")
        elif prior != expected_prior:
            raise PublicationError("journaled state does not extend the exact committed history")
        _check_versions(prior, entry)
    _verify_historical(fs, state, policy)
    if not _STAGE_NAME.fullmatch(staging_name):
        raise PublicationError("publication journal staging reference is invalid")
    stage_fd = os.open(staging_name, _DIR_FLAGS, dir_fd=state_fd)
    try:
        stage_info = os.fstat(stage_fd)
        if stage_info.st_uid != os.geteuid() or stage_info.st_mode & 0o077:
            raise PublicationError("pending release staging directory is unsafe")
        expected_names = {item["name"] for item in entry["inventory"]}
        if set(os.listdir(stage_fd)) != expected_names:
            raise PublicationError("pending release staging inventory is incomplete or unexpected")
        for name in expected_names:
            item_info = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
            if (not stat.S_ISREG(item_info.st_mode) or item_info.st_uid != os.geteuid()
                    or item_info.st_nlink != 1 or item_info.st_mode & 0o077):
                raise PublicationError("pending staged release contains an unsafe file")
        stage_path = policy_path(policy, STATE_NAME, staging_name)
        files = {name: stage_path / name for name in expected_names}
        try:
            release = contract.validate_release(app, channel, files, policy,
                                                verifier=verifier, scratch=stage_path)
        except ContractError as error:
            raise PublicationError(str(error)) from error
        if (release["version"] != plan["version"] or release["inventoryDigest"] != plan["inventoryDigest"]
                or _scope_key(release) != _scope_key(plan)
                or release["distribution"] != plan["distribution"]
                or release["manifestBytes"] != contents[plan["feed"]]
                or _record_from_release(release) != entry):
            raise PublicationError("journaled release does not match its signed staged bytes")
    finally:
        os.close(stage_fd)

    target_fd = fs.directory(["downloads", app, channel], create=True)
    try:
        for item in release["inventory"]:
            name = item["name"]
            if name == release["feed"]:
                continue
            created = _promote_immutable(files[name], target_fd, name, item["size"], item["sha256"])
            if created:
                _checkpoint("asset:" + name)
    finally:
        os.close(target_fd)
    if release["legacy"] is not None:
        alias_fd = fs.directory([release["legacy"]], create=True)
        try:
            for target_record in release["receipt"]["targets"].values():
                for artifact in target_record["artifacts"]:
                    _copy_immutable_alias(files[artifact["name"]], alias_fd, artifact["name"],
                                          artifact["size"], artifact["sha256"])
                    _checkpoint("legacy:" + artifact["name"])
        finally:
            os.close(alias_fd)
    _verify_alias_assets_before_commit(fs, release)
    releases = _current_releases(policy, fs, state, override=release, verifier=verifier)
    catalog, index = _outputs(releases, state)
    if contents["catalog.json"] != catalog or contents["index.html"] != index:
        raise PublicationError("journaled catalog or index is not derived from validated current releases")
    return state, release, contents


def _verify_alias_assets_before_commit(fs, release):
    alias = release["legacy"]
    if alias is None:
        return
    alias_fd = fs.directory([alias], create=True)
    try:
        package_names = {
            artifact["name"]
            for target in release["receipt"]["targets"].values()
            for artifact in target["artifacts"]
        }
        for item in release["inventory"]:
            name = item["name"]
            if name not in package_names:
                continue
            size, digest = _hash_at(alias_fd, name)
            if (size, digest) != (item["size"], item["sha256"]):
                raise PublicationError("legacy release asset is missing or differs from canonical bytes")
    finally:
        os.close(alias_fd)


def _apply_pending(fs, state_fd, journal, plan, contents, policy):
    _validate_scope(plan, policy)
    expected_alias = None if plan["coverage"] == "windows-x64" else policy.legacy_aliases[plan["app"]][plan["channel"]]
    if plan["legacyAlias"] != expected_alias:
        raise PublicationError("pending apply alias differs from the fixed coverage policy")
    for key in ("app", "channel", "version", "inventoryDigest", "coverage", "feed", "targets", "distribution"):
        if journal[key] != plan[key]:
            raise PublicationError("pending apply journal and plan disagree")
    txn_fd = os.open(journal["transaction"], _DIR_FLAGS, dir_fd=state_fd)
    try:
        app, channel, alias = plan["app"], plan["channel"], plan["legacyAlias"]
        target_fd = fs.directory(["downloads", app, channel], create=True)
        try:
            _replace_at(target_fd, plan["feed"], contents[plan["feed"]], _PUBLIC_MODE)
            _checkpoint("feed:" + plan["feed"])
        finally:
            os.close(target_fd)
        if alias is not None:
            alias_fd = fs.directory([alias], create=True)
            try:
                _replace_at(alias_fd, "latest.json", contents[plan["feed"]], _PUBLIC_MODE)
                _checkpoint("feed:legacy")
            finally:
                os.close(alias_fd)
        _replace_at(state_fd, STATE_FILE, contents["state.json"], _PRIVATE_MODE)
        _checkpoint("state")
        downloads_fd = fs.directory(["downloads"], create=True)
        try:
            _replace_at(downloads_fd, "catalog.json", contents["catalog.json"], _PUBLIC_MODE)
            _checkpoint("catalog")
            _replace_at(downloads_fd, "index.html", contents["index.html"], _PUBLIC_MODE)
            _checkpoint("index")
        finally:
            os.close(downloads_fd)
    finally:
        os.close(txn_fd)
    os.unlink(JOURNAL_FILE, dir_fd=state_fd)
    _fsync(state_fd)
    _checkpoint("journal-cleared")
    _remove_stage_dir(state_fd, journal["transaction"])
    _remove_stage_dir(state_fd, journal["staging"])


def _checkpoint(boundary):
    """Internal no-op boundary, replaced only by in-process fault-injection tests."""


def _recover_locked(fs, state_fd, policy, verifier=contract.VERIFIER_PATH,
                    verify_committed=True):
    # A crash between link(create-new intent) and unlink(temp) can leave the
    # journal with two links. Remove only dead owned temp names first; strict
    # single-link journal/state validation remains unchanged.
    _cleanup_file_temps(state_fd)
    journal_bytes = _read_at(state_fd, JOURNAL_FILE, MAX_JOURNAL_BYTES, required=False)
    if journal_bytes is not None:
        journal = contract.strict_json(journal_bytes, MAX_JOURNAL_BYTES, "publication journal")
        if (type(journal) is not dict or contract.canonical_json(journal) != journal_bytes
                or set(journal) != {"schema", "transaction", "staging", "app", "channel", "version", "inventoryDigest",
                                    "coverage", "feed", "targets", "distribution"}
                or journal["schema"] != JOURNAL_SCHEMA):
            raise PublicationError("publication journal is invalid; manual review is required")
        if (type(journal["transaction"]) is not str or not _TXN_NAME.fullmatch(journal["transaction"])
                or type(journal["staging"]) is not str or not _STAGE_NAME.fullmatch(journal["staging"])
                or type(journal["app"]) is not str or journal["app"] not in contract.APP_IDS
                or type(journal["channel"]) is not str or journal["channel"] not in contract.CHANNELS
                or type(journal["version"]) is not str
                or type(journal["inventoryDigest"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", journal["inventoryDigest"])):
            raise PublicationError("publication journal fields are invalid")
        _version_tuple(journal["version"])
        _validate_scope(journal, policy)
        _cleanup_owned_temporary_state(state_fd, keep_stage=journal["staging"],
                                       keep_txn=journal["transaction"])
        plan, contents = _read_transaction(state_fd, journal["transaction"], policy)
        for key in ("app", "channel", "version", "inventoryDigest", "coverage", "feed", "targets", "distribution"):
            if plan[key] != journal[key]:
                raise PublicationError("publication journal and transaction disagree")
        plan["transaction"] = journal["transaction"]
        _release_for_transaction(policy, fs, state_fd, plan, contents,
                                 journal["staging"], verifier)
        _apply_pending(fs, state_fd, journal, plan, contents, policy)
    else:
        _cleanup_owned_temporary_state(state_fd)
    loaded = _read_state_bytes(state_fd, policy)
    state = loaded[1] if loaded is not None else None
    if verify_committed:
        _validate_committed_state(fs, policy, state, verifier=verifier)
    elif state is None:
        _bootstrap_check(fs, policy)
    return state


def recover_publications(policy: Policy, verifier=contract.VERIFIER_PATH,
                         verify_committed=True):
    """Durably finish any interrupted commit before pickup reports no work."""
    with RootFS(policy.root) as fs:
        with _publication_lock(fs) as state_fd:
            _recover_locked(fs, state_fd, policy, verifier=verifier,
                            verify_committed=verify_committed)


def _validate_staging_files(policy, state_fd, staging_name, files):
    if type(staging_name) is not str or not _STAGE_NAME.fullmatch(staging_name):
        raise PublicationError("release staging name is invalid")
    if type(files) is not dict or not 1 <= len(files) <= contract.MAX_FILES:
        raise PublicationError("release staging inventory count is invalid")
    stage_fd = os.open(staging_name, _DIR_FLAGS, dir_fd=state_fd)
    try:
        info = os.fstat(stage_fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PublicationError("release staging directory permissions are unsafe")
        names = set(os.listdir(stage_fd))
        if names != set(files):
            raise PublicationError("release staging contains missing or unexpected files")
        for name in names:
            info = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077):
                raise PublicationError("release staging contains a link, special file, or non-private file")
        expected_parent = policy_path(policy, STATE_NAME, staging_name)
        for name, path in files.items():
            if (type(name) is not str or not _SAFE_NAME.fullmatch(name)
                    or not isinstance(path, Path) or path.parent != expected_parent
                    or path.name != name):
                raise PublicationError("release files must come from this publisher's owned staging directory")
    finally:
        os.close(stage_fd)


def _check_versions(state, incoming):
    """Monotonic per target and fixed feed; equal versions require the exact record."""
    if state is None:
        return False
    same = next((record for record in state["history"]
                 if _scope_key(record) == _scope_key(incoming)
                 and record["version"] == incoming["version"]), None)
    if same is not None and same != incoming:
        raise PublicationError("same-version release conflicts with durable publication history")
    currents = list(_latest_by_app_channel(state).values())
    if state["historical"]:
        currents.extend({**item, "targets": [item["target"]], "versionTuple": list(_version_tuple(item["version"]))}
                        for item in state["historical"]["current"])
    for previous in currents:
        if (previous["app"] != incoming["app"] or previous["channel"] != incoming["channel"]
                or not set(previous["targets"]) & set(incoming["targets"])):
            continue
        current_version, incoming_version = tuple(previous["versionTuple"]), tuple(incoming["versionTuple"])
        if incoming_version < current_version:
            raise PublicationError("stale release retry cannot roll back a current target/feed")
        if incoming_version == current_version and previous != incoming:
            raise PublicationError("same-version release conflicts with the current target/feed identity")
    return same is not None


def _preflight_immutable(fs, release):
    try:
        target_fd = fs.directory(["downloads", release["app"], release["channel"]])
    except PublicationError as error:
        if "required publisher directory is missing" in str(error):
            return
        raise
    try:
        for item in release["inventory"]:
            if item["name"] == release["feed"]:
                continue
            if _stat_at(target_fd, item["name"]) is not None and _hash_at(target_fd, item["name"]) != (item["size"], item["sha256"]):
                raise PublicationError("same-version immutable metadata/asset conflicts with retained bytes")
    finally:
        os.close(target_fd)


def _publication_result(release, status):
    return {"status": status, **{key: release[key] for key in (
        "app", "channel", "version", "coverage", "feed", "targets", "distribution",
        "inventoryDigest", "inventory")}}


def publish_files(policy: Policy, app: str, channel: str, files: dict[str, Path],
                  staging_name: str, verifier: Path = contract.VERIFIER_PATH):
    """Publish one exact configured scope using the single journal/recovery path.

    This is an ordered, recoverable multi-file commit, not an atomic transaction
    across public files. The fixed feed is mutable and is never an immutable asset.
    """
    verifier = Path(verifier)
    with RootFS(policy.root) as fs:
        with _publication_lock(fs) as state_fd:
            state = _recover_locked(fs, state_fd, policy, verifier=verifier, verify_committed=False)
            committed = _validate_committed_state(fs, policy, state, verifier=verifier)
            _validate_staging_files(policy, state_fd, staging_name, files)
            try:
                release = contract.validate_release(app, channel, files, policy, verifier=verifier,
                    scratch=policy_path(policy, STATE_NAME, staging_name))
            except ContractError as error:
                raise PublicationError(str(error)) from error
            candidate_record = _record_from_release(release)
            if _check_versions(state, candidate_record):
                return _publication_result(release, "identical-retry")
            _preflight_immutable(fs, release)
            history = list(state["history"] if state else [])
            if len(history) >= MAX_HISTORY:
                raise PublicationError("publisher history is full; reviewed archival is required")
            history.append(candidate_record)
            history.sort(key=_history_sort)
            tentative_state = {"schema": STATE_SCHEMA, "history": history,
                               "historical": state["historical"] if state else None}
            _validate_state(_canonical(tentative_state), policy)
            candidate_current = dict(committed)
            candidate_current[_scope_key(release)] = release
            plan_files = _make_plan_files(tentative_state, release, candidate_current)
            txn_name = _make_transaction(state_fd, app, channel, release, tentative_state, plan_files, staging_name)
            _checkpoint("journal")
            journal_bytes = _read_at(state_fd, JOURNAL_FILE, MAX_JOURNAL_BYTES)
            journal = contract.strict_json(journal_bytes, MAX_JOURNAL_BYTES, "publication journal")
            plan, contents = _read_transaction(state_fd, txn_name, policy)
            _release_for_transaction(policy, fs, state_fd, plan, contents, staging_name, verifier)
            _apply_pending(fs, state_fd, journal, plan, contents, policy)
            return _publication_result(release, "published")


def _frame_receiver(policy, stream):
    recover_publications(policy, verify_committed=False)
    staging_name, staging_path = create_staging(policy)
    try:
        app, channel, files = read_payload(stream, staging_path)
        return app, channel, files, staging_name
    except BaseException:
        remove_staging(policy, staging_name)
        raise


def receive_main():
    # This local-only administrative command is not accepted by the forced SSH
    # wrapper and is never reached by ordinary receive or scheduled pickup.
    if (len(sys.argv) == 6 and sys.argv[1] == "--initialize-history-v1"
            and sys.argv[2] == "--inventory" and sys.argv[4] == "--sha256"):
        try:
            result = initialize_history(contract.load_policy(), Path(sys.argv[3]), sys.argv[5])
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        except (ContractError, PublicationError, OSError) as error:
            print(f"publisher history initialization rejected: {error}", file=sys.stderr)
            return 1
    if len(sys.argv) != 2 or sys.argv[1] != "--receive-v1":
        print("publisher accepts only the fixed framed receive command", file=sys.stderr)
        return 64
    try:
        policy = contract.load_policy()
        app, channel, files, staging_name = _frame_receiver(policy, sys.stdin.buffer)
        try:
            result = publish_files(policy, app, channel, files, staging_name)
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0
        finally:
            remove_staging(policy, staging_name)
    except (ContractError, PublicationError, OSError) as error:
        print(f"publisher rejected release: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(receive_main())
