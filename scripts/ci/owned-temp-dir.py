#!/usr/bin/env python3
import os
import pathlib
import shutil
import stat
import sys


def refuse(reason):
    print(f"Refusing temporary-directory operation: {reason}", file=sys.stderr)
    return 1


def validated(root_value, path_value, prefix, identity, allow_root_owner=False):
    try:
        root = pathlib.Path(root_value).resolve(strict=True)
        root_info = os.lstat(root)
        if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
                or root_info.st_uid != os.getuid()):
            return None, "temporary root is not a runner-owned directory"
        path = pathlib.Path(path_value)
        if (not path.is_absolute() or path.parent != root
                or not path.name.startswith(prefix + ".")):
            return None, "path is outside the expected temporary-directory prefix"
        info = os.lstat(path)
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or path.resolve(strict=True) != path):
            return None, "path is not a real directory"
        if info.st_dev != root_info.st_dev:
            return None, "path is on a different device"
        if identity != f"{info.st_dev}:{info.st_ino}":
            return None, "directory identity changed"
        owners = {os.getuid(), 0} if allow_root_owner else {os.getuid()}
        if info.st_uid not in owners:
            return None, "directory is not owned by this runner"
        if stat.S_IMODE(info.st_mode) != 0o700:
            return None, "directory permissions changed"
        return (root, path, root_info, info), None
    except (OSError, ValueError):
        return None, "path or identity could not be validated"


def main():
    if len(sys.argv) not in (6, 7):
        return refuse("usage: owned-temp-dir.py validate|cleanup RUNNER_TEMP PATH PREFIX DEVICE:INODE [runner|root-or-runner]")
    operation, root_value, path_value, prefix, identity = sys.argv[1:6]
    ownership_mode = sys.argv[6] if len(sys.argv) == 7 else "runner"
    if ownership_mode not in ("runner", "root-or-runner"):
        return refuse("invalid ownership mode")
    allow_root_owner = ownership_mode == "root-or-runner"
    if operation == "cleanup" and path_value == "" and identity == "":
        return 0
    if operation not in ("validate", "cleanup"):
        return refuse("unknown operation")
    if not path_value or not identity:
        return refuse("path and directory identity must be supplied together")
    result, error = validated(root_value, path_value, prefix, identity, allow_root_owner)
    if error:
        return refuse(error)
    if operation == "validate":
        return 0
    if allow_root_owner or result[3].st_uid != os.getuid():
        return refuse("cleanup requires runner ownership")
    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        return refuse("platform cannot safely remove a directory tree")

    root, path, root_info, info = result
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(root, flags)
        try:
            opened_root = os.fstat(root_fd)
            if (opened_root.st_dev, opened_root.st_ino) != (root_info.st_dev, root_info.st_ino):
                return refuse("temporary root changed during cleanup")
            current = os.stat(path.name, dir_fd=root_fd, follow_symlinks=False)
            if (not stat.S_ISDIR(current.st_mode) or stat.S_ISLNK(current.st_mode)
                    or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
                    or current.st_uid != os.getuid() or stat.S_IMODE(current.st_mode) != 0o700):
                return refuse("directory changed before cleanup")
            # Python 3.8 on the approved runners has fd-safe rmtree but no
            # dir_fd argument. Anchor its relative path to the opened root in
            # this single-threaded helper; never fall back to an absolute path.
            previous_cwd = os.open(".", flags)
            try:
                os.fchdir(root_fd)
                shutil.rmtree(path.name)
            finally:
                os.fchdir(previous_cwd)
                os.close(previous_cwd)
        finally:
            os.close(root_fd)
    except OSError:
        return refuse("validated directory could not be removed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
