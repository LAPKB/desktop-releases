"""Remote half of the LAPKB publish pipeline.

Two entry points share one implementation:
  * stdin payload (used by a trusted workstation over ssh)
  * direct call (used by the on-host pickup job that polls staged releases)

Writes release files under ``<root>/downloads/<app>/<channel>/``, mirrors the
legacy manifest path, and rewrites ``downloads/catalog.json``.
"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path

APP = re.compile(r'^[a-z][a-z0-9-]{1,31}$')
CHANNEL = re.compile(r'^[a-z][a-z0-9-]{0,31}$')
FILE = re.compile(r'^[A-Za-z0-9._-]{1,160}$')


def digest_bytes(data):
    return hashlib.sha256(data).hexdigest()


def digest_file(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def validate(app, channel, legacy):
    if not APP.fullmatch(app) or not CHANNEL.fullmatch(channel):
        raise SystemExit('unexpected app or channel')
    if legacy and not APP.fullmatch(legacy):
        raise SystemExit('unexpected legacy path')


def publish_files(root, app, channel, legacy, files):
    """files: ordered mapping of name -> bytes, latest.json last."""
    public = Path(root)
    downloads = public / 'downloads'
    target = downloads / app / channel
    target.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        if not FILE.fullmatch(name):
            raise SystemExit('unexpected file name')
        path = target / name
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        if legacy and name != 'latest.json':
            destination = public / legacy
            destination.mkdir(parents=True, exist_ok=True)
            fd = os.open(destination / name,
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
            with os.fdopen(fd, 'wb') as output:
                output.write(data)
    if legacy:
        source = target / 'latest.json'
        destination = public / legacy
        destination.mkdir(parents=True, exist_ok=True)
        fd = os.open(destination / 'latest.json',
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'wb') as output:
            output.write(source.read_bytes())

    catalog = {'schema': 'lapkb-downloads-v1', 'apps': {}}
    for app_dir in sorted(p for p in downloads.iterdir() if p.is_dir()):
        detail = {'channels': {}}
        for channel_dir in sorted(p for p in app_dir.iterdir() if p.is_dir()):
            files_entry = {}
            version = ''
            manifest = channel_dir / 'latest.json'
            if manifest.is_file():
                try:
                    version = str(json.loads(manifest.read_text()).get('version', ''))
                except ValueError:
                    version = ''
            for item in sorted(channel_dir.iterdir()):
                if item.is_file() and item.name != 'latest.json':
                    files_entry[item.name] = {'sha256': digest_file(item),
                                              'size': item.stat().st_size}
            detail['channels'][channel_dir.name] = {'version': version, 'files': files_entry}
        catalog['apps'][app_dir.name] = detail
    fd = os.open(downloads / 'catalog.json',
                 os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'w') as output:
        json.dump(catalog, output, indent=2, sort_keys=True)
        output.write('\n')
    return {'written': list(files), 'catalog': sorted(catalog['apps'])}


def read_payload():
    """Size-framed payload: <names/sizes json line><bytes in order>."""
    try:
        entries = json.loads(sys.stdin.buffer.readline())
    except ValueError:
        raise SystemExit('publisher payload is not JSON') from None
    files = {}
    for name, size in entries:
        chunks = []
        try:
            remaining = int(size)
        except (TypeError, ValueError):
            raise SystemExit('unexpected payload size') from None
        if remaining < 0:
            raise SystemExit('unexpected payload size')
        while remaining > 0:
            chunk = sys.stdin.buffer.read(min(65536, remaining))
            if not chunk:
                raise SystemExit('truncated payload for ' + name)
            chunks.append(chunk)
            remaining -= len(chunk)
        files[name] = b''.join(chunks)
    return files


def main():
    if len(sys.argv) not in (4, 5):
        print('usage: publish-remote.py <root> <app> <channel> [legacy]', file=sys.stderr)
        return 64
    root, app, channel = sys.argv[1], sys.argv[2], sys.argv[3]
    legacy = sys.argv[4] if len(sys.argv) == 5 and sys.argv[4] else None
    validate(app, channel, legacy)
    result = publish_files(root, app, channel, legacy, read_payload())
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    sys.exit(main())
