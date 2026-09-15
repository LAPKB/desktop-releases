"""Remote half of the LAPKB publish pipeline. Runs on the download origin.

Invoked by the publisher client (directly with a workstation key, or through
the forced-command wrapper for the restricted CI key). Reads a size-framed
payload from stdin, writes the release files, mirrors the legacy manifest path,
and rewrites the catalog.
"""
import hashlib
import json
import os
import re
import sys
from pathlib import Path

APP = re.compile(r'^[a-z][a-z0-9-]{1,31}$')
CHANNEL = re.compile(r'^[a-z][a-z0-9-]{0,31}$')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    if len(sys.argv) not in (4, 5):
        print('usage: publish-remote.py <root> <app> <channel> [legacy]', file=sys.stderr)
        return 64
    public = Path(sys.argv[1])
    app, channel = sys.argv[2], sys.argv[3]
    legacy = sys.argv[4] if len(sys.argv) == 5 and sys.argv[4] else None
    if not APP.fullmatch(app) or not CHANNEL.fullmatch(channel):
        print('unexpected app or channel', file=sys.stderr)
        return 64
    if legacy and not APP.fullmatch(legacy):
        print('unexpected legacy path', file=sys.stderr)
        return 64
    downloads = public / 'downloads'
    target = downloads / app / channel
    target.mkdir(parents=True, exist_ok=True)

    def store(name, size):
        path = target / name
        remaining = size
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'wb') as output:
            while remaining > 0:
                chunk = sys.stdin.buffer.read(min(65536, remaining))
                if not chunk:
                    raise SystemExit('truncated payload for ' + name)
                output.write(chunk)
                remaining -= len(chunk)
            output.flush()
            os.fsync(output.fileno())
        return path

    def mirror(source):
        if not legacy:
            return
        destination = public / legacy
        destination.mkdir(parents=True, exist_ok=True)
        fd = os.open(destination / source.name,
                     os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, 'wb') as output:
            output.write(source.read_bytes())

    try:
        entries = json.loads(sys.stdin.buffer.readline())
    except ValueError:
        print('publisher payload is not JSON', file=sys.stderr)
        return 65
    for name, size in entries:
        if name != 'latest.json' and not re.fullmatch(r'[A-Za-z0-9._-]{1,160}', name):
            print('unexpected file name', file=sys.stderr)
            return 64
        path = store(name, size)
        if name != 'latest.json':
            mirror(path)
    if legacy:
        mirror(target / 'latest.json')

    catalog = {'schema': 'lapkb-downloads-v1', 'apps': {}}
    for app_dir in sorted(p for p in downloads.iterdir() if p.is_dir()):
        detail = {'channels': {}}
        for channel_dir in sorted(p for p in app_dir.iterdir() if p.is_dir()):
            files = {}
            version = ''
            manifest = channel_dir / 'latest.json'
            if manifest.is_file():
                try:
                    parsed = json.loads(manifest.read_text())
                    version = str(parsed.get('version', ''))
                except ValueError:
                    version = ''
            for item in sorted(channel_dir.iterdir()):
                if item.is_file() and item.name != 'latest.json':
                    files[item.name] = {'sha256': digest(item), 'size': item.stat().st_size}
            detail['channels'][channel_dir.name] = {'version': version, 'files': files}
        catalog['apps'][app_dir.name] = detail
    fd = os.open(downloads / 'catalog.json',
                 os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'w') as output:
        json.dump(catalog, output, indent=2, sort_keys=True)
        output.write('\n')
    print(json.dumps({'written': [name for name, _ in entries], 'catalog': sorted(catalog['apps'])}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
