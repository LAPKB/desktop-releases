"""On-origin pickup job.

Polls LAPKB release staging for `publish-<app>-<channel>-<version>` releases,
verifies the staged files with the same rules the workstation publisher uses,
and publishes them locally. Intended to run from cron on the download origin,
so the origin stays pull-only and no CI runner needs network access to it.

Configuration (all optional except the release repository):
    ~/.config/lapkb/pickup.json    {"repository": "LAPKB/desktop-releases",
                                    "root": "/home/siel/.../edge/public",
                                    "legacy": {"papir": "papir", "launcher": "launcher"}}
    ~/.config/lapkb/pickup-token   fine-grained read-only token (0600, optional
                                   for public repositories)
    ~/.local/state/lapkb/pickup-state.json   processed release tags

Exit status is 0 for "nothing to do" and non-zero only for unexpected errors.
"""
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from publish_remote import publish_files, validate  # noqa: E402

CONFIG = Path.home() / '.config' / 'lapkb' / 'pickup.json'
TOKEN = Path.home() / '.config' / 'lapkb' / 'pickup-token'
STATE = Path.home() / '.local' / 'state' / 'lapkb' / 'pickup-state.json'
TAG = re.compile(r'^publish-([a-z][a-z0-9-]{1,31})-([a-z][a-z0-9-]{0,31})-'
                 r'((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))$')
CONTENT_ADDRESSED = re.compile(
    r'^[a-z0-9-]+-(\d+\.\d+\.\d+)-darwin-aarch64-([0-9a-f]{64})\.app\.tar\.gz$')
VERSIONED = re.compile(r'^[a-z0-9-]+-(\d+\.\d+\.\d+)-darwin-aarch64\.app\.zip$')


def api(path, token):
    request = urllib.request.Request('https://api.github.com' + path,
                                     headers={'Accept': 'application/vnd.github+json',
                                              'User-Agent': 'LAPKB-Pickup/1.0'})
    if token:
        request.add_header('Authorization', 'Bearer ' + token)
    with urllib.request.urlopen(request, timeout=60) as response:
        raw = response.read(4 * 1024 * 1024)
    try:
        return json.loads(raw)
    except ValueError:
        raise RuntimeError('GitHub API returned a non-JSON response') from None


def download(url, token, limit=512 * 1024 * 1024):
    request = urllib.request.Request(url, headers={'Accept': 'application/octet-stream',
                                                   'User-Agent': 'LAPKB-Pickup/1.0'})
    if token:
        request.add_header('Authorization', 'Bearer ' + token)
    with urllib.request.urlopen(request, timeout=600) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError('asset is larger than the accepted maximum')
    return data


def load_json(path, default):
    if not path.is_file():
        return default
    try:
        return json.loads(path.read_text())
    except ValueError:
        raise SystemExit(str(path) + ' is not valid JSON') from None


def main():
    config = load_json(CONFIG, {})
    repository = config.get('repository', 'LAPKB/desktop-releases')
    root = config.get('root')
    if not root:
        print('pickup is not configured; nothing to do')
        return 0
    legacy_for = config.get('legacy', {})
    token = TOKEN.read_text().strip() if TOKEN.is_file() else ''
    state = load_json(STATE, {'published': {}})
    published = state.setdefault('published', {})

    releases = api(f'/repos/{repository}/releases?per_page=50', token)
    pending = []
    for release in releases:
        tag = release.get('tag_name', '')
        if not TAG.fullmatch(tag) or tag in published:
            continue
        pending.append(release)
    if not pending:
        print('no staged releases pending')
        return 0

    changed = False
    for release in reversed(pending):
        tag = release['tag_name']
        match = TAG.fullmatch(tag)
        if match is None:
            continue
        app, channel, version = match.group(1), match.group(2), match.group(3)
        assets = {asset['name']: asset for asset in release.get('assets', [])}
        if 'latest.json' not in assets or len(assets) != 2:
            print(f'{tag}: skipped, expected exactly one artifact plus latest.json')
            continue
        artifact_name = next(name for name in assets if name != 'latest.json')
        manifest_bytes = download(assets['latest.json']['url'], token)
        artifact_bytes = download(assets[artifact_name]['url'], token)
        digest = hashlib.sha256(artifact_bytes).hexdigest()
        content = CONTENT_ADDRESSED.match(artifact_name)
        versioned = VERSIONED.match(artifact_name)
        if content:
            if content.group(1) != version or content.group(2) != digest:
                print(f'{tag}: skipped, artifact name does not match its bytes')
                continue
        elif versioned:
            if versioned.group(1) != version:
                print(f'{tag}: skipped, artifact name does not match the version')
                continue
        else:
            print(f'{tag}: skipped, unexpected artifact name')
            continue
        try:
            manifest = json.loads(manifest_bytes)
        except ValueError:
            print(f'{tag}: skipped, manifest is not JSON')
            continue
        if manifest.get('version') != version:
            print(f'{tag}: skipped, manifest version mismatch')
            continue
        expected = f"{config.get('origin', '')}/downloads/{app}/{channel}/{artifact_name}".lstrip('/')
        url = manifest.get('platforms', {}).get('darwin-aarch64', {}).get('url', '')
        if url and config.get('origin') and url not in (expected, expected.replace('/downloads/', '/')):
            print(f'{tag}: skipped, manifest archive URL does not match the layout')
            continue
        try:
            validate(app, channel, legacy_for.get(app))
        except SystemExit as error:
            print(f'{tag}: skipped, {error}')
            continue
        result = publish_files(root, app, channel, legacy_for.get(app),
                               {artifact_name: artifact_bytes, 'latest.json': manifest_bytes})
        published[tag] = {'version': version, 'artifact': artifact_name, 'sha256': digest,
                          'size': len(artifact_bytes), 'catalog': result['catalog']}
        changed = True
        print(f'{tag}: published {app}/{channel} {version} ({len(artifact_bytes)} bytes)')
    if changed:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(state, indent=2, sort_keys=True) + '\n')
        STATE.chmod(0o600)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except urllib.error.HTTPError as error:
        # A missing or expired read token, or a private staging repository, is a
        # configuration state, not an unexpected failure: log it and wait.
        print(f'pickup could not read staged releases: HTTP {error.code}')
        sys.exit(0)
    except urllib.error.URLError as error:
        print(f'pickup could not reach GitHub: {error.reason}')
        sys.exit(0)
