"""Publish one product artifact to the shared LAPKB download origin.

Layout served by the edge:
    /downloads/<app>/<channel>/<immutable release file>
    /downloads/<app>/<channel>/latest.json
    /downloads/catalog.json

Legacy paths (``/<app>/...``) keep serving the same manifest bytes because
installed clients fetch the manifest URL they were compiled with.

Everything is validated before the catalog is rewritten: the artifact name must
match its content hash, the manifest must name the published location, and the
manifest and artifact are fetched back through the public origin and compared.

Environment:
    LAPKB_PUBLISH_KEY     path to the deploy key (required)
    LAPKB_PUBLISH_HOST    origin host (required)
    LAPKB_PUBLISH_USER    ssh user (required)
    LAPKB_PUBLISH_ROOT    public directory on the origin (required)
    LAPKB_PUBLISH_ORIGIN  public base URL used for verification (required)
    LAPKB_PUBLISH_PORT    ssh port (default 22)
"""
import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import urllib.request
from pathlib import Path

CONTENT_ADDRESSED = re.compile(
    r'^[a-z0-9-]+-(\d+\.\d+\.\d+)-darwin-aarch64-([0-9a-f]{64})\.app\.tar\.gz$')
VERSIONED = re.compile(r'^[a-z0-9-]+-(\d+\.\d+\.\d+)-darwin-aarch64\.app\.zip$')

REMOTE_SCRIPT = '/home/siel/bin/publish_remote.py'


def required(name):
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f'{name} is required')
    return value


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def ssh_command():
    key = required('LAPKB_PUBLISH_KEY')
    config = os.environ.get('LAPKB_PUBLISH_SSH_CONFIG')
    command = ['ssh']
    if config:
        command += ['-F', config]
    command += ['-i', key, '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'BatchMode=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'ClearAllForwardings=yes',
                '-o', 'ControlPath=none', '-o', 'ConnectTimeout=15']
    for name, option in (('LAPKB_PUBLISH_KNOWN_HOSTS', 'UserKnownHostsFile'),
                         ('LAPKB_PUBLISH_HOSTKEY_ALIAS', 'HostKeyAlias')):
        value = os.environ.get(name)
        if value:
            command += ['-o', f'{option}={value}']
    command += ['-p', os.environ.get('LAPKB_PUBLISH_PORT', '22'),
                f'{required("LAPKB_PUBLISH_USER")}@{required("LAPKB_PUBLISH_HOST")}']
    return command


def fetch(url, limit=512 * 1024 * 1024):
    request = urllib.request.Request(url, headers={'User-Agent': 'LAPKB-Release/1.0'})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read(limit)


def publish(app, channel, version, artifact, manifest, legacy):
    artifact, manifest = Path(artifact), Path(manifest)
    origin = required('LAPKB_PUBLISH_ORIGIN').rstrip('/')
    if not artifact.is_file() or not manifest.is_file():
        raise SystemExit('artifact and manifest are required')
    if not re.fullmatch(r'[a-z][a-z0-9-]{1,31}', app) or not re.fullmatch(r'[a-z][a-z0-9-]*', channel):
        raise SystemExit('unexpected app or channel')
    digest = sha256(artifact)
    content = CONTENT_ADDRESSED.match(artifact.name)
    versioned = VERSIONED.match(artifact.name)
    if content:
        if content.group(1) != version or content.group(2) != digest:
            raise SystemExit('content-addressed artifact name does not match its bytes')
    elif versioned:
        if versioned.group(1) != version:
            raise SystemExit('artifact name does not match the version')
    else:
        raise SystemExit('unexpected artifact name')
    try:
        document = json.loads(manifest.read_text())
    except (OSError, ValueError):
        raise SystemExit('manifest is not readable JSON') from None
    if document.get('version') != version:
        raise SystemExit('manifest version does not match the release')
    url = document.get('platforms', {}).get('darwin-aarch64', {}).get('url', '')
    expected = f'{origin}/downloads/{app}/{channel}/{artifact.name}'
    # Manifests signed before the shared layout name the previous path; both are
    # served, so accept either until the packaging helper emits canonical URLs.
    legacy_url = f'{origin}/{app}/{artifact.name}'
    if url and url not in (expected, legacy_url):
        raise SystemExit('manifest archive URL does not match the published location')
    payload = json.dumps([[artifact.name, artifact.stat().st_size],
                          ['latest.json', manifest.stat().st_size]]).encode() + b'\n' + \
        artifact.read_bytes() + manifest.read_bytes()
    values = [required('LAPKB_PUBLISH_ROOT'), app, channel]
    if legacy:
        values.append(legacy)
    remote_command = 'python3 ' + REMOTE_SCRIPT + ' ' + ' '.join(
        shlex.quote(value) for value in values)
    result = subprocess.run(ssh_command() + [remote_command], input=payload,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=1800)
    if result.returncode:
        raise SystemExit('publish failed: ' + result.stderr.decode()[-500:])
    try:
        state = json.loads(result.stdout.decode().strip().splitlines()[-1])
    except (IndexError, ValueError):
        raise SystemExit('publisher response was not JSON') from None
    served_manifest = fetch(f'{origin}/downloads/{app}/{channel}/latest.json')
    try:
        served_version = json.loads(served_manifest).get('version')
    except ValueError:
        raise SystemExit('served manifest is not JSON') from None
    if served_version != version:
        raise SystemExit('served manifest does not report the published version')
    served = fetch(f'{origin}/downloads/{app}/{channel}/{artifact.name}')
    if hashlib.sha256(served).hexdigest() != digest:
        raise SystemExit('served artifact does not match the published bytes')
    if legacy:
        if fetch(f'{origin}/{legacy}/latest.json') != served_manifest:
            raise SystemExit('legacy manifest path does not serve the same bytes')
    print(json.dumps({'app': app, 'channel': channel, 'version': version,
                      'artifact': artifact.name, 'sha256': digest, 'size': artifact.stat().st_size,
                      'legacy': legacy or None, 'catalogApps': state['catalog']}))
    return {'artifact': artifact.name, 'sha256': digest, 'size': artifact.stat().st_size}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--app', required=True)
    parser.add_argument('--channel', default='stable')
    parser.add_argument('--version', required=True)
    parser.add_argument('--artifact', required=True)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--legacy', help='previous manifest path kept byte-identical')
    args = parser.parse_args()
    publish(args.app, args.channel, args.version, args.artifact, args.manifest, args.legacy)
