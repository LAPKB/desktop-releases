"""One-time CI-native tool setup; no product, credential, receiver or policy writes.

Use the maintained validation lane and its tested locked verifier output. Install
only hash-pinned standalone tools in an append-only, protected runner directory.
"""
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from contextlib import suppress
from pathlib import Path

if sys.version_info < (3, 11):
    raise SystemExit('Release tooling requires Python 3.11+ on the X64 worker')
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import publish_artifact
import release_contract as contract
from release_desktop import pinned_tool

VERIFIER_SHA256 = '7ffe163cfb5d2f180a09120d0290f299448223cf21c7f77fb4c0e510313220a3'
SIGNER_SHA256 = '23a27f61c50417fe87c92fa958fb56ecc8de7c791f78df3cac046c8579b45897'
SIGNER_ARCHIVE_SHA256 = '6864602a34292aa6f2ad40ae019eebe5c1064d6c623fe20696a8a8974067e60b'
SIGNER_URL = 'https://github.com/tauri-apps/tauri/releases/download/tauri-cli-v2.11.4/cargo-tauri-x86_64-unknown-linux-gnu.tgz'
CLEAN_ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}
VERIFIER_SOURCE_FILES = {
    'host/verifier/Cargo.lock': 'fabcd9cd587acbd0cf4c484d015048968c56e5e150795810b94698a23d799c94',
    'host/verifier/Cargo.toml': '3511c18c293d7db551973c69ff9ae7acd1261d73722e624deb562e4cb70880fd',
    'host/verifier/examples/synthetic-signer.rs': '26a8d6f2468edfe114af8c80dd0a6288541bb251e924ce8bd81c59158ac1c16e',
    'host/verifier/src/main.rs': '04c5ece68f962319c45c09d54beb845df68c3f3bb2cca183cc414762c45271ef',
}


def closure(tool):
    """Record the actual protected system loader/library closure, never use a wrapper."""
    contract._read_protected_file(Path('/usr/bin/ldd'), 1024 * 1024)
    result = subprocess.run(['/usr/bin/ldd', str(tool)], check=True, capture_output=True,
                            timeout=30, env=CLEAN_ENV)
    paths = re.findall(r'(?:=>\s+)?(/[^\s]+)\s+\(0x[0-9a-f]+\)', result.stdout.decode())
    assert paths and b'not found' not in result.stdout
    records = []
    for name in sorted(set(paths)):
        p = Path(name)
        # Distro library links are allowed only under root-controlled paths;
        # the tool itself still uses the maintained non-link protected-file rule.
        for ancestor in (Path('/'), *reversed(p.parents[:-1]), p):
            s = ancestor.lstat()
            assert s.st_uid == 0
            assert stat.S_ISLNK(s.st_mode) or not s.st_mode & 0o022
        real = p.resolve(strict=True)
        data = contract._read_protected_file(real, 256 * 1024 * 1024)
        assert real.stat().st_uid == 0
        records.append({'path': str(p), 'resolvedPath': str(real), 'sha256': hashlib.sha256(data).hexdigest(),
                        'bytes': len(data), 'mode': oct(stat.S_IMODE(real.stat().st_mode))})
    return {'lddSha256': hashlib.sha256(Path('/usr/bin/ldd').read_bytes()).hexdigest(), 'files': records}


def retain_tool(root, name, data, mode):
    destination = root / name
    if destination.exists() or destination.is_symlink():
        assert contract._read_protected_file(destination, 256 * 1024 * 1024) == data
        assert stat.S_IMODE(destination.lstat().st_mode) == mode
        return destination  # Preserve matching existing bytes, inode and metadata.
    fd, temporary = tempfile.mkstemp(prefix='.setup-', dir=root)
    temporary = Path(temporary)
    info = os.fstat(fd)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fchmod(output.fileno(), mode)
            os.fsync(output.fileno())
        os.link(temporary, destination, follow_symlinks=False)  # Exclusive, never replace.
    finally:
        current = temporary.lstat()
        assert (current.st_dev, current.st_ino) == (info.st_dev, info.st_ino)
        temporary.unlink()
    return destination


def main():
    os.umask(0o077)
    assert os.environ['GITHUB_REPOSITORY'] == 'LAPKB/desktop-releases'
    assert os.environ['GITHUB_EVENT_NAME'] in ('push', 'workflow_dispatch')
    assert os.environ['GITHUB_REF'] == 'refs/heads/launcher'
    assert (os.environ['RUNNER_OS'], os.environ['RUNNER_ARCH'], os.uname().machine) == ('Linux', 'X64', 'x86_64')
    work = Path(sys.argv[1])
    subprocess.run([sys.executable, str(Path(__file__).with_name('owned-temp-dir.py')), 'validate',
                    os.environ['RUNNER_TEMP'], str(work), 'publisher-jobs2', sys.argv[2]], check=True)
    source_files = {p.relative_to(work / 'source').as_posix() for p in
                    (work / 'source/host/verifier').rglob('*') if not p.is_dir()}
    assert source_files == set(VERIFIER_SOURCE_FILES)
    for name, expected in VERIFIER_SOURCE_FILES.items():
        assert hashlib.sha256(contract._read_protected_file(work / 'source' / name, 1024 * 1024)).hexdigest() == expected
    verifier = work / 'evidence/lapkb-release-verifier'
    os.environ.update(RELEASE_VERIFIER_PATH=str(verifier), RELEASE_VERIFIER_SHA256=VERIFIER_SHA256)
    pinned_tool('RELEASE_VERIFIER_PATH', 'RELEASE_VERIFIER_SHA256')
    with urllib.request.urlopen(SIGNER_URL, timeout=120) as response:
        assert response.status == 200 and response.url.startswith('https://')
        archive = response.read(8259865)
    assert len(archive) == 8259864 and hashlib.sha256(archive).hexdigest() == SIGNER_ARCHIVE_SHA256
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        items = tar.getmembers()
        assert sorted(i.name for i in items) == ['LICENSE_APACHE-2.0', 'LICENSE_MIT', 'README.md', 'cargo-tauri']
        assert all(i.isfile() and i.size <= 64 * 1024 * 1024 for i in items)
        files = {}
        for item in items:
            stream = tar.extractfile(item)
            assert stream is not None
            files[item.name] = stream.read()
    assert hashlib.sha256(files['cargo-tauri']).hexdigest() == SIGNER_SHA256
    staging = work / 'native-release-tools'
    staging.mkdir(mode=0o700)
    signer = retain_tool(staging, 'cargo-tauri', files['cargo-tauri'], 0o700)
    os.environ.update(RELEASE_SIGNER_PATH=str(signer), RELEASE_SIGNER_SHA256=SIGNER_SHA256)
    pinned_tool('RELEASE_SIGNER_PATH', 'RELEASE_SIGNER_SHA256')  # Actual standalone --version.
    loader = subprocess.run([str(verifier)], capture_output=True, timeout=30, env=CLEAN_ENV)
    assert loader.returncode == 1 and loader.stderr.strip() == b'lapkb-release-verifier: usage: lapkb-release-verifier verify <signature-file> <payload-file>'
    verifier_closure, signer_closure = closure(verifier), closure(signer)

    home_fd, home = publish_artifact._secure_bundle_dir(Path.home())
    try:
        with suppress(FileExistsError):
            os.mkdir('lapkb-desktop-release-tools', 0o700, dir_fd=home_fd)
        root_fd = os.open('lapkb-desktop-release-tools', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=home_fd)
        try:
            info = os.fstat(root_fd)
            assert info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
        finally:
            os.close(root_fd)
    finally:
        os.close(home_fd)
    root = home / 'lapkb-desktop-release-tools'
    verifier_installed = retain_tool(root, 'lapkb-release-verifier-' + VERIFIER_SHA256, verifier.read_bytes(), 0o700)
    signer_installed = retain_tool(root, 'cargo-tauri-2.11.4-' + SIGNER_SHA256, files['cargo-tauri'], 0o700)
    for name in ('LICENSE_APACHE-2.0', 'LICENSE_MIT', 'README.md'):
        retain_tool(root, 'tauri-2.11.4-' + name, files[name], 0o600)
    variables = {'RELEASE_VERIFIER_PATH': str(verifier_installed), 'RELEASE_VERIFIER_SHA256': VERIFIER_SHA256,
                 'RELEASE_SIGNER_PATH': str(signer_installed), 'RELEASE_SIGNER_SHA256': SIGNER_SHA256}
    os.environ.update(variables)
    pinned_tool('RELEASE_VERIFIER_PATH', 'RELEASE_VERIFIER_SHA256')
    pinned_tool('RELEASE_SIGNER_PATH', 'RELEASE_SIGNER_SHA256')
    assert closure(verifier_installed) == verifier_closure and closure(signer_installed) == signer_closure
    receipt = {'publisherSource': os.environ['GITHUB_SHA'], 'run': os.environ['GITHUB_RUN_ID'],
        'attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'runner': os.environ['RUNNER_NAME'],
        'runnerGroup': 'Default', 'architecture': 'Linux X64', 'python': sys.version,
        'variables': variables, 'verifierOriginalSuccessfulCI': {'source': '1b2258933531a52a77c1336b94d9a968a7e4c626',
            'run': 37353523443, 'attempt': 1, 'job': 111910023931, 'artifactId': 11363901478,
            'lockedVerifierSourceUnchanged': True, 'sourceFileSha256': VERIFIER_SOURCE_FILES,
            'sameTestedBinarySha256': VERIFIER_SHA256},
        'signer': {'version': '2.11.4', 'source': '8909f221d1515955fc843808032bdc5d62209c96',
            'officialArchive': SIGNER_URL, 'archiveSha256': SIGNER_ARCHIVE_SHA256,
            'standaloneVersionExecutedSuccessfully': True},
        'verifierClosure': verifier_closure, 'signerClosure': signer_closure,
        'protectedInstallation': {'root': str(root), 'uid': info.st_uid, 'directoryMode': '0700',
            'toolMode': '0700', 'noLinksOrReplacement': True},
        'productOrCandidateExecution': False, 'credentialPolicyReceiverWrites': False}
    data = (json.dumps(receipt, sort_keys=True, indent=2) + '\n').encode()
    retain_tool(root, 'setup-' + os.environ['GITHUB_RUN_ID'] + '-' + os.environ['GITHUB_RUN_ATTEMPT'] + '.json', data, 0o600)
    with (work / 'evidence/release-tools-setup.json').open('xb') as output:
        output.write(data)
    print('Protected, hash-pinned native release tools installed; non-secret closure/provenance receipt retained.')


if __name__ == '__main__':
    main()
