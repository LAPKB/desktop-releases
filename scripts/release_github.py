"""Bounded GitHub Actions handoff. Downloaded candidates are data, never programs."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "host"))
import release_contract as contract

Error = contract.ContractError
PUBLISHER = "LAPKB/desktop-releases"
TARGETS = ("darwin-aarch64", "windows-x86_64")
# This is a source mapping, not an arbitrary ref input or a publication allowlist.
PRODUCTS = {
    "launcher": {"repository": "LAPKB/Launcher", "integration": "launcher-authorization-repair-20261002", "workflow": "release-launcher.yml", "root": "", "jobs": {"darwin-aarch64": ("build-candidate", "Launcher aarch64-apple-darwin candidate"), "windows-x86_64": ("build-candidate", "Launcher x86_64-pc-windows-msvc candidate")}},
    "papir": {"repository": "LAPKB/Pmetrics-Papir", "integration": "launcher", "workflow": "tauri.yml", "root": "", "jobs": {"darwin-aarch64": ("macos", "macos"), "windows-x86_64": ("windows", "Papir Windows windows-x86_64")}},
    "bestdose": {"repository": "LAPKB/BestDose", "integration": "launcher-session-support", "workflow": "ci.yml", "root": "", "jobs": {"darwin-aarch64": ("macos", "macOS build candidates"), "windows-x86_64": ("windows-cross-build", "Windows unsigned build candidate (x86_64-pc-windows-msvc)")}},
    "bdautodial": {"repository": "LAPKB/BDautodial", "integration": "launcher-session-support", "workflow": "ci.yml", "root": "", "jobs": {"darwin-aarch64": ("macos", "macOS build candidates"), "windows-x86_64": ("windows-cross-build", "Windows unsigned build candidate (x86_64-pc-windows-msvc)")}},
    "checkerboard": {"repository": "LAPKB/Checkerboard", "integration": "launcher-checkmate-support", "workflow": "ci.yml", "root": "desktop/", "jobs": {"darwin-aarch64": ("macos", "macOS build candidates"), "windows-x86_64": ("containers", "x86_64-pc-windows-msvc build candidate")}},
}
CHECKS = {
    "launcher": {"darwin-aarch64": ("Build and package macOS app candidate", "Run native authorization and Launcher update checks", "Bind complete original candidate inventory after all native checks", "Export original candidate files and proofs through Actions only"), "windows-x86_64": ("Test Windows package parsers without running Windows binaries", "Build and verify Windows candidate", "Sign genuine exported Windows x64 updater bytes outside Docker", "Bind complete original candidate inventory after all native checks", "Export original candidate files and proofs through Actions only")},
    "papir": {"darwin-aarch64": ("Run frontend and CI-helper checks", "Run locked, offline native Rust checks", "Verify the macOS ARM64 app and collect its DMG", "Verify and bind complete Mac ARM64 files after all native checks", "Export original Mac ARM64 candidate through Actions only"), "windows-x86_64": ("Test Windows package parsers without running Windows binaries", "Cross-build and compile tests in a job-owned Windows toolchain container", "Bind complete original Windows proof and compiled PE inventory", "Export Windows candidate through Actions only")},
    "bestdose": {"darwin-aarch64": ("Install and test frontend dependencies", "Test native licensing and scientific behavior offline", "Build unsigned ARM64 macOS build candidate", "Verify and bind Mac package identity/resources after native checks", "Export complete Mac ARM64 candidate through Actions only"), "windows-x86_64": ("Test Windows package parsers without running Windows binaries", "Build and verify unsigned Windows build candidate", "Bind complete original Windows proof and compiled PE inventory", "Export Windows candidate through Actions only")},
    "bdautodial": {"darwin-aarch64": ("Run frontend unit tests", "Run Rust tests natively on ARM64", "Build unsigned ARM64 macOS build candidate", "Verify and bind Mac package identity/resources after native checks", "Export complete Mac ARM64 candidate through Actions only"), "windows-x86_64": ("Test Windows package parsers without running Windows binaries", "Build and verify unsigned Windows build candidate", "Bind complete original Windows proof and compiled PE inventory", "Export Windows candidate through Actions only")},
    "checkerboard": {"darwin-aarch64": ("Build frontend", "Build ARM64 DMG", "Test native licensing and scientific core offline", "Verify and bind Mac package identity/resources after native checks", "Export complete original Mac ARM64 release candidate"), "windows-x86_64": ("Test Windows package parsers without running Windows binaries", "Build and verify packages with credentials confined to fetch", "Bind complete original Windows proof and compiled PE inventory", "Export complete original Windows release candidate")},
}
SHA = re.compile(r"[0-9a-f]{40}\Z")
REQUEST = re.compile(r"desktop-[1-9][0-9]{0,19}-[1-9][0-9]{0,3}-[0-9a-f]{32}\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,191}\Z")
MAX_ARCHIVE = contract.MAX_RELEASE_BYTES


def require(condition, message):
    if not condition:
        raise Error(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHub:
    """No proxy/implicit redirects, no credential forwarding to archive hosts."""
    def __init__(self, token):
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, path, *, body=None, destination=None):
        require(path.startswith("/repos/") or path.startswith("/app/") or path.startswith("/orgs/") or path.startswith("/installation/"), "Unexpected GitHub API path")
        url = "https://api.github.com" + path
        token = self.token() if callable(self.token) else self.token
        require(type(token) is str and token and not any(c.isspace() for c in token), "Missing/invalid narrowly scoped GitHub credential")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "LAPKB-desktop-release", "Authorization": "Bearer " + token}
        data = None if body is None else contract.canonical_json(body)
        if data is not None:
            headers["Content-Type"] = "application/json"
        try:
            response = self.opener.open(urllib.request.Request(url, data=data, headers=headers), timeout=120)
        except urllib.error.HTTPError as error:
            location = error.headers.get("Location")
            status = error.code
            error.close()
            if destination is not None and status == 302 and location:
                parsed = urllib.parse.urlsplit(location)
                # GitHub's signed archive redirect has its own credential. Never
                # send the API bearer token (nor log its signed query) there.
                require(parsed.scheme == "https" and parsed.port in (None, 443) and not parsed.username and not parsed.password and not parsed.fragment and (parsed.hostname in ("productionresultssa0.blob.core.windows.net", "results-receiver.actions.githubusercontent.com") or re.fullmatch(r"productionresultssa[0-9]+\.blob\.core\.windows\.net", parsed.hostname or "") is not None or (parsed.hostname or "").endswith(".actions.githubusercontent.com")), "Unapproved GitHub artifact redirect host")
                request = urllib.request.Request(location, headers={"User-Agent": "LAPKB-desktop-release"})
                try:
                    response = self.opener.open(request, timeout=120)
                except (urllib.error.URLError, OSError) as failure:
                    raise Error("GitHub archive download failed; no publication attempted") from failure
            else:
                raise Error(f"GitHub API HTTP {status}; check the selected repository's App Actions/Contents grants") from None
        except (urllib.error.URLError, OSError) as failure:
            # A POST may have succeeded remotely. Caller must reconcile the
            # persisted request, not automatically submit another dispatch.
            raise Error("GitHub request could not complete; reconcile its persisted identity, never blindly redispatch") from failure
        with response:
            status = response.status
            require(status in ((200,) if destination else (200, 201, 204)), "Incomplete GitHub API response")
            if destination is not None:
                length = response.headers.get("Content-Length")
                if length is not None:
                    require(length.isdigit() and 0 < int(length) <= MAX_ARCHIVE, "GitHub archive length is outside its bound")
                total = 0
                with Path(destination).open("xb") as output:
                    os.chmod(destination, 0o600)
                    while chunk := response.read(1024 * 1024):
                        total += len(chunk)
                        require(total <= MAX_ARCHIVE, "GitHub archive exceeds the download bound")
                        output.write(chunk)
                    require(total > 0 and (length is None or total == int(length)), "Truncated GitHub artifact archive")
                    output.flush()
                    os.fsync(output.fileno())
                return None
            raw = response.read(4 * 1024 * 1024 + 1)
            if status == 204:
                require(not raw, "Unexpected dispatch response body")
                return None
            return contract.strict_json(raw, 4 * 1024 * 1024, "GitHub response")

    def pages(self, path, key):
        result = []
        separator = "&" if "?" in path else "?"
        for page in range(1, 11):
            data = self.request(f"{path}{separator}per_page=100&page={page}")
            require(type(data) is dict and type(data.get(key)) is list and all(type(item) is dict for item in data[key]) and type(data.get("total_count")) is int and data["total_count"] >= 0, "Malformed GitHub list response")
            result.extend(data[key])
            if len(data[key]) < 100:
                require(data.get("total_count", len(result)) == len(result), "Incomplete/changed GitHub response inventory")
                return result
        raise Error("GitHub result inventory exceeds its bounded page limit")


class AppToken:
    """Renew short-lived, single-selected-repository installation tokens in CI.

    OpenSSL signs only the standard GitHub App JWT. It is not release signing,
    and no App key, JWT or installation token is retained in evidence/artifacts.
    """
    def __init__(self, app_id, key, repository, *, actions="read"):
        require(re.fullmatch(r"[1-9][0-9]{0,19}", app_id or ""), "RELEASE_APP_ID is missing/invalid")
        require(actions in ("read", "write"), "Invalid App Actions permission")
        self.app_id, self.key, self.repository, self.actions = app_id, key, repository, actions
        self.token, self.deadline = None, 0

    def __call__(self):
        now = time.time()
        if self.token and now < self.deadline:
            return self.token
        encode = lambda value: base64.urlsafe_b64encode(contract.canonical_json(value)).rstrip(b"=")
        unsigned = encode({"alg": "RS256", "typ": "JWT"}) + b"." + encode({"iat": int(now) - 60, "exp": int(now) + 540, "iss": self.app_id})
        try:
            signed = subprocess.run(["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(self.key)], input=unsigned, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=True).stdout
        except (OSError, subprocess.SubprocessError) as error:
            raise Error("GitHub App JWT signing failed; check RELEASE_APP_PRIVATE_KEY custody") from error
        jwt = (unsigned + b"." + base64.urlsafe_b64encode(signed).rstrip(b"=")).decode("ascii")
        api = GitHub(jwt)
        installation = api.request("/repos/" + self.repository + "/installation")
        require(type(installation) is dict and type(installation.get("id")) is int and installation["id"] > 0, "App is not installed on the selected product repository")
        result = api.request(f"/app/installations/{installation['id']}/access_tokens", body={"repositories": [self.repository.split("/")[1]], "permissions": {"actions": self.actions, "contents": "read"}})
        require(type(result) is dict and type(result.get("token")) is str and result["token"] and result.get("permissions") == {"actions": self.actions, "contents": "read", "metadata": "read"}, "App token does not have exactly the requested narrow permissions")
        self.token, self.deadline = result["token"], now + 45 * 60
        return self.token


def producer_attempt(plan):
    # Old immutable bundles predate this explicit field and bind attempt 1.
    attempt = plan.get("producerAttempt", 1)
    require(type(attempt) is int and 1 <= attempt <= 9999, "Invalid bound producer attempt")
    return attempt


def validate_run(run, plan, *, completed=False):
    product = PRODUCTS[plan["app"]]
    expected = {"event": "workflow_dispatch", "head_branch": plan["branch"], "head_sha": plan["source"], "display_title": "desktop-release " + plan["request"], "workflow_id": plan["workflowId"]}
    require(type(run) is dict and all(run.get(k) == v for k, v in expected.items()), "Producer run has wrong workflow/event/ref/SHA/request identity")
    require(type(run.get("repository")) is dict and type(run.get("head_repository")) is dict and run["repository"].get("full_name") == product["repository"] and run["head_repository"].get("full_name") == product["repository"], "Producer run repository differs from selected product")
    require(run.get("path") == ".github/workflows/" + product["workflow"] and type(run.get("id")) is int and run["id"] > 0, "Producer workflow path/run identity is invalid")
    require(type(run.get("run_attempt")) is int and run["run_attempt"] == producer_attempt(plan), "Producer attempt differs from the persisted exact intent")
    if "producerRun" in plan:
        require(run["id"] == plan["producerRun"], "Producer run changed after binding")
    if completed:
        require(run.get("status") == "completed" and run.get("conclusion") == "success", "Producer build/test run is not completed and successful")
    else:
        require(run.get("status") in ("queued", "in_progress", "waiting", "pending", "requested", "completed"), "Unknown producer run status")
    return run


def validate_jobs(jobs, plan):
    product = PRODUCTS[plan["app"]]
    required = {name for _, name in product["jobs"].values()}
    require(type(jobs) is list and len(jobs) <= 64 and all(type(j) is dict for j in jobs), "Malformed producer job inventory")
    matched = {}
    for job in jobs:
        name = job.get("name")
        if name not in required:
            # Genuine extra CI jobs may be skipped by the qualified matrix.
            require(job.get("conclusion") in ("success", "skipped") and job.get("status") == "completed", "An additional producer job failed or is incomplete")
            continue
        require(name not in matched, "Duplicate required producer job")
        require(type(job.get("run_id")) is int and job["run_id"] == plan["producerRun"] and type(job.get("run_attempt")) is int and job["run_attempt"] == producer_attempt(plan) and job.get("head_sha") == plan["source"] and job.get("status") == "completed" and job.get("conclusion") == "success", "Required producer job has wrong run/attempt/source or failed")
        steps = job.get("steps")
        require(type(steps) is list and steps and all(type(s) is dict for s in steps), "Required producer job has no completed step evidence")
        require(all(s.get("status") == "completed" and s.get("conclusion") in ("success", "skipped") for s in steps), "Producer step failed or is incomplete")
        # Every exact source workflow contains the named inventory step, which
        # runs only after its native tests/package proof. Require it and export.
        successful = [s.get("name", "") for s in steps if s.get("conclusion") == "success"]
        target = next(t for t, (_, expected_name) in product["jobs"].items() if expected_name == name)
        require(all(successful.count(required_step) == 1 for required_step in CHECKS[plan["app"]][target]), "Required native tests/package-proof inventory/export steps did not run exactly once")
        matched[name] = job
    require(set(matched) == required, "Missing a qualified Mac ARM64 or Windows x64 job")
    return matched


def candidate_name(plan, target):
    return f"candidate-{plan['app']}-{plan['source']}-{plan['producerRun']}-{producer_attempt(plan)}-{target}-{plan['request']}"


def validate_artifacts(artifacts, plan):
    expected = {candidate_name(plan, t): t for t in TARGETS}
    found = {}
    require(type(artifacts) is list and len(artifacts) <= 64 and all(type(a) is dict and type(a.get("name")) is str for a in artifacts), "Malformed/oversized candidate artifact inventory")
    for item in artifacts:
        name = item.get("name", "")
        if not name.startswith("candidate-"):
            continue
        require(name in expected and name not in found and item.get("expired") is False and type(item.get("id")) is int and item["id"] > 0 and type(item.get("size_in_bytes")) is int and 0 < item["size_in_bytes"] <= MAX_ARCHIVE, "Missing/duplicate/mixed/expired candidate artifact")
        identity = item.get("workflow_run", {})
        require(type(identity) is dict and type(identity.get("id")) is int and identity["id"] == plan["producerRun"] and identity.get("head_sha") == plan["source"] and identity.get("head_branch") == plan["branch"] and identity.get("repository_id") == plan["repositoryId"] and identity.get("head_repository_id") == plan["repositoryId"], "Candidate artifact workflow/source repository identity differs")
        found[name] = item
    require(set(found) == set(expected), "Both exact qualified target artifacts are required before signing")
    return {expected[n]: item for n, item in found.items()}


def extract_archive(path, destination, *, nested=False):
    """Extract only bounded regular files, exclusively; never follow archive links."""
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    count, total, names = 0, 0, set()
    try:
        # Bound the central directory BEFORE ZipFile allocates its entry list.
        # Qualified desktop candidates fit ordinary ZIP, not unbounded ZIP64.
        with Path(path).open("rb") as source:
            source.seek(0, os.SEEK_END)
            size = source.tell()
            source.seek(max(0, size - 65557))
            tail = source.read(65557)
        marker = tail.rfind(b"PK\x05\x06")
        require(marker >= 0 and marker + 22 <= len(tail), "Artifact archive has no bounded ZIP directory")
        _, disk, start_disk, disk_count, entry_count, directory_size, directory_offset, comment = struct.unpack_from("<4s4H2LH", tail, marker)
        require(disk == start_disk == 0 and disk_count == entry_count and 1 <= entry_count <= 192 and directory_size <= 4 * 1024 * 1024 and directory_offset + directory_size <= size and marker + 22 + comment == len(tail), "Artifact ZIP directory count/size/multi-volume bound exceeded")
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            require(1 <= len(entries) <= 192, "Artifact archive file-count bound exceeded")
            for item in entries:
                name = item.filename
                parts = name.split("/")
                require(name not in names and not name.endswith("/") and (1 <= len(parts) <= (2 if nested else 1)) and len(name) <= 1024 and all(NAME.fullmatch(p) for p in parts), "Artifact archive has unsafe/duplicate/nested paths")
                names.add(name)
                mode = item.external_attr >> 16
                require(not item.flag_bits & 1 and item.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and (stat.S_IFMT(mode) in (0, stat.S_IFREG)) and not mode & 0o7000, "Artifact archive contains links/special/encrypted files or unsafe modes")
                require(0 < item.file_size <= contract.MAX_FILE_BYTES and item.compress_size > 0 and item.file_size <= max(1024 * 1024, item.compress_size * 200), "Artifact archive has an invalid size/compression bound")
                count += 1
                total += item.file_size
                require(count <= 192 and total <= MAX_ARCHIVE, "Artifact archive expanded size exceeds bound")
                target = destination.joinpath(*parts)
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.open(item) as source, target.open("xb") as output:
                    os.chmod(target, 0o600)
                    copied = 0
                    while chunk := source.read(1024 * 1024):
                        copied += len(chunk)
                        require(copied <= item.file_size, "Artifact entry expanded past its declared size")
                        output.write(chunk)
                    require(copied == item.file_size, "Artifact entry is truncated")
                    output.flush()
                    os.fsync(output.fileno())
    except (zipfile.BadZipFile, RuntimeError, OSError) as error:
        raise Error("Malformed or unsafe GitHub artifact archive") from error
    return destination


def inventory(directory):
    result = []
    for path in sorted(Path(directory).iterdir()):
        require(NAME.fullmatch(path.name), "Candidate file name is unsafe")
        size, digest = contract._sha256_file(path)
        result.append({"name": path.name, "size": size, "sha256": digest})
    require(1 <= len(result) <= 64 and sum(i["size"] for i in result) <= MAX_ARCHIVE, "Candidate complete inventory exceeds bounds")
    return result


def validate_candidate(directory, plan, target):
    raw = contract._read_regular(directory / "release-candidate.json", contract.MAX_ATTESTATION_BYTES, "Actions candidate")
    candidate = contract.strict_json(raw, contract.MAX_ATTESTATION_BYTES, "Actions candidate")
    product = PRODUCTS[plan["app"]]
    job = product["jobs"][target][0]
    expected = {"schema": "lapkb-actions-candidate-v1", "app": plan["app"], "repository": product["repository"], "workflow": product["workflow"], "workflowRef": f"{product['repository']}/.github/workflows/{product['workflow']}@refs/heads/{plan['branch']}", "source": plan["source"], "version": plan["version"], "target": target, "request": plan["request"], "runId": str(plan["producerRun"]), "runAttempt": producer_attempt(plan), "job": job}
    require(type(candidate) is dict and set(candidate) == set(expected) | {"inventory", "inventoryDigest"} and all(type(candidate[k]) is type(v) and candidate[k] == v for k, v in expected.items()) and contract.canonical_json(candidate) == raw, "Candidate source/run/attempt/request/target/job identity differs")
    actual = [i for i in inventory(directory) if i["name"] != "release-candidate.json"]
    require(candidate["inventory"] == actual and candidate["inventoryDigest"] == hashlib.sha256(contract.canonical_json(actual)).hexdigest(), "Candidate complete original inventory differs from its correlation proof")
    return candidate


def find_producer(api, plan):
    base = "/repos/" + PRODUCTS[plan["app"]]["repository"] + "/actions"
    runs = api.pages(f"{base}/workflows/{plan['workflowId']}/runs?event=workflow_dispatch&branch={urllib.parse.quote(plan['branch'], safe='')}", "workflow_runs")
    matched = [r for r in runs if r.get("display_title") == "desktop-release " + plan["request"]]
    require(len(matched) <= 1, "Duplicate producer runs for the persisted request; no signing")
    return validate_run(matched[0], plan) if matched else None


def wait_for_producer(api, plan, *, dispatch=False, timeout=3 * 60 * 60 + 30 * 60, pause=time.sleep, clock=time.monotonic):
    """Bounded CI-only wait, including one dispatch; never choose a latest run."""
    repository = PRODUCTS[plan["app"]]["repository"]
    base = "/repos/" + repository + "/actions"
    if dispatch:
        api.request(f"{base}/workflows/{plan['workflowId']}/dispatches", body={"ref": plan["branch"], "inputs": {**plan.get("producerInputs", {}), "source_sha": plan["source"], "release_request": plan["request"], "release_version": plan["version"], "desktop_release": "true"}})
    deadline = clock() + timeout
    while clock() < deadline:
        if "producerRun" not in plan:
            run = find_producer(api, plan)
            if run:
                plan["producerRun"] = run["id"]
        if "producerRun" in plan:
            run = api.request(f"{base}/runs/{plan['producerRun']}/attempts/{producer_attempt(plan)}")
            validate_run(run, plan)
            if run["status"] == "completed":
                validate_run(run, plan, completed=True)
                jobs = api.pages(f"{base}/runs/{plan['producerRun']}/attempts/{producer_attempt(plan)}/jobs", "jobs")
                validate_jobs(jobs, plan)
                artifacts = validate_artifacts(api.pages(f"{base}/runs/{plan['producerRun']}/artifacts", "artifacts"), plan)
                return {"run": run, "jobs": jobs, "artifacts": artifacts}
        pause(min(30, max(0, deadline - clock())))
    raise Error("Timed out waiting for the exact producer request. Re-run the coordinator to reconcile the retained intent; do not manually redispatch")
