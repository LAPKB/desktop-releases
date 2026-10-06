"""Isolated CI evidence, not synthetic production releases or native app acceptance.

GitHub responses/candidate package claims are explicit fixtures. Signatures use
fresh process-local test keys and the existing real native verifier; all writer
transactions target temporary isolated roots, with no network/SSH/app execution.
"""
from __future__ import annotations

import base64
import copy
import email.message
import hashlib
import io
import json
import re
import stat
import sys
import tempfile
import unittest
import urllib.error
import zipfile
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "scripts"), str(ROOT / "host")]
import prepare_bundle
import publish_artifact
import publish_remote as publisher
import release_contract as contract
import release_desktop as desktop
import release_github as github
from support import (VERIFIER, SyntheticSigner, canonical, make_bundle, make_historical_input,
                     make_root, make_trust, public_snapshot, stage_bundle)


def fixture_plan(app="papir"):
    product = github.PRODUCTS[app]
    return {"schema": "lapkb-desktop-release-plan-v1", "app": app, "mode": "integration",
            "repository": product["repository"], "repositoryId": 7,
            "branch": product["integration"], "source": "a" * 40, "version": "2.3.4",
            "workflowId": 81, "request": "desktop-100-1-" + "f" * 32,
            "publisherRun": 100, "publisherAttempt": 1, "publisherSource": "b" * 40,
            "publisherBranch": "launcher", "producerRun": 12345, "producerAttempt": 1}


def fixture_run(plan):
    return {"id": plan["producerRun"], "event": "workflow_dispatch", "head_branch": plan["branch"],
            "head_sha": plan["source"], "display_title": "desktop-release " + plan["request"],
            "workflow_id": plan["workflowId"], "path": ".github/workflows/" + github.PRODUCTS[plan["app"]]["workflow"],
            "repository": {"full_name": plan["repository"]}, "head_repository": {"full_name": plan["repository"]},
            "run_attempt": github.producer_attempt(plan), "status": "completed", "conclusion": "success"}


def fixture_jobs(plan):
    return [{"id": n + 1, "name": github.PRODUCTS[plan["app"]]["jobs"][target][1],
             "run_id": plan["producerRun"], "run_attempt": github.producer_attempt(plan), "head_sha": plan["source"],
             "status": "completed", "conclusion": "success", "steps": [
                 {"name": name, "status": "completed", "conclusion": "success"}
                 for name in github.CHECKS[plan["app"]][target]]}
            for n, target in enumerate(github.TARGETS)]


def fixture_artifacts(plan):
    return [{"id": n + 1, "name": github.candidate_name(plan, target), "expired": False,
             "size_in_bytes": 123, "workflow_run": {"id": plan["producerRun"],
                 "head_sha": plan["source"], "head_branch": plan["branch"],
                 "repository_id": plan["repositoryId"], "head_repository_id": plan["repositoryId"]}}
            for n, target in enumerate(github.TARGETS)]


def fixture_source_plan():
    plan = fixture_plan()
    paths = ("package.json", "src-tauri/tauri.conf.json", "src-tauri/Cargo.toml", "src-tauri/Cargo.lock", "package-lock.json")
    plan.update(declarations={"fixture": "2.3.4"}, sourceFiles={p: hashlib.sha256(b"fixture").hexdigest() for p in paths}, producerInputs={"signing_kid": "existing-public-kid", "signing_public_key": "existing-public-key"})
    return plan


def fixture_publisher_artifact(plan, kind="intent", artifact_id=8):
    return {"id": artifact_id, "name": desktop.artifact_name(kind, plan), "workflow_run": {"id": plan["publisherRun"]}}


@contextmanager
def fixture_planning(workspace, records, runs, *, attempt=2, correlated=None, branch_source=None):
    """Only planning I/O is mocked; retry/source/run validation stays real."""
    old = records[0][0]
    api, own = mock.Mock(), mock.Mock()
    own.pages.return_value = [a for _, a in records]
    api.pages.return_value = list(runs.values()) if correlated is None else correlated
    def response(path):
        if "/git/ref/" in path:
            return {"ref": "refs/heads/" + old["branch"], "object": {"type": "commit", "sha": branch_source or old["source"]}}
        if "/actions/runs/" in path:
            return runs[int(path.split("/runs/")[1].split("/")[0])]
        if "/actions/workflows/" in path:
            return {"id": 81, "path": ".github/workflows/tauri.yml", "state": "active"}
        return {"full_name": old["repository"], "id": 7}
    api.request.side_effect = response
    def contents(_api, _repo, source, path):
        if source != old["source"]:
            raise AssertionError("Planning changed the frozen source")
        return b"release_request: desktop_release: source_sha:" if path.endswith(".yml") else b"lapkb-actions-candidate-v1" if path.endswith(".py") else b"fixture"
    def retained(_own, artifact, mode, kind, _workspace):
        return next(p for p, a in records if a["id"] == artifact["id"]), workspace
    env = {"GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": str(attempt), "GITHUB_SHA": "b" * 40,
           "RELEASE_PAPIR_SIGNING_KID": "existing-public-kid", "RELEASE_PAPIR_SIGNING_PUBLIC_KEY": "existing-public-key"}
    with mock.patch.dict(desktop.os.environ, env), mock.patch.object(desktop, "publisher_guard", return_value="launcher"), mock.patch.object(desktop, "app_api", return_value=api), mock.patch.object(desktop, "GitHub", return_value=own), mock.patch.object(desktop, "content", side_effect=contents), mock.patch.object(desktop, "derive_version", return_value=("2.3.4", old["declarations"])), mock.patch.object(desktop, "publisher_artifact", side_effect=retained):
        yield api


class CoordinatorSourceTests(unittest.TestCase):
    def test_one_x64_producer_worker_is_not_reserved_by_waiting_coordinator(self):
        source = (ROOT / ".github/workflows/publish-download.yml").read_text()
        jobs = dict(re.findall(r"^  (\w+):\n(.*?)(?=^  \w+:\n|\Z)", source, re.M | re.S))
        def lane(name):
            block = jobs[name]
            group = re.search(r"^      group: (\w+)$", block, re.M).group(1)
            labels = re.search(r"^      labels: \[self-hosted, Linux, (\w+)\]$", block, re.M).group(1)
            return group, labels
        self.assertEqual(lane("build"), ("rust", "ARM64"))
        for name in ("plan", "authorize", "release"):
            self.assertEqual(lane(name), ("Default", "X64"))
        self.assertIn("needs: [plan, authorize]", jobs["build"])
        self.assertIn("needs: [plan, authorize, build]", jobs["release"])
        # One worker per lane: plan/authorize finish before the coordinator waits;
        # publication cannot start until its child builds have finished.
        occupied_during_wait = {lane("build")}
        producer_lane = ("Default", "X64")
        def worker_available(requested, occupied):
            return requested not in occupied
        self.assertTrue(worker_available(producer_lane, occupied_during_wait))
        self.assertFalse(worker_available(producer_lane, {producer_lane}))  # Old lane deadlocks.
        build = jobs["build"]
        runtime = build.index("Check coordinator lane and runtime before any dispatch")
        retained = build.index("Persist release intent before any dispatch")
        dispatch = build.index("python3 scripts/release_desktop.py build")
        self.assertLess(runtime, retained)
        self.assertLess(retained, dispatch)
        self.assertIn("import sys,tomllib", build)
        self.assertIn("test -x /usr/bin/openssl", build)
        for key in ("APP_SIGNING_KEY", "PUBLISH_SSH_KEY", "RELEASE_VERIFIER_PATH", "RELEASE_SIGNER_PATH", "environment:"):
            self.assertNotIn(key, build)


class GitHubHandoffTests(unittest.TestCase):
    def test_all_five_fixed_product_job_and_artifact_contracts(self):
        for app in github.PRODUCTS:
            for attempt in (1, 2):
                plan = {**fixture_plan(app), "producerAttempt": attempt}
                github.validate_run(fixture_run(plan), plan, completed=True)
                github.validate_jobs(fixture_jobs(plan), plan)
                self.assertEqual(set(github.validate_artifacts(fixture_artifacts(plan), plan)), set(github.TARGETS))

    def test_bound_attempt_cannot_mix_jobs_or_artifacts_from_another_attempt(self):
        plan = {**fixture_plan(), "producerAttempt": 2}
        jobs = fixture_jobs(plan)
        jobs[0]["run_attempt"] = 1
        with self.assertRaises(contract.ContractError):
            github.validate_jobs(jobs, plan)
        artifacts = fixture_artifacts(plan)
        artifacts[0] = fixture_artifacts({**plan, "producerAttempt": 1})[0]
        with self.assertRaises(contract.ContractError):
            github.validate_artifacts(artifacts, plan)
        for value in (True, 0, -1, "2", 10000):
            with self.subTest(value=value), self.assertRaises(contract.ContractError):
                github.producer_attempt({**plan, "producerAttempt": value})

    def test_wrong_ref_sha_workflow_event_repository_attempt_request_and_run_rejected(self):
        plan = fixture_plan()
        changes = {"id": 99, "head_branch": "arbitrary", "head_sha": "c" * 40,
                   "workflow_id": 99, "path": ".github/workflows/evil.yml", "event": "pull_request",
                   "run_attempt": 2, "display_title": "desktop-release other",
                   "repository": {"full_name": "attacker/repo"}, "head_repository": {"full_name": "attacker/repo"},
                   "status": "in_progress", "conclusion": "failure"}
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(contract.ContractError):
                github.validate_run({**fixture_run(plan), key: value}, plan, completed=True)

    def test_missing_duplicate_failed_skipped_or_wrong_job_step_identity_rejected(self):
        plan = fixture_plan()
        good = fixture_jobs(plan)
        bad = [good[:1], good + [good[0]], []]
        for key, value in (("run_id", 99), ("run_attempt", 2), ("head_sha", "c" * 40),
                           ("status", "in_progress"), ("conclusion", "failure"), ("conclusion", "skipped")):
            changed = copy.deepcopy(good)
            changed[0][key] = value
            bad.append(changed)
        for change in ("missing", "skipped", "failed", "duplicate"):
            changed = copy.deepcopy(good)
            if change == "missing":
                changed[0]["steps"].pop()
            elif change == "duplicate":
                changed[0]["steps"].append(changed[0]["steps"][0])
            else:
                changed[0]["steps"][0]["conclusion"] = "skipped" if change == "skipped" else "failure"
            bad.append(changed)
        for jobs in bad:
            with self.subTest(jobs=jobs), self.assertRaises(contract.ContractError):
                github.validate_jobs(jobs, plan)

    def test_missing_duplicate_mixed_expired_or_wrong_artifact_identity_rejected(self):
        plan = fixture_plan()
        good = fixture_artifacts(plan)
        bad = [good[:1], good + [good[0]]]
        for key, value in (("name", "candidate-mixed"), ("expired", True), ("size_in_bytes", 0)):
            changed = copy.deepcopy(good)
            changed[0][key] = value
            bad.append(changed)
        for key, value in (("id", 99), ("head_sha", "c" * 40), ("head_branch", "main"),
                           ("repository_id", 99), ("head_repository_id", 99)):
            changed = copy.deepcopy(good)
            changed[0]["workflow_run"][key] = value
            bad.append(changed)
        for artifacts in bad:
            with self.subTest(artifacts=artifacts), self.assertRaises(contract.ContractError):
                github.validate_artifacts(artifacts, plan)

    def test_wait_joins_only_correlated_run_and_is_bounded_never_redispatches(self):
        plan = fixture_plan()
        plan.pop("producerRun")
        bound = {**plan, "producerRun": 12345}
        api = mock.Mock()
        api.pages.side_effect = [[fixture_run(bound)], fixture_jobs(bound), fixture_artifacts(bound)]
        api.request.side_effect = [None, fixture_run(bound)]
        result = github.wait_for_producer(api, plan, dispatch=True, pause=lambda _: self.fail("unexpected wait"), clock=lambda: 0)
        self.assertEqual(result["run"]["id"], 12345)
        self.assertEqual(sum("dispatches" in call.args[0] for call in api.request.call_args_list), 1)
        timed = fixture_plan()
        api = mock.Mock()
        api.request.return_value = {**fixture_run(timed), "status": "in_progress", "conclusion": None}
        clock = iter((0, 0, 0, 2))
        with self.assertRaisesRegex(contract.ContractError, "Timed out"):
            github.wait_for_producer(api, timed, timeout=1, clock=lambda: next(clock), pause=lambda _: None)
        self.assertFalse(any("dispatches" in call.args[0] for call in api.request.call_args_list))
        api = mock.Mock()
        api.pages.return_value = [fixture_run(bound), fixture_run(bound)]
        unbound = {k: v for k, v in bound.items() if k != "producerRun"}
        with self.assertRaisesRegex(contract.ContractError, "Duplicate producer"):
            github.wait_for_producer(api, unbound, clock=lambda: 0)
        api = mock.Mock()
        api.request.return_value = {**fixture_run(bound), "conclusion": "failure"}
        with self.assertRaises(contract.ContractError):
            github.wait_for_producer(api, bound, clock=lambda: 0)

    def test_malformed_response_shapes_and_boolean_attempts_fail_closed(self):
        plan = fixture_plan()
        for run in (None, [], {**fixture_run(plan), "repository": None}, {**fixture_run(plan), "run_attempt": True}):
            with self.assertRaises(contract.ContractError):
                github.validate_run(run, plan, completed=True)
        for jobs in ([None], [{**fixture_jobs(plan)[0], "steps": [None]}], [{**fixture_jobs(plan)[0], "run_attempt": True}]):
            with self.assertRaises(contract.ContractError):
                github.validate_jobs(jobs, plan)
        for artifacts in ([None], [{**fixture_artifacts(plan)[0], "workflow_run": None}]):
            with self.assertRaises(contract.ContractError):
                github.validate_artifacts(artifacts, plan)

    def test_archive_bounds_unsafe_paths_links_duplicates_and_corruption(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = [[("../escape", b"x")], [("/absolute", b"x")], [("nested/file", b"x")],
                     [("same", b"x"), ("same", b"y")], [("back\\slash", b"x")], [("empty", b"")]]
            for index, entries in enumerate(cases):
                path = root / f"{index}.zip"
                with zipfile.ZipFile(path, "w") as archive:
                    for name, body in entries:
                        archive.writestr(name, body)
                with self.subTest(entries=entries), self.assertRaises(contract.ContractError):
                    github.extract_archive(path, root / f"out-{index}")
            path = root / "link.zip"
            with zipfile.ZipFile(path, "w") as archive:
                item = zipfile.ZipInfo("linked")
                item.create_system = 3
                item.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(item, "outside")
            with self.assertRaises(contract.ContractError):
                github.extract_archive(path, root / "link-out")
            path.write_bytes(b"malformed ZIP")
            with self.assertRaises(contract.ContractError):
                github.extract_archive(path, root / "broken-out")
            path = root / "large.zip"
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("bomb", b"a" * (2 * 1024 * 1024))
            with self.assertRaises(contract.ContractError):
                github.extract_archive(path, root / "large-out")
            path = root / "good.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("original.exe", b"fixture original bytes")
            directory = github.extract_archive(path, root / "good")
            self.assertEqual((directory / "original.exe").read_bytes(), b"fixture original bytes")

    def test_archive_redirect_never_forwards_api_token_or_uses_proxy(self):
        class Response(io.BytesIO):
            status = 200
            headers = {"Content-Length": "3"}
        api = github.GitHub("API-SECRET")
        headers = email.message.Message()
        headers["Location"] = "https://productionresultssa0.blob.core.windows.net/artifact?signature=private"
        redirect = urllib.error.HTTPError("https://api.github.com", 302, "Found", headers, io.BytesIO())
        api.opener = mock.Mock()
        api.opener.open.side_effect = [redirect, Response(b"zip")]
        with tempfile.TemporaryDirectory() as temporary:
            api.request("/repos/LAPKB/desktop-releases/actions/artifacts/7/zip", destination=Path(temporary) / "artifact.zip")
        first, second = [c.args[0] for c in api.opener.open.call_args_list]
        self.assertEqual(first.get_header("Authorization"), "Bearer API-SECRET")
        self.assertIsNone(second.get_header("Authorization"))
        self.assertIsNone(second.get_header("Proxy-Authorization"))
        headers.replace_header("Location", "https://attacker.example/artifact")
        api.opener.open.side_effect = [urllib.error.HTTPError("https://api.github.com", 302, "Found", headers, io.BytesIO())]
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(contract.ContractError):
            api.request("/repos/LAPKB/desktop-releases/actions/artifacts/7/zip", destination=Path(temporary) / "artifact.zip")

    def test_version_is_derived_from_all_actual_manifest_shapes_and_blob_bound(self):
        for app in github.PRODUCTS:
            root = github.PRODUCTS[app]["root"]
            files = {root + "package.json": canonical({"version": "2.3.4"}),
                     root + "src-tauri/tauri.conf.json": canonical({"productName": contract.WINDOWS_PRODUCTS[app], "identifier": contract.BUNDLE_IDS[app], **({} if app == "bestdose" else {"version": "2.3.4"})}),
                     root + "src-tauri/Cargo.toml": b'[package]\nname="app"\nversion="2.3.4"\n',
                     root + "src-tauri/Cargo.lock": b'[[package]]\nname="app"\nversion="2.3.4"\n'}
            if app in ("papir", "checkerboard"):
                files[root + "package-lock.json"] = canonical({"version": "2.3.4", "packages": {"": {"version": "2.3.4"}}})
            self.assertEqual(desktop.derive_version(files, app)[0], "2.3.4")
            wrong = {**files, root + "src-tauri/Cargo.lock": b'[[package]]\nname="app"\nversion="2.3.5"\n'}
            with self.assertRaisesRegex(contract.ContractError, "Incoherent"):
                desktop.derive_version(wrong, app)
        api = mock.Mock()
        payload = b"actual immutable blob"
        api.request.return_value = {"type": "file", "path": "package.json", "encoding": "base64", "size": len(payload), "content": base64.b64encode(payload).decode(), "sha": hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload, usedforsecurity=False).hexdigest()}
        self.assertEqual(desktop.content(api, "LAPKB/Launcher", "a" * 40, "package.json"), payload)
        api.request.return_value["sha"] = "0" * 40
        with self.assertRaises(contract.ContractError):
            desktop.content(api, "LAPKB/Launcher", "a" * 40, "package.json")


class PublisherRecoveryTests(unittest.TestCase):
    def completion(self):
        plan = fixture_plan()
        execution = {"run": 300, "attempt": 2, "source": "c" * 40}
        def artifact(kind, run, sha, name):
            return {"id": run, "name": name, "expired": False, "size_in_bytes": 1000,
                    "workflow_run": {"id": run, "head_sha": sha, "head_branch": "launcher",
                                     "repository_id": 22, "head_repository_id": 22}}
        bundle = artifact("bundle", 100, plan["publisherSource"], desktop.artifact_name("bundle", plan))
        result = artifact("result", 300, execution["source"], desktop.result_name(plan, execution))
        results = [{"coverage": scope, "version": plan["version"], "status": "published",
                    "inventoryDigest": "d" * 64, "publicLinks": {"downloads": "https://fixture.test/downloads/",
                    "feed": "https://fixture.test/fixture-feed", "installers": ["https://fixture.test/fixture-installer"]}}
                   for scope in ("macos-arm64", "windows-x64")]
        value = {"schema": "lapkb-release-completion-v1", "source": plan, "execution": execution,
                 "results": results, "publicVerification": "complete",
                 "signedBundles": {r["coverage"]: {"inventoryDigest": r["inventoryDigest"], "receiptSha256": "e" * 64} for r in results}}
        files = {r["coverage"] + ".json": canonical(r) for r in results}
        files["complete.json"] = canonical(value)
        run = {"id": 300, "run_attempt": 2, "head_sha": execution["source"], "event": "workflow_dispatch",
               "head_branch": "launcher", "path": ".github/workflows/publish-download.yml",
               "repository": {"full_name": github.PUBLISHER}, "head_repository": {"full_name": github.PUBLISHER},
               "status": "completed", "conclusion": "success"}
        jobs = [{"name": "Sign, publish and verify", "run_id": 300, "run_attempt": 2,
                 "head_sha": execution["source"], "status": "completed", "conclusion": "success",
                 "steps": [{"name": name, "status": "completed", "conclusion": "success"}
                           for name in (desktop.PUBLISH_STEP, desktop.RESULT_STEP)]}]
        api = mock.Mock()
        api.request.return_value = run
        api.pages.return_value = jobs
        return plan, execution, bundle, result, value, files, api

    def test_completion_binds_original_bundle_and_actual_retry_execution_not_upload_only(self):
        plan, execution, bundle, result, value, files, api = self.completion()
        self.assertEqual(desktop.validate_completion(value, files, result, bundle), (plan, execution))
        desktop.validate_publisher_attempt(api, result, plan, execution, desktop.PUBLISH_STEP, "Sign, publish and verify", complete=True)
        for field, wrong in (("run_attempt", 1), ("head_sha", "f" * 40), ("event", "pull_request"),
                             ("head_branch", "arbitrary"), ("conclusion", "failure"), ("status", "in_progress")):
            original = api.request.return_value
            api.request.return_value = {**original, field: wrong}
            with self.subTest(field=field), self.assertRaises(contract.ContractError):
                desktop.validate_publisher_attempt(api, result, plan, execution, desktop.PUBLISH_STEP, "Sign, publish and verify", complete=True)
            api.request.return_value = original
        jobs = api.pages.return_value
        for name in (desktop.PUBLISH_STEP, desktop.RESULT_STEP):
            altered = copy.deepcopy(jobs)
            next(s for s in altered[0]["steps"] if s["name"] == name)["conclusion"] = "skipped"
            api.pages.return_value = altered
            with self.assertRaises(contract.ContractError):
                desktop.validate_publisher_attempt(api, result, plan, execution, desktop.PUBLISH_STEP, "Sign, publish and verify", complete=True)
        api.pages.return_value = jobs
        for change in (lambda v: v["execution"].update(attempt=1), lambda v: v["source"].update(source="f" * 40),
                       lambda v: v["results"].pop(), lambda v: v["results"][0].update(inventoryDigest="f" * 64),
                       lambda v: v.update(publicVerification="partial")):
            wrong = copy.deepcopy(value)
            change(wrong)
            with self.assertRaises(contract.ContractError):
                desktop.validate_completion(wrong, files, result, bundle)
        with self.assertRaises(contract.ContractError):
            desktop.validate_completion(value, {**files, "complete.json": b" " + files["complete.json"]}, result, bundle)

    def test_newer_source_cannot_hide_pending_or_only_partially_verified_prior_version(self):
        plan, execution, bundle, result, value, files, api = self.completion()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            selected = desktop.artifact_name("bundle", {**plan, "version": "2.3.5", "source": "f" * 40})
            with self.assertRaisesRegex(contract.ContractError, "previous.*re-run"):
                desktop.require_completed_prior_bundles(api, [bundle], selected, root, "papir")
            partial = root / "partial"
            partial.mkdir()
            (partial / "macos-arm64.json").write_bytes(files["macos-arm64.json"])
            with mock.patch.object(desktop, "download_evidence", return_value=partial), self.assertRaisesRegex(contract.ContractError, "partially verified"):
                desktop.require_completed_prior_bundles(api, [bundle, result], selected, root, "papir")
            complete = root / "complete"
            complete.mkdir()
            for name, data in files.items():
                (complete / name).write_bytes(data)
            with mock.patch.object(desktop, "download_evidence", return_value=complete):
                desktop.require_completed_prior_bundles(api, [bundle, result], selected, root, "papir")

    def test_public_partial_pair_is_not_hidden_by_a_newer_source_version(self):
        plan = {**fixture_plan(), "version": "2.3.5"}
        policy = mock.Mock(origin="https://fixture.test")
        targets = {"darwin-aarch64": {"version": "2.3.4", "distribution": "signed"}, "windows-x86_64": {"version": "2.3.3", "distribution": "signed"}}
        catalog = {"schema": "lapkb-downloads-v1", "apps": {"papir": {"channels": {"stable": {"targets": targets, "files": {}}}}}}
        with mock.patch.object(publish_artifact, "_fetch_exact", return_value=canonical(catalog)):
            with self.assertRaisesRegex(contract.ContractError, "versions differ"):
                desktop.check_public_version(plan, policy, False)
            desktop.check_public_version(plan, policy, True)
        targets["darwin-aarch64"]["distribution"] = "observed-history"
        with mock.patch.object(publish_artifact, "_fetch_exact", return_value=canonical(catalog)):
            desktop.check_public_version(plan, policy, False)  # First honest upgrade of observed Mac history.

    def test_failed_request_retries_only_on_explicit_original_coordinator_rerun(self):
        old = fixture_source_plan()
        failed = {**fixture_run(old), "conclusion": "failure"}
        artifact = fixture_publisher_artifact(old)
        for attempt, expected in ((1, False), (2, True)):
            with tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                with fixture_planning(work, [(old, artifact)], {old["producerRun"]: failed}, attempt=attempt) as api:
                    desktop.plan_release("papir", "integration", work)
                    selected, action = desktop.load(work / "plan.json"), desktop.load(work / "action.json")
                    self.assertEqual(action["fresh"], expected)
                    self.assertFalse(any("dispatches" in c.args[0] for c in api.request.call_args_list))
                    if expected:
                        self.assertEqual(selected["retryOf"], {"planSha256": hashlib.sha256(canonical(old)).hexdigest(), "request": old["request"], "run": old["producerRun"], "attempt": 1})
                        self.assertNotEqual(selected["request"], old["request"])
                        self.assertNotIn("producerRun", selected)
                        for field in desktop.SOURCE_FIELDS:
                            self.assertEqual(selected[field], old[field])
                    else:
                        self.assertEqual(selected, old)
        with tempfile.TemporaryDirectory() as temporary, fixture_planning(Path(temporary), [(old, artifact)], {old["producerRun"]: failed}, branch_source="c" * 40), self.assertRaisesRegex(contract.ContractError, "branch moved"):
            desktop.plan_release("papir", "integration", Path(temporary))
        env = {"GITHUB_RUN_ID": "200", "GITHUB_RUN_ATTEMPT": "2"}
        with mock.patch.dict(desktop.os.environ, env):
            api = mock.Mock()
            self.assertIsNone(desktop.retry_failed_producer(api, old, "desktop-200-2-" + "e" * 32))
            api.pages.assert_not_called()

    def test_uncertain_dispatch_reconciles_saved_intent_without_blind_repeat(self):
        old = fixture_source_plan()
        failed = {**fixture_run(old), "conclusion": "failure"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            first.mkdir()
            with fixture_planning(first, [(old, fixture_publisher_artifact(old))], {old["producerRun"]: failed}):
                desktop.plan_release("papir", "integration", first)
            retry = desktop.load(first / "plan.json")
            recovered = root / "recovered"
            recovered.mkdir()
            records = [(old, fixture_publisher_artifact(old)), (retry, fixture_publisher_artifact(retry, artifact_id=9))]
            with fixture_planning(recovered, records, {old["producerRun"]: failed}, attempt=3, correlated=[]) as api:
                desktop.plan_release("papir", "integration", recovered)
                selected = desktop.load(recovered / "plan.json")
                self.assertEqual(selected, retry)
                self.assertFalse(desktop.load(recovered / "action.json")["fresh"])
                clock = iter((0, 0, 0, 2))
                with self.assertRaisesRegex(contract.ContractError, "Timed out"):
                    github.wait_for_producer(api, selected, timeout=1, clock=lambda: next(clock), pause=lambda _: None)
                self.assertFalse(any("dispatches" in c.args[0] for c in api.request.call_args_list))
            for alteration in (lambda p: p["retryOf"].update(planSha256="0" * 64), lambda p: p.update(source="c" * 40), lambda p: p.update(publisherAttempt=1)):
                wrong = copy.deepcopy(retry)
                alteration(wrong)
                records = [(old, fixture_publisher_artifact(old)), (wrong, fixture_publisher_artifact(wrong, artifact_id=9))]
                with fixture_planning(root, records, {old["producerRun"]: failed}) as api, self.assertRaises(contract.ContractError):
                    desktop.retained_intent(mock.Mock(), api, [a for _, a in records], "integration", root)
            with fixture_planning(root, [(old, fixture_publisher_artifact(old))], {old["producerRun"]: failed}, correlated=[failed, {**failed, "id": 999}]) as api, self.assertRaisesRegex(contract.ContractError, "Duplicate producer"):
                desktop.retry_failed_producer(api, old, retry["request"])

    def test_original_workflow_rerun_recovers_immutable_source_without_resolving_moved_branch(self):
        old = fixture_plan()
        product = github.PRODUCTS["papir"]
        paths = ("package.json", "src-tauri/tauri.conf.json", "src-tauri/Cargo.toml", "src-tauri/Cargo.lock", "package-lock.json")
        old.update(declarations={"fixture": "2.3.4"}, sourceFiles={p: hashlib.sha256(b"fixture").hexdigest() for p in paths}, producerInputs={"signing_kid": "existing-public-kid", "signing_public_key": "existing-public-key"})
        # A different execution retained signed bytes after the original stopped.
        signed = {**old, "publisherRun": 200}
        bundle = fixture_publisher_artifact(signed, "bundle")
        intent = fixture_publisher_artifact(old, artifact_id=9)
        api, own = mock.Mock(), mock.Mock()
        def response(path):
            if "/git/ref/" in path:
                self.fail("Retry must not resolve a moved source branch")
            return {"full_name": product["repository"], "id": 7} if "/actions/" not in path else {"id": 81, "path": ".github/workflows/tauri.yml", "state": "active"}
        api.request.side_effect = response
        own.pages.return_value = [intent, bundle]
        def contents(_api, _repo, source, path):
            self.assertEqual(source, old["source"])
            return b"release_request: desktop_release: source_sha:" if path.endswith(".yml") else b"lapkb-actions-candidate-v1" if path.endswith(".py") else b"fixture"
        env = {"GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_SHA": "b" * 40,
               "RELEASE_PAPIR_SIGNING_KID": "existing-public-kid", "RELEASE_PAPIR_SIGNING_PUBLIC_KEY": "existing-public-key"}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.dict(desktop.os.environ, env), mock.patch.object(desktop, "publisher_guard", return_value="launcher"), mock.patch.object(desktop, "app_api", return_value=api), mock.patch.object(desktop, "GitHub", return_value=own), mock.patch.object(desktop, "content", side_effect=contents), mock.patch.object(desktop, "derive_version", return_value=("2.3.4", old["declarations"])), mock.patch.object(desktop, "publisher_artifact", side_effect=lambda _api, _artifact, _mode, kind, _workspace: (signed if kind == "bundle" else old, Path(temporary))):
            desktop.plan_release("papir", "integration", Path(temporary))
            self.assertEqual(desktop.load(Path(temporary) / "plan.json"), signed)
            self.assertEqual(desktop.load(Path(temporary) / "action.json")["kind"], "bundle")
            self.assertFalse(desktop.load(Path(temporary) / "action.json")["fresh"])
            api.pages.assert_not_called()


class SignedAutomationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signer = SyntheticSigner()

    @classmethod
    def tearDownClass(cls):
        cls.signer.close()

    def setUp(self):
        self.temp, self.root = make_root()
        _, self.raw = make_trust(self.root, self.signer.public_key, self.signer.key_id, desktop=True)
        for app, entry in self.raw["apps"].items():
            entry.update(sourceRepository=github.PRODUCTS[app]["repository"], branch=github.PRODUCTS[app]["integration"])
        self.policy = contract.validate_policy(self.raw)

    def tearDown(self):
        self.temp.cleanup()

    def publish(self, app, bundle, policy=None):
        policy = policy or self.policy
        stage, files = stage_bundle(publisher, policy, bundle)
        try:
            return publisher.publish_files(policy, app, "stable", files, stage, verifier=VERIFIER)
        finally:
            publisher.remove_staging(policy, stage)

    def validate(self, app, bundle, policy=None):
        policy = policy or self.policy
        stage, files = stage_bundle(publisher, policy, bundle)
        try:
            return contract.validate_release(app, "stable", files, policy, verifier=VERIFIER)
        finally:
            publisher.remove_staging(policy, stage)

    def candidate(self, directory, plan, target):
        directory.mkdir(mode=0o700)
        app, version = plan["app"], plan["version"]
        identity = {"bundleIdentifier": contract.BUNDLE_IDS[app], "displayName": contract.WINDOWS_PRODUCTS[app],
                    "executable": self.policy.apps[app]["executable"], "architecture": target.split("-")[-1], "version": version}
        build = {"runId": str(plan["producerRun"]), "runAttempt": github.producer_attempt(plan), "profile": "public-staging"}
        def file(name, payload):
            prepare_bundle.write_new(directory / name, payload)
            return {"filename": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        if target == "darwin-aarch64":
            items = [file("fixture.app.tar.gz", b"explicit synthetic archive fixture"), file("fixture.dmg", b"explicit synthetic DMG fixture")]
            proof = {"schema": "lapkb-macos-package-v1", "packageIdentity": identity,
                     "artifacts": items, "updater": items[0]["filename"], "checks": ["ad-hoc seal", "tar identity and DMG sealed payload"]}
        else:
            installed = b"explicit synthetic compiled app fixture"
            proof = {"schema": "lapkb-windows-package-v1", "compiledApplication": file("fixture-app.exe", installed),
                     "installer": {**file("fixture-nsis.exe", b"explicit synthetic NSIS fixture"), "kind": "nsis", "stubMachine": 0x14c},
                     "windowsPayload": {"schema": "lapkb-windows-payload-v1", "productName": contract.WINDOWS_PRODUCTS[app], "executable": identity["executable"] + ".exe", "architecture": "x86_64", "version": version, "installMode": "currentUser", "files": [{"path": identity["executable"] + ".exe", "size": len(installed), "sha256": hashlib.sha256(installed).hexdigest()}]}}
        proof.update(app=app, version=version, sourceCommit=plan["source"], target=target, build=build)
        prepare_bundle.write_new(directory / ("macos-package.json" if target == "darwin-aarch64" else "windows-package.json"), canonical(proof))
        inventory = github.inventory(directory)
        candidate = {"schema": "lapkb-actions-candidate-v1", "app": app, "repository": plan["repository"],
                     "workflow": github.PRODUCTS[app]["workflow"], "workflowRef": f"{plan['repository']}/.github/workflows/{github.PRODUCTS[app]['workflow']}@refs/heads/{plan['branch']}",
                     "source": plan["source"], "version": version, "target": target, "request": plan["request"],
                     "runId": str(plan["producerRun"]), "runAttempt": github.producer_attempt(plan), "job": github.PRODUCTS[app]["jobs"][target][0],
                     "inventory": inventory, "inventoryDigest": hashlib.sha256(canonical(inventory)).hexdigest()}
        prepare_bundle.write_new(directory / "release-candidate.json", canonical(candidate))

    def prepared(self, plan=None):
        work = self.root.parent / "work"
        work.mkdir(mode=0o700)
        candidates = work / "candidates"
        candidates.mkdir(mode=0o700)
        plan = plan or fixture_plan()
        for target in github.TARGETS:
            self.candidate(candidates / target, plan, target)
        signer = mock.Mock()
        signer.sign.side_effect = lambda path, scratch: self.signer.sign(path.read_bytes())
        output = work / "bundle"
        meta = prepare_bundle.prepare(plan, self.policy, candidates, output, signer, VERIFIER)
        return plan, output, meta, signer

    def test_transient_failed_or_cancelled_producer_explicit_retry_collects_same_source_pair(self):
        for conclusion in ("failure", "cancelled"):
            with self.subTest(conclusion=conclusion):
                old = fixture_source_plan()
                failed = {**fixture_run(old), "conclusion": conclusion}
                work = self.root.parent / ("retry-" + conclusion)
                work.mkdir(mode=0o700)
                with fixture_planning(work, [(old, fixture_publisher_artifact(old))], {old["producerRun"]: failed}):
                    desktop.plan_release("papir", "integration", work)
                    plan, action = desktop.load(work / "plan.json"), desktop.load(work / "action.json")
                    self.assertTrue(action["fresh"])
                    # Fixture for the workflow's immutable upload-before-POST step.
                    desktop.save(work / "persisted-retry-intent.json", plan)
                    bound = {**plan, "producerRun": 23456}
                    packages = work / "producer"
                    packages.mkdir()
                    archives = {}
                    for target in github.TARGETS:
                        directory = packages / target
                        self.candidate(directory, bound, target)
                        payload = io.BytesIO()
                        with zipfile.ZipFile(payload, "w") as archive:
                            for path in directory.iterdir():
                                archive.writestr(path.name, path.read_bytes())
                        archives[target] = payload.getvalue()
                    api = mock.Mock()
                    artifacts = fixture_artifacts(bound)
                    api.pages.side_effect = [[fixture_run(bound)], fixture_jobs(bound), artifacts]
                    def response(path, *, body=None, destination=None, work=work,
                                 plan=copy.deepcopy(plan), old=old, bound=bound,
                                 artifacts=artifacts, archives=archives):
                        if path.endswith("/dispatches"):
                            self.assertEqual(desktop.load(work / "persisted-retry-intent.json"), plan)
                            self.assertEqual(body["inputs"]["source_sha"], old["source"])
                            self.assertEqual(body["inputs"]["release_request"], plan["request"])
                            return None
                        if destination:
                            target = next(t for t, a in zip(github.TARGETS, artifacts, strict=True) if f"/artifacts/{a['id']}/" in path)
                            destination.write_bytes(archives[target])
                            return None
                        return fixture_run(bound)
                    api.request.side_effect = response
                    with mock.patch.object(desktop, "app_api", return_value=api):
                        desktop.build(plan, action, work)
                    self.assertEqual(sum("dispatches" in c.args[0] for c in api.request.call_args_list), 1)
                built = desktop.load(work / "built-plan.json")
                self.assertEqual((built["source"], built["version"], built["producerRun"], built["producerAttempt"]), (old["source"], old["version"], 23456, 1))
                signer = mock.Mock()
                signer.sign.side_effect = lambda path, scratch: self.signer.sign(path.read_bytes())
                output = work / "bundle"
                prepare_bundle.prepare(built, self.policy, work / "candidates", output, signer, VERIFIER)
                releases = prepare_bundle.validate_bundles(built, self.policy, output, VERIFIER)
                self.assertEqual(set(releases), {"macos-arm64", "windows-x64"})
                self.assertTrue(all(t["build"] == {"runId": "23456", "runAttempt": 1, "profile": "public-staging"} for r in releases.values() for t in r["receipt"]["targets"].values()))
                for target in github.TARGETS:
                    with self.assertRaises(contract.ContractError):
                        github.validate_candidate(work / "candidates" / target, {**built, "producerAttempt": 2}, target)
                    with self.assertRaises(contract.ContractError):
                        prepare_bundle.read_proof(work / "candidates" / target, {**built, "producerRun": old["producerRun"]}, target, self.policy)

    def test_preparation_canonical_parity_original_inventory_and_native_signatures(self):
        plan, output, meta, signer = self.prepared()
        releases = prepare_bundle.validate_bundles(plan, self.policy, output, VERIFIER)
        self.assertEqual(set(releases), {"macos-arm64", "windows-x64"})
        self.assertEqual(signer.sign.call_count, 6)
        self.assertEqual(set(releases["macos-arm64"]["files"]) & set(releases["windows-x64"]["files"]), set())
        for scope, release in releases.items():
            self.assertEqual(release["manifestBytes"], contract._expected_manifest(self.policy, "papir", "stable", plan["version"], release["attestation"]))
            self.assertEqual(release["receiptBytes"], canonical(contract._expected_receipt(self.policy, "papir", "stable", plan["version"], release["attestation"], release["manifestBytes"])))
            self.assertEqual(meta["bundles"][scope]["inventoryDigest"], release["inventoryDigest"])
        meta_path = output / "automation.json"
        retained_meta = meta_path.read_bytes()
        meta_path.write_bytes(b" " + retained_meta)
        with self.assertRaises(contract.ContractError):
            prepare_bundle.validate_bundles(plan, self.policy, output, VERIFIER)
        meta_path.unlink()
        with self.assertRaises(contract.ContractError):
            prepare_bundle.validate_bundles(plan, self.policy, output, VERIFIER)
        meta_path.write_bytes(retained_meta)
        original = output.parent / "candidates" / "windows-x86_64" / "fixture-app.exe"
        original.write_bytes(b"tampered compiled PE")
        with self.assertRaises(contract.ContractError):
            prepare_bundle.read_proof(original.parent, plan, "windows-x86_64", self.policy)

    def test_key_signature_identity_target_and_inventory_tampering_rejected(self):
        bundle = make_bundle(self.signer, self.policy, app="papir", version="2.3.4", coverage="macos-arm64")
        for name in list(bundle):
            if name.endswith(".sig") or name.endswith(".app.tar.gz"):
                wrong = {**bundle, name: bundle[name] + b"tamper"}
                with self.subTest(name=name), self.assertRaises(contract.ContractError):
                    self.validate("papir", wrong)
        other = SyntheticSigner()
        try:
            wrong = make_bundle(other, self.policy, app="papir", version="2.3.4", coverage="macos-arm64")
            with self.assertRaises(contract.ContractError):
                self.validate("papir", wrong)
        finally:
            other.close()
        att_name, _ = contract.metadata_names("2.3.4", "macos-arm64")
        att = json.loads(bundle[att_name])
        att["targets"]["darwin-aarch64"]["packageIdentity"]["bundleIdentifier"] = "attacker.bundle"
        wrong = {**bundle, att_name: canonical(att), att_name + ".sig": self.signer.sign(canonical(att))}
        with self.assertRaises(contract.ContractError):
            self.validate("papir", wrong)

    def test_both_feeds_and_existing_mac_reader_origin_directory_are_preserved(self):
        for app in ("papir", "bestdose", "bdautodial", "checkerboard"):
            mac = make_bundle(self.signer, self.policy, app=app, version="2.3.4", coverage="macos-arm64")
            windows = make_bundle(self.signer, self.policy, app=app, version="2.3.4", coverage="windows-x64")
            self.publish(app, mac)
            self.publish(app, windows)
            mac_feed = json.loads(mac["latest.json"])
            win_feed = json.loads(windows["latest-windows.json"])
            self.assertEqual(set(mac_feed["platforms"]), {"darwin-aarch64"})
            self.assertEqual(set(win_feed["platforms"]), {"windows-x86_64"})
            parent = self.policy.apps[app]["channels"]["stable"]["macFeedUrl"].rsplit("/", 1)[0]
            self.assertTrue(mac_feed["platforms"]["darwin-aarch64"]["url"].startswith(parent + "/"))
            publisher.recover_publications(self.policy, verifier=VERIFIER)
        catalog = json.loads((self.root / "downloads/catalog.json").read_bytes())
        for app in ("papir", "bestdose", "bdautodial", "checkerboard"):
            entry = catalog["apps"][app]["channels"]["stable"]
            self.assertEqual(entry["version"], "2.3.4")
            self.assertEqual(entry["targets"]["darwin-aarch64"]["feed"], "latest.json")
            self.assertEqual(entry["targets"]["windows-x86_64"]["feed"], "latest-windows.json")

    def test_partial_failure_retries_only_immutable_signed_bytes_and_preserves_other_apps(self):
        self.publish("bestdose", make_bundle(self.signer, self.policy, app="bestdose", version="2.3.3", coverage="macos-arm64"))
        before = public_snapshot(self.root)
        # Legacy retained bundles omit producerAttempt but bind exact attempt 1.
        plan, output, _, signer = self.prepared({k: v for k, v in fixture_plan().items() if k != "producerAttempt"})
        signed_before = {str(p.relative_to(output)): p.read_bytes() for p in output.rglob("*") if p.is_file()}
        def writer(app, channel, directory):
            bundle = {p.name: p.read_bytes() for p in directory.iterdir()}
            result = self.publish(app, bundle)
            # Exercise the real existing public verifier using actual writer
            # outputs on the isolated filesystem, not mocked green results.
            release = self.validate(app, bundle)
            def fetch(url, policy, maximum, expected=None):
                if url.startswith("https://mac-feed.example.test/"):
                    relative = url.removeprefix("https://mac-feed.example.test/")
                else:
                    relative = url.removeprefix(self.policy.origin + "/")
                if relative.endswith("/"):
                    relative += "index.html"
                data = (self.root / relative).read_bytes()
                if expected is None:
                    return data
                self.assertEqual((len(data), hashlib.sha256(data).hexdigest()), (expected["size"], expected["sha256"]))
                return expected
            with mock.patch.object(publish_artifact, "_fetch_exact", side_effect=fetch):
                publish_artifact._verify_served(self.policy, release, result)
            return {"version": release["version"], "coverage": release["coverage"], "status": result["status"], "inventoryDigest": release["inventoryDigest"], "publicLinks": {"downloads": self.policy.origin + "/downloads/", "feed": self.policy.origin + "/downloads/papir/stable/" + release["feed"], "installers": []}}
        calls = []
        def interrupted(app, channel, directory):
            calls.append(directory.name)
            if len(calls) == 2:
                raise contract.ContractError("interrupted after Mac promotion")
            return writer(app, channel, directory)
        with self.assertRaises(contract.ContractError):
            desktop.publish_pair(plan, self.policy, output, VERIFIER, output.parent / "first-results", publish=interrupted)
        publisher.recover_publications(self.policy, verifier=VERIFIER)
        action = {"kind": "bundle", "fresh": False, "artifact": fixture_publisher_artifact(plan, "bundle")}
        recovery = output.parent / "recovery"
        recovery.mkdir(mode=0o700)
        with mock.patch.object(desktop, "publisher_guard"), mock.patch.object(desktop, "app_api") as api, mock.patch.object(desktop, "wait_for_producer") as wait:
            desktop.build(plan, action, recovery)
            api.assert_not_called()
            wait.assert_not_called()
        with mock.patch.object(desktop, "GitHub"), mock.patch.object(desktop, "publisher_artifact", return_value=(plan, output)):
            output = desktop.restore_bundle(plan, action, recovery)
        self.assertEqual(signed_before, {str(p.relative_to(output)): p.read_bytes() for p in output.rglob("*") if p.is_file()})
        results = desktop.publish_pair(plan, self.policy, output, VERIFIER, output.parent / "retry-results", publish=writer, execution={"run": 100, "attempt": 2, "source": "b" * 40})
        self.assertEqual([r["status"] for r in results], ["identical-retry", "published"])
        self.assertEqual(signer.sign.call_count, 6)
        self.assertEqual(signed_before, {str(p.relative_to(output)): p.read_bytes() for p in output.rglob("*") if p.is_file()})
        after = public_snapshot(self.root)
        for path, info in before.items():
            if path.startswith("downloads/bestdose/"):
                self.assertEqual(after[path], info)
        with self.assertRaises(contract.ContractError):
            self.publish("papir", make_bundle(self.signer, self.policy, app="papir", version="2.3.4", coverage="macos-arm64", nonce="different bytes"))

    def test_main_transition_requires_exact_whole_history_pins_not_a_branch_allowlist(self):
        for app, coverage in (("launcher", "launcher-desktop"), ("papir", "macos-arm64"), ("papir", "windows-x64")):
            self.publish(app, make_bundle(self.signer, self.policy, app=app, version="2.3.4", coverage=coverage))
        before = public_snapshot(self.root)
        state_path = self.root / publisher.STATE_NAME / publisher.STATE_FILE
        state_bytes = state_path.read_bytes()
        state = json.loads(state_bytes)
        main_raw = copy.deepcopy(self.raw)
        for app, entry in main_raw["apps"].items():
            entry["branch"] = "main"
            records = [r for r in state["history"] if r["app"] == app]
            if records:
                entry["retainedSourceRecords"] = sorted(hashlib.sha256(canonical(r)).hexdigest() for r in records)
        main = contract.validate_policy(main_raw)
        publisher.recover_publications(main, verifier=VERIFIER)
        self.assertEqual(state_path.read_bytes(), state_bytes)
        self.assertEqual(public_snapshot(self.root), before)
        for field in ("source", "receiptSha256", "inventoryDigest"):
            changed = copy.deepcopy(state)
            if field == "source":
                changed["history"][0][field]["commit"] = "c" * 40
            else:
                changed["history"][0][field] = "c" * 64
            with self.subTest(field=field), self.assertRaises(contract.ContractError):
                publisher._validate_state(canonical(changed), main)
        stale_branch = make_bundle(self.signer, self.policy, app="papir", version="2.3.5", coverage="macos-arm64")
        with self.assertRaisesRegex(contract.ContractError, "branch"):
            self.publish("papir", stale_branch, main)
        old_exact = make_bundle(self.signer, self.policy, app="papir", version="2.3.4", coverage="macos-arm64")
        with self.assertRaisesRegex(contract.ContractError, "branch"):
            self.publish("papir", old_exact, main)
        att_name, _ = contract.metadata_names("2.3.5", "macos-arm64")
        self.assertIs(contract.retained_policy(main, json.loads(stale_branch[att_name])), main)
        self.publish("papir", make_bundle(self.signer, main, app="papir", version="2.3.5", coverage="macos-arm64"), main)
        publisher.recover_publications(main, verifier=VERIFIER)

    def test_manual_history_needs_independent_manual_and_retired_source_pins(self):
        _, manual_raw = make_trust(self.root, self.signer.public_key, self.signer.key_id, windows_only=True)
        for app, entry in manual_raw["apps"].items():
            entry.update(sourceRepository=self.raw["apps"][app]["sourceRepository"], branch=self.raw["apps"][app]["branch"])
        manual = contract.validate_policy(manual_raw)
        observed = make_historical_input(self.root, manual)
        inventory = self.root.parent / "observed-history.json"
        prepare_bundle.write_new(inventory, canonical(observed))
        publisher.initialize_history(manual, inventory, hashlib.sha256(inventory.read_bytes()).hexdigest())
        self.publish("launcher", make_bundle(None, manual, app="launcher", version="0.1.9", coverage="windows-x64"), manual)
        state_path = self.root / publisher.STATE_NAME / publisher.STATE_FILE
        original = state_path.read_bytes()
        record = next(r for r in json.loads(original)["history"] if r["app"] == "launcher")
        digest = hashlib.sha256(canonical(record)).hexdigest()
        new_raw = copy.deepcopy(self.raw)
        new_raw["apps"]["launcher"].update(branch="main", retainedSourceRecords=[digest], retainedManualRecords={"0.1.9": digest})
        main = contract.validate_policy(new_raw)
        publisher.recover_publications(main, verifier=VERIFIER)
        self.assertEqual(state_path.read_bytes(), original)
        wrong = copy.deepcopy(new_raw)
        wrong["apps"]["launcher"]["retainedManualRecords"] = {"0.1.9": "0" * 64}
        with self.assertRaises(contract.ContractError):
            publisher.recover_publications(contract.validate_policy(wrong), verifier=VERIFIER)
        self.publish("launcher", make_bundle(self.signer, main, app="launcher", version="0.1.13", coverage="launcher-desktop"), main)
        self.assertIn(record, json.loads(state_path.read_bytes())["history"])

    def test_cross_feed_same_version_different_source_is_rejected(self):
        self.publish("papir", make_bundle(self.signer, self.policy, app="papir", version="2.3.4", coverage="macos-arm64"))
        other_raw = copy.deepcopy(self.raw)
        other_raw["apps"]["papir"]["branch"] = "main"
        old_state = json.loads((self.root / publisher.STATE_NAME / publisher.STATE_FILE).read_bytes())
        other_raw["apps"]["papir"]["retainedSourceRecords"] = [hashlib.sha256(canonical(old_state["history"][0])).hexdigest()]
        other = contract.validate_policy(other_raw)
        with self.assertRaisesRegex(contract.ContractError, "identical source"):
            self.publish("papir", make_bundle(self.signer, other, app="papir", version="2.3.4", coverage="windows-x64"), other)

    def test_catalog_filename_target_mapping_page_links_and_mac_feed_bytes_are_compulsory(self):
        bundle = make_bundle(self.signer, self.policy, app="papir", version="2.3.4", coverage="macos-arm64")
        release = self.validate("papir", bundle)
        catalog, page = publisher._outputs({"release": release}, {"historical": None, "history": [publisher._record_from_release(release)]})
        def fetch(url, policy, maximum, expected=None):
            if url.endswith("/catalog.json"):
                return catalog
            if url.endswith("/index.html") or url.endswith("/downloads/"):
                return page
            return bundle[url.rsplit("/", 1)[-1]] if expected is None else expected
        result = publisher._publication_result(release, "published")
        with mock.patch.object(publish_artifact, "_fetch_exact", side_effect=fetch):
            publish_artifact._verify_served(self.policy, release, result)
        original_catalog, original_page = catalog, page
        parsed = json.loads(catalog)
        parsed["apps"]["papir"]["channels"]["stable"]["targets"]["darwin-aarch64"]["feed"] = "latest-windows.json"
        catalog = canonical(parsed)
        with mock.patch.object(publish_artifact, "_fetch_exact", side_effect=fetch), self.assertRaises(contract.ContractError):
            publish_artifact._verify_served(self.policy, release, result)
        catalog = original_catalog
        for bad in (original_page.replace(b'href="/downloads/papir/', b'href="/wrong/'), original_page + original_page, b"<base href='https://attacker.example'>" + original_page):
            page = bad
            with mock.patch.object(publish_artifact, "_fetch_exact", side_effect=fetch), self.assertRaises(contract.ContractError):
                publish_artifact._verify_served(self.policy, release, result)
        page = original_page
        def wrong_reader(url, policy, maximum, expected=None):
            return b"wrong retained Mac feed" if url == self.policy.apps["papir"]["channels"]["stable"]["macFeedUrl"] else fetch(url, policy, maximum, expected)
        with mock.patch.object(publish_artifact, "_fetch_exact", side_effect=wrong_reader), self.assertRaises(contract.ContractError):
            publish_artifact._verify_served(self.policy, release, result)


if __name__ == "__main__":
    unittest.main()
