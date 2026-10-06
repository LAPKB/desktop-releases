"""The one manual desktop-release coordinator, used only by publish-download.yml.

Plan -> protected setup gate -> credential-free candidate collection -> protected
canonical signing -> immutable Actions retention -> existing receive-v1 writer.
Explicit retries recover signed bytes first; only a proven failed/cancelled
producer may get one new, same-source request after its retry intent is retained.
There is no operator source-ref, version, hash, artifact-path or key input.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tomllib
import urllib.parse
from pathlib import Path

from release_github import (AppToken, GitHub, PRODUCTS, PUBLISHER, REQUEST, SHA, TARGETS,
    Error, extract_archive, find_producer, producer_attempt, require, validate_candidate, validate_run, wait_for_producer)
import release_contract as contract
import publish_artifact
import prepare_bundle

WORKFLOW = "publish-download.yml"


def load(path):
    raw = contract._read_regular(Path(path), 2 * 1024 * 1024, "release plan")
    return contract.strict_json(raw, 2 * 1024 * 1024, "release plan")


def save(path, value):
    prepare_bundle.write_new(path, contract.canonical_json(value))


def publisher_guard(mode):
    branch = "main" if mode == "main" else "launcher"
    require(mode in ("main", "integration") and os.environ.get("GITHUB_REPOSITORY") == PUBLISHER and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and os.environ.get("GITHUB_REF") == "refs/heads/" + branch, "Release authorization permits only publisher main/main mode or launcher/integration mode; tags, PRs and arbitrary refs cannot publish")
    sha = os.environ.get("GITHUB_SHA", "")
    require(SHA.fullmatch(sha) and os.environ.get("GITHUB_WORKFLOW_SHA") == sha and os.environ.get("GITHUB_WORKFLOW_REF") == f"{PUBLISHER}/.github/workflows/{WORKFLOW}@refs/heads/{branch}", "Publisher workflow/source identity differs")
    checked = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    require(checked == sha, "Publisher checkout must be its explicit immutable workflow source")
    return branch


def app_api(app, workspace, *, dispatch=False):
    key = workspace / "app-private-key.pem"
    if not key.exists():
        value = os.environ.get("RELEASE_APP_PRIVATE_KEY")
        require(value, "Missing RELEASE_APP_PRIVATE_KEY; an administrator must install the narrow dispatch/read GitHub App")
        prepare_bundle.write_new(key, value.encode())
    publish_artifact._owned_regular_file(str(key), private=True)
    return GitHub(AppToken(os.environ.get("RELEASE_APP_ID", ""), key, PRODUCTS[app]["repository"], actions="write" if dispatch else "read"))


def content(api, repository, source, path):
    data = api.request(f"/repos/{repository}/contents/{path}?ref={source}")
    require(type(data) is dict and data.get("type") == "file" and data.get("path") == path and data.get("encoding") == "base64" and type(data.get("size")) is int and 0 < data["size"] <= 2 * 1024 * 1024, f"Missing or oversized source manifest/workflow: {path}")
    try:
        raw = base64.b64decode(data["content"].replace("\n", ""), validate=True)
    except (KeyError, ValueError, TypeError) as error:
        raise Error(f"Invalid GitHub source response: {path}") from error
    require(len(raw) == data["size"] and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw, usedforsecurity=False).hexdigest() == data.get("sha"), f"Immutable source blob identity differs: {path}")
    return raw


def derive_version(files, app):
    root = PRODUCTS[app]["root"]
    package = contract.strict_json(files[root + "package.json"], 2 * 1024 * 1024, "package.json")
    tauri = contract.strict_json(files[root + "src-tauri/tauri.conf.json"], 2 * 1024 * 1024, "tauri.conf.json")
    cargo = tomllib.loads(files[root + "src-tauri/Cargo.toml"].decode())["package"]
    lock = tomllib.loads(files[root + "src-tauri/Cargo.lock"].decode())["package"]
    own = [entry for entry in lock if entry.get("name") == cargo["name"] and "source" not in entry]
    require(len(own) == 1, "Cargo.lock must bind exactly one local application package")
    declarations = {"package.json": package["version"], "Cargo.toml": cargo["version"], "Cargo.lock": own[0]["version"], "tauri.conf.json (effective)": tauri.get("version", package["version"])}
    if root + "package-lock.json" in files:
        npm = contract.strict_json(files[root + "package-lock.json"], 2 * 1024 * 1024, "package-lock.json")
        declarations.update({"package-lock.json": npm["version"], "package-lock.json root": npm["packages"][""]["version"]})
    version = package["version"]
    contract._version(version)
    require(all(value == version for value in declarations.values()), "Incoherent product version declarations: " + json.dumps(declarations, sort_keys=True))
    require(tauri.get("identifier") == contract.BUNDLE_IDS[app] and tauri.get("productName") == contract.WINDOWS_PRODUCTS[app], "Product source package identity differs from the approved application")
    return version, declarations


def artifact_name(kind, plan):
    name = f"release-{kind}-{plan['app']}-{plan['version']}-{plan['source']}"
    if kind == "intent" and "retryOf" in plan:
        name += f"-{plan['publisherRun']}-{plan['publisherAttempt']}"
    return name


PUBLISH_STEP = "Publish through receive-v1 and verify both public feeds, files, catalog and page"
RESULT_STEP = "Retain real publication/reconciliation results"


def execution_identity():
    return {"run": int(os.environ["GITHUB_RUN_ID"]), "attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "source": os.environ["GITHUB_SHA"]}


def result_name(plan, execution):
    return artifact_name("result", plan) + f"-{execution['run']}-{execution['attempt']}"


def validate_publisher_attempt(api, artifact, plan, execution, step_name, job_name, *, complete=False):
    branch = "main" if plan["mode"] == "main" else "launcher"
    require(plan["mode"] in ("main", "integration") and plan["publisherBranch"] == branch, "Retained publisher mode/ref differs")
    run_id, attempt, sha = execution["run"], execution["attempt"], execution["source"]
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0 and type(sha) is str and SHA.fullmatch(sha), "Malformed retained publisher execution identity")
    identity = artifact.get("workflow_run")
    require(type(identity) is dict and identity.get("id") == run_id and identity.get("head_sha") == sha and identity.get("head_branch") == branch and type(identity.get("repository_id")) is int and identity.get("repository_id") == identity.get("head_repository_id"), "Retained artifact workflow/source identity differs")
    exact = api.request(f"/repos/{PUBLISHER}/actions/runs/{run_id}/attempts/{attempt}")
    require(type(exact) is dict and type(exact.get("repository")) is dict and type(exact.get("head_repository")) is dict and exact.get("repository", {}).get("full_name") == PUBLISHER and exact.get("head_repository", {}).get("full_name") == PUBLISHER and exact.get("head_sha") == sha and type(exact.get("run_attempt")) is int and exact["run_attempt"] == attempt and exact.get("id") == run_id and exact.get("event") == "workflow_dispatch" and exact.get("head_branch") == branch and exact.get("path") == ".github/workflows/" + WORKFLOW, "Retained artifact exact publisher attempt differs")
    require(not complete or (exact.get("status") == "completed" and exact.get("conclusion") == "success"), "Publication completion is not a successful completed publisher attempt")
    jobs = api.pages(f"/repos/{PUBLISHER}/actions/runs/{run_id}/attempts/{attempt}/jobs", "jobs")
    require(all(type(j) is dict for j in jobs), "Malformed publisher job inventory")
    matches = [j for j in jobs if j.get("name") == job_name and j.get("run_id") == run_id and j.get("run_attempt") == attempt and j.get("head_sha") == sha]
    require(len(matches) == 1 and type(matches[0].get("steps")) is list, "Retained artifact exact authorized job is missing/ambiguous")
    steps = matches[0]["steps"]
    require(all(type(s) is dict for s in steps) and sum(s.get("name") == step_name and s.get("conclusion") == "success" and s.get("status") == "completed" for s in steps) == 1, "Retained artifact upload/publication step is not proven by its exact authorized attempt")
    if complete:
        require(matches[0].get("status") == "completed" and matches[0].get("conclusion") == "success" and sum(s.get("name") == RESULT_STEP and s.get("status") == "completed" and s.get("conclusion") == "success" for s in steps) == 1, "Publication completion result upload/job did not succeed")


def download_evidence(api, artifact, kind, workspace):
    require(type(artifact) is dict and artifact.get("expired") is False and type(artifact.get("id")) is int and artifact["id"] > 0 and type(artifact.get("size_in_bytes")) is int and 0 < artifact["size_in_bytes"] <= (contract.MAX_RELEASE_BYTES if kind == "bundle" else 2 * 1024 * 1024), "Retained release evidence is expired/malformed; never regenerate a potentially published version")
    label = f"{kind}-{artifact['id']}"
    archive = workspace / (label + ".zip")
    api.request(f"/repos/{PUBLISHER}/actions/artifacts/{artifact['id']}/zip", destination=archive)
    return extract_archive(archive, workspace / label, nested=kind == "bundle")


def publisher_artifact(api, artifact, mode, kind, workspace):
    directory = download_evidence(api, artifact, kind, workspace)
    stored = load(directory / ("automation.json" if kind == "bundle" else "plan.json"))
    plan = stored["plan"] if kind == "bundle" else stored
    require(type(plan) is dict and plan.get("mode") == mode and type(plan.get("request")) is str and REQUEST.fullmatch(plan["request"]), "Retained artifact source/mode/request identity differs")
    execution = {"run": plan["publisherRun"], "attempt": plan["publisherAttempt"], "source": plan["publisherSource"]}
    validate_publisher_attempt(api, artifact, plan, execution, "Retain exact signed bundles before the writer" if kind == "bundle" else "Persist release intent before any dispatch", "Sign, publish and verify" if kind == "bundle" else "Build qualified candidates")
    require(artifact["name"] == artifact_name(kind, plan), "Retained artifact filename differs from its immutable release source")
    return plan, directory


def validate_completion(value, files, artifact, bundle):
    require(type(value) is dict and set(value) == {"schema", "source", "execution", "results", "signedBundles", "publicVerification"} and value["schema"] == "lapkb-release-completion-v1" and value["publicVerification"] == "complete", "Missing/malformed publication completion")
    plan, execution = value["source"], value["execution"]
    require(type(plan) is dict and type(execution) is dict and set(execution) == {"run", "attempt", "source"} and artifact["name"] == result_name(plan, execution) and bundle["name"] == artifact_name("bundle", plan), "Publication completion source/result identity differs")
    identity = bundle.get("workflow_run", {})
    require(identity.get("id") == plan["publisherRun"] and identity.get("head_sha") == plan["publisherSource"] and identity.get("head_branch") == plan["publisherBranch"], "Completion does not bind the original retained signed bundle")
    scopes = {"launcher-desktop"} if plan["app"] == "launcher" else {"macos-arm64", "windows-x64"}
    results, signed = value["results"], value["signedBundles"]
    require(type(results) is list and len(results) == len(scopes) and type(signed) is dict and set(signed) == scopes and set(files) == {"complete.json"} | {s + ".json" for s in scopes}, "Publication completion lacks the complete exact target pair")
    require(all(type(r) is dict for r in results) and {r.get("coverage") for r in results} == scopes, "Completion contains mixed/duplicate target results")
    for result in results:
        scope = result["coverage"]
        require(type(signed[scope]) is dict and set(signed[scope]) == {"inventoryDigest", "receiptSha256"} and all(type(v) is str and contract._HEX.fullmatch(v) for v in signed[scope].values()) and result.get("version") == plan["version"] and result.get("status") in ("published", "identical-retry") and result.get("inventoryDigest") == signed[scope]["inventoryDigest"] and type(result.get("publicLinks")) is dict and files[scope + ".json"] == contract.canonical_json(result), "Completion result bytes differ from the signed pair")
    require(files["complete.json"] == contract.canonical_json(value), "Completion evidence is noncanonical")
    return plan, execution


def require_completed_prior_bundles(api, artifacts, selected_name, workspace, app):
    # A moved source/version cannot hide an interrupted public verification.
    # Re-run the original workflow to reconcile its retained immutable source.
    for bundle in artifacts:
        if not bundle["name"].startswith(f"release-bundle-{app}-") or bundle["name"] == selected_name:
            continue
        prefix = bundle["name"].replace("release-bundle-", "release-result-", 1) + "-"
        completions = [a for a in artifacts if a["name"].startswith(prefix)]
        require(completions, f"A previous {app} release has no complete public verification: re-run publisher run {bundle.get('workflow_run', {}).get('id')} before starting another version")
        proven = False
        for artifact in completions:
            directory = download_evidence(api, artifact, "result", workspace)
            files = {p.name: contract._read_regular(p, 2 * 1024 * 1024, "publication evidence") for p in directory.iterdir()}
            if "complete.json" not in files:
                continue  # Retained partial result, not a successful release.
            value = contract.strict_json(files["complete.json"], 2 * 1024 * 1024, "publication completion")
            plan, execution = validate_completion(value, files, artifact, bundle)
            validate_publisher_attempt(api, artifact, plan, execution, PUBLISH_STEP, "Sign, publish and verify", complete=True)
            proven = True
        require(proven, f"Previous {app} release is only partially verified: re-run publisher run {bundle.get('workflow_run', {}).get('id')}; no new signing/build may hide it")


SOURCE_FIELDS = ("app", "mode", "repository", "repositoryId", "branch", "source", "version", "declarations", "sourceFiles", "workflowId", "producerInputs")


def retained_intent(own, api, artifacts, mode, workspace):
    """Follow a single proven retry chain, never select an unrelated/latest build."""
    require(1 <= len(artifacts) <= 64, "Missing/oversized retained intent chain")
    records = [(publisher_artifact(own, a, mode, "intent", workspace)[0], a) for a in artifacts]
    records.sort(key=lambda r: r[0]["publisherAttempt"])
    require("retryOf" not in records[0][0], "Original dispatch intent is missing; no blind retry")
    for (prior, _), (current, _) in zip(records, records[1:], strict=False):
        retry = current.get("retryOf")
        require(type(retry) is dict and set(retry) == {"planSha256", "request", "run", "attempt"} and type(retry.get("run")) is int and retry["run"] > 0 and type(retry.get("attempt")) is int and retry["attempt"] == producer_attempt(prior), "Ambiguous/malformed producer retry predecessor")
        require(all(current.get(k) == prior.get(k) for k in SOURCE_FIELDS + ("publisherRun", "publisherSource", "publisherBranch")) and current["publisherAttempt"] > prior["publisherAttempt"] and current["request"] != prior["request"] and producer_attempt(current) == 1 and "producerRun" not in current and retry["request"] == prior["request"] and retry["planSha256"] == hashlib.sha256(contract.canonical_json(prior)).hexdigest(), "Duplicate, mixed-source or disconnected producer retry intents")
        failed = api.request(f"/repos/{prior['repository']}/actions/runs/{retry['run']}/attempts/{retry['attempt']}")
        validate_run(failed, {**prior, "producerRun": retry["run"]})
        require(failed["status"] == "completed" and failed.get("conclusion") in ("failure", "cancelled"), "Retry predecessor is not a proven failed/cancelled producer")
    return records[-1]


def retry_failed_producer(api, plan, request):
    """An explicit original-coordinator rerun can retry once, not an agent loop.

    A new workflow dispatch starts attempt 1 with a new correlation identity.
    The old source/config remain frozen, and the existing producer guards still
    demand the trusted branch's exact head. An uncertain dispatch is joined,
    never repeated; its retained intent remains the head of this chain.
    """
    if int(os.environ["GITHUB_RUN_ID"]) != plan["publisherRun"] or int(os.environ["GITHUB_RUN_ATTEMPT"]) <= plan["publisherAttempt"]:
        return None
    run = find_producer(api, plan)
    if run is None:
        return None  # Uncertain prior dispatch: keep joining its existing intent.
    failed = api.request(f"/repos/{plan['repository']}/actions/runs/{run['id']}/attempts/{producer_attempt(plan)}")
    validate_run(failed, {**plan, "producerRun": run["id"]})
    if failed["status"] != "completed" or failed.get("conclusion") not in ("failure", "cancelled"):
        return None
    ref = api.request(f"/repos/{plan['repository']}/git/ref/heads/{urllib.parse.quote(plan['branch'], safe='')}")
    require(type(ref) is dict and type(ref.get("object")) is dict and ref.get("ref") == "refs/heads/" + plan["branch"] and ref["object"].get("type") == "commit" and ref["object"].get("sha") == plan["source"], "Failed producer source branch moved; cannot retry a different source at this version")
    next_plan = {**plan, "request": request, "publisherAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "producerAttempt": 1, "retryOf": {"planSha256": hashlib.sha256(contract.canonical_json(plan)).hexdigest(), "request": plan["request"], "run": run["id"], "attempt": producer_attempt(plan)}}
    next_plan.pop("producerRun", None)
    return next_plan


def plan_release(app, mode, workspace):
    publisher_branch = publisher_guard(mode)
    product = PRODUCTS[app]
    api = app_api(app, workspace)
    own = GitHub(os.environ.get("GH_TOKEN", ""))
    artifacts = own.pages(f"/repos/{PUBLISHER}/actions/artifacts", "artifacts")
    require(all(type(a) is dict and type(a.get("name")) is str and type(a.get("workflow_run")) is dict for a in artifacts), "Malformed retained publisher artifact inventory")
    retry = None
    # Re-runs recover the original immutable source, even after branch movement.
    if int(os.environ["GITHUB_RUN_ATTEMPT"]) > 1:
        for kind in ("bundle", "intent"):
            matches = [a for a in artifacts if a["name"].startswith(f"release-{kind}-{app}-") and a["workflow_run"].get("id") == int(os.environ["GITHUB_RUN_ID"])]
            if kind == "bundle":
                require(len(matches) <= 1, "Original publisher run has ambiguous signed bundles")
            if matches:
                old, artifact = retained_intent(own, api, matches, mode, workspace) if kind == "intent" else (publisher_artifact(own, matches[0], mode, kind, workspace)[0], matches[0])
                retry = (old, {"kind": kind, "artifact": artifact, "fresh": False})
                break
    branch = "main" if mode == "main" else product["integration"]
    repo = api.request("/repos/" + product["repository"])
    require(type(repo) is dict and repo.get("full_name") == product["repository"] and type(repo.get("id")) is int and repo["id"] > 0, "Selected source repository canonical identity differs")
    if retry:
        source = retry[0]["source"]
        require(retry[0]["app"] == app and retry[0]["branch"] == branch and retry[0]["repository"] == product["repository"] and SHA.fullmatch(source), "Original retry source differs from the fixed product mapping")
    else:
        ref = api.request(f"/repos/{product['repository']}/git/ref/heads/{urllib.parse.quote(branch, safe='')}")
        require(type(ref) is dict and type(ref.get("object")) is dict, "Malformed trusted source ref response")
        source = ref["object"].get("sha", "")
        require(ref.get("ref") == "refs/heads/" + branch and ref.get("object", {}).get("type") == "commit" and SHA.fullmatch(source), "Selected trusted source branch is missing or has no immutable commit")
    paths = [product["root"] + p for p in ("package.json", "src-tauri/tauri.conf.json", "src-tauri/Cargo.toml", "src-tauri/Cargo.lock")]
    if app in ("papir", "checkerboard"):
        paths.append(product["root"] + "package-lock.json")
    files = {p: content(api, product["repository"], source, p) for p in paths}
    version, declarations = derive_version(files, app)
    workflow = api.request(f"/repos/{product['repository']}/actions/workflows/{product['workflow']}")
    require(type(workflow) is dict and workflow.get("path") == ".github/workflows/" + product["workflow"] and workflow.get("state") == "active" and type(workflow.get("id")) is int, "Selected producer workflow is not registered/active; administrator must review its default-branch registration")
    workflow_bytes = content(api, product["repository"], source, workflow["path"])
    helper_bytes = content(api, product["repository"], source, "scripts/ci/release-inputs.py")
    require(all(field in workflow_bytes for field in (b"release_request:", b"desktop_release:", b"source_sha:")) and b"lapkb-actions-candidate-v1" in helper_bytes, "Selected source does not contain the coordinated producer implementation; deliver the reviewed integration changes first")
    producer_inputs = {}
    if app == "papir":
        kid, public = os.environ.get("RELEASE_PAPIR_SIGNING_KID", ""), os.environ.get("RELEASE_PAPIR_SIGNING_PUBLIC_KEY", "")
        require(kid and public, "Missing RELEASE_PAPIR_SIGNING_KID/RELEASE_PAPIR_SIGNING_PUBLIC_KEY (existing PUBLIC lease-verification configuration, not an archive/account signing key)")
        producer_inputs = {"signing_kid": kid, "signing_public_key": public}
    plan = {"schema": "lapkb-desktop-release-plan-v1", "app": app, "mode": mode, "repository": product["repository"], "repositoryId": repo["id"], "branch": branch, "source": source, "version": version, "declarations": declarations, "sourceFiles": {p: hashlib.sha256(raw).hexdigest() for p, raw in files.items()}, "workflowId": workflow["id"], "producerInputs": producer_inputs, "producerAttempt": 1, "request": f"desktop-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}-{secrets.token_hex(16)}", "publisherRun": int(os.environ["GITHUB_RUN_ID"]), "publisherAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "publisherSource": os.environ["GITHUB_SHA"], "publisherBranch": publisher_branch}
    if retry:
        old, action = retry
        # Another coordinator execution may have signed this frozen source after
        # the original intent owner stopped. Recover those bytes before a retry.
        bundles = [a for a in artifacts if a["name"].startswith(f"release-bundle-{app}-{version}-")]
        require(len(bundles) <= 1, "Duplicate retained signed bundles for this version; no rebuild")
        if bundles:
            require(bundles[0]["name"] == artifact_name("bundle", plan), "Retained signed bundle has a different source; no rebuild")
            if action["kind"] != "bundle":
                old, _ = publisher_artifact(own, bundles[0], mode, "bundle", workspace)
                action = {"kind": "bundle", "artifact": bundles[0], "fresh": False}
            else:
                require(bundles[0]["id"] == action["artifact"]["id"], "Ambiguous original signed bundle; no rebuild")
    else:
        old, action = None, {"kind": "intent", "fresh": True}
        for kind in ("bundle", "intent"):
            prefix = f"release-{kind}-{app}-{version}-"
            candidates = [a for a in artifacts if a["name"].startswith(prefix)]
            if kind == "bundle":
                require(len(candidates) <= 1, "Duplicate retained signed bundles for this version; refuse ambiguous signing")
            if candidates:
                old, artifact = retained_intent(own, api, candidates, mode, workspace) if kind == "intent" else (publisher_artifact(own, candidates[0], mode, kind, workspace)[0], candidates[0])
                require(old["source"] == source, "This version already has different-source release bytes/intent; bump coherently instead of reusing a version")
                action = {"kind": kind, "artifact": artifact, "fresh": False}
                break
    if old:
        require(all(old.get(k) == plan[k] for k in SOURCE_FIELDS), "Retained version/source/config differs; refuse signing or source reuse")
    require_completed_prior_bundles(own, artifacts, artifact_name("bundle", plan), workspace, app)
    if old:
        retried = retry_failed_producer(api, old, plan["request"]) if action["kind"] == "intent" else None
        plan = retried or old
        if retried:
            # The workflow uploads this exact new plan before the single POST.
            action = {"kind": "intent", "fresh": True}
    save(workspace / "plan.json", plan)
    save(workspace / "action.json", action)
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a") as stream:
            stream.write(f"version={version}\nsource={source}\nintent_name={artifact_name('intent', plan)}\nbundle_name={artifact_name('bundle', plan)}\nresult_name={result_name(plan, execution_identity())}\nrecovery={str(action['kind'] == 'bundle').lower()}\nfresh={str(action['fresh']).lower()}\n")
    print(f"{contract.DISPLAY_NAMES[app]} {version} from {product['repository']} {branch}@{source}; {('new build' if action['fresh'] else 'exact ' + action['kind'] + ' recovery')}")


def pinned_tool(name, digest_name):
    value, expected = os.environ.get(name, ""), os.environ.get(digest_name, "")
    require(value and contract._HEX.fullmatch(expected), f"Missing {name}/{digest_name}; provision the reviewed CI-native tool, not a downloaded product binary")
    path = Path(value)
    data = contract._read_protected_file(path, 256 * 1024 * 1024)
    require(os.access(path, os.X_OK) and hashlib.sha256(data).hexdigest() == expected, f"Pinned tool identity differs: {name}")
    require(len(data) >= 64 and data[:6] == b"\x7fELF\x02\x01" and int.from_bytes(data[18:20], "little") == 62, f"{name} must be the pinned Linux x64 native binary, not a shell/npm wrapper or downloaded product")
    if name == "RELEASE_SIGNER_PATH":
        result = subprocess.run([str(path), "--version"], capture_output=True, timeout=30, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        require(result.returncode == 0 and result.stdout.strip() == b"tauri-cli 2.11.4", "Provision the reviewed existing Tauri signer 2.11.4; do not substitute a different signing tool")
    return path


def protected_setup(plan, workspace, *, check_key=False):
    publisher_guard(plan["mode"])
    value = os.environ.get("RELEASE_PUBLISHER_POLICY", "")
    require(value, "Missing protected RELEASE_PUBLISHER_POLICY; administrator must approve both target scopes and retained history before deployment")
    policy_path = workspace / "publisher-policy.json"
    if not policy_path.exists():
        prepare_bundle.write_new(policy_path, value.encode())
    policy = contract.load_policy(policy_path)
    entry = policy.apps[plan["app"]]
    require(entry["sourceRepository"] == plan["repository"] and entry["branch"] == plan["branch"] and entry["allowedCoverages"] == (["launcher-desktop"] if plan["app"] == "launcher" else ["macos-arm64", "windows-x64"]), "Protected receiver policy must approve this exact source branch and both qualified targets; do not silently change live policy")
    expected_policy = os.environ.get("RELEASE_RECEIVER_POLICY_SHA256", "")
    require(expected_policy == hashlib.sha256(value.encode()).hexdigest(), "RELEASE_RECEIVER_POLICY_SHA256 does not match the exact administrator-approved receiver policy bytes")
    provisioned_verifier = pinned_tool("RELEASE_VERIFIER_PATH", "RELEASE_VERIFIER_SHA256")
    # The existing publisher client requires a private runner-owned verifier.
    # Copy only the approved native tool, never a downloaded product/helper.
    verifier = workspace / "release-verifier"
    if not verifier.exists():
        prepare_bundle.write_new(verifier, contract._read_protected_file(provisioned_verifier, 256 * 1024 * 1024))
        os.chmod(verifier, 0o700)
    require(contract._sha256_file(verifier)[1] == os.environ["RELEASE_VERIFIER_SHA256"], "Private native verifier differs from its provisioned pin")
    tool = pinned_tool("RELEASE_SIGNER_PATH", "RELEASE_SIGNER_SHA256")
    key = workspace / "app-signing-key"
    require(os.environ.get("APP_SIGNING_KEY"), f"Missing existing {plan['app']} archive signing key in this protected environment; no new key may be generated")
    if not key.exists():
        prepare_bundle.write_new(key, os.environ["APP_SIGNING_KEY"].encode())
    signer = prepare_bundle.Signer(policy, plan["app"], key, tool, verifier)
    for secret, filename, target in (("PUBLISH_SSH_KEY", "publisher-key", "LAPKB_PUBLISH_KEY"), ("PUBLISH_KNOWN_HOSTS", "known-hosts", "LAPKB_PUBLISH_KNOWN_HOSTS")):
        require(os.environ.get(secret), f"Missing protected {secret}; use only the existing forced receive-v1 credential, never general SSH candidate-export authority")
        path = workspace / filename
        if not path.exists():
            prepare_bundle.write_new(path, os.environ[secret].encode())
        os.environ[target] = str(path)
    os.environ["LAPKB_PUBLISHER_CONFIG"] = str(policy_path)
    os.environ["LAPKB_PUBLISHER_VERIFIER"] = str(verifier)
    if os.environ.get("LAPKB_PUBLISH_HOST_KEY_ALIAS") == "":
        os.environ.pop("LAPKB_PUBLISH_HOST_KEY_ALIAS")
    publish_artifact._ssh_command()  # complete credential/host/user/pin syntax gate, no connection
    if check_key:
        payload = workspace / "key-check"
        prepare_bundle.write_new(payload, b"LAPKB CI key custody check; not a release, licence or account token\n")
        signer.sign(payload, workspace / "key-check-signing")  # genuine native verification
    return policy, signer, verifier


def check_public_version(plan, policy, recovering):
    catalog = contract.strict_json(publish_artifact._fetch_exact(policy.origin + "/downloads/catalog.json", policy, 4 * 1024 * 1024), 4 * 1024 * 1024, "current public catalog")
    require(type(catalog) is dict and catalog.get("schema") == "lapkb-downloads-v1", "Current public website catalog is unavailable or invalid")
    entry = catalog.get("apps", {}).get(plan["app"], {}).get("channels", {}).get("stable", {})
    current_targets = entry.get("targets", {})
    qualified = [current_targets.get(target) for target in TARGETS]
    if all(type(record) is dict and record.get("distribution") == "signed" for record in qualified):
        require(recovering or len({record.get("version") for record in qualified}) == 1, "Current signed Mac/Windows versions differ: reconcile the prior exact bundle before starting another version")
    for target in TARGETS:
        current = current_targets.get(target)
        if current:
            compared = contract._version(current["version"])
            requested = contract._version(plan["version"])
            require(compared <= requested, "Source version is behind the current public release; update coherent source manifests first")
            require(compared != requested or recovering, "This version is already public without retained exact signed bundles; do not rebuild/re-sign/republish it")
    used = any(name.startswith(f"{plan['app']}-{plan['version']}-") for name in entry.get("files", {}))
    require(not used or recovering, "Version bytes already exist publicly; only retained exact bundle recovery is permitted")


def build(plan, action, workspace):
    publisher_guard(plan["mode"])
    if action["kind"] == "bundle":
        print("Both targets already have immutable signed bundles; no rebuild or redispatch")
        return
    api = app_api(plan["app"], workspace, dispatch=action["fresh"])
    if action["fresh"]:
        require(plan["publisherRun"] == int(os.environ["GITHUB_RUN_ID"]) and plan["publisherAttempt"] == int(os.environ["GITHUB_RUN_ATTEMPT"]), "Only the original persisted intent owner may dispatch once")
    evidence = wait_for_producer(api, plan, dispatch=action["fresh"])
    candidates = workspace / "candidates"
    candidates.mkdir(mode=0o700)
    for target, artifact in evidence["artifacts"].items():
        archive = workspace / (target + ".zip")
        api.request(f"/repos/{plan['repository']}/actions/artifacts/{artifact['id']}/zip", destination=archive)
        directory = extract_archive(archive, candidates / target)
        validate_candidate(directory, plan, target)
    save(workspace / "build-evidence.json", evidence)
    # Preserve original intent plan separately; this result binds the exact run.
    save(workspace / "built-plan.json", plan)


def restore_bundle(plan, action, workspace):
    own = GitHub(os.environ.get("GH_TOKEN", ""))
    original, bundle = publisher_artifact(own, action["artifact"], plan["mode"], "bundle", workspace)
    require(original == plan, "Recovered immutable bundle source plan differs")
    # Move the complete recovered directory, never regenerate its signed bytes.
    destination = workspace / "bundle"
    require(not destination.exists(), "Recovery bundle destination already exists")
    bundle.rename(destination)
    return destination


def publish_pair(plan, policy, bundle, verifier, output, publish=None, execution=None):
    releases = prepare_bundle.validate_bundles(plan, policy, bundle, verifier)
    if publish is None:
        def publish(app, channel, directory):
            result = subprocess.run([sys.executable, str(Path(__file__).parent / "publish_artifact.py"), "--app", app, "--channel", channel, "--bundle-dir", str(directory)], capture_output=True, timeout=2400, check=False)
            require(result.returncode == 0, result.stderr.decode("utf-8", "replace")[-1024:] or "Publisher failed; exact retained bundle must be reconciled, never regenerated")
            return contract.strict_json(result.stdout.strip(), 128 * 1024, "publisher/client result")
    results = []
    output.mkdir(mode=0o700)
    for scope in releases:
        result = publish(plan["app"], "stable", bundle / scope)
        require(result.get("version") == plan["version"] and result.get("coverage") == scope and result.get("status") in ("published", "identical-retry") and result.get("inventoryDigest") == releases[scope]["inventoryDigest"] and "publicLinks" in result, "Publisher/client result differs from retained signed bytes")
        save(output / (scope + ".json"), result)
        results.append(result)
    summary = f"## {contract.DISPLAY_NAMES[plan['app']]} {plan['version']} released\n\nSource: `{plan['repository']} {plan['branch']}@{plan['source']}`\n\nBoth qualified target builds/tests passed (producer run {plan['producerRun']}, attempt {producer_attempt(plan)}). Signed metadata, public feeds/files, catalog mappings and page installer links verified.\n\n"
    for result in results:
        links = result["publicLinks"]
        summary += f"### {result['coverage']}\n- [Downloads]({links['downloads']})\n- [Feed]({links['feed']})\n"
        summary += "".join(f"- [Installer]({url})\n" for url in links["installers"])
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
            stream.write(summary)
    save(output / "complete.json", {"schema": "lapkb-release-completion-v1", "source": plan, "execution": execution or execution_identity(), "results": results, "signedBundles": {scope: {"inventoryDigest": release["inventoryDigest"], "receiptSha256": hashlib.sha256(release["receiptBytes"]).hexdigest()} for scope, release in releases.items()}, "publicVerification": "complete"})
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("plan", "authorize", "build", "prepare", "publish"))
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--app", choices=tuple(PRODUCTS))
    parser.add_argument("--mode", choices=("main", "integration"))
    args = parser.parse_args()
    os.umask(0o077)
    workspace = args.workspace.resolve(strict=True)
    try:
        if args.operation == "plan":
            require(args.app and args.mode, "Select app and main/integration release mode")
            plan_release(args.app, args.mode, workspace)
            return 0
        plan, action = load(workspace / "plan.json"), load(workspace / "action.json")
        if args.operation == "build":
            build(plan, action, workspace)
            return 0
        if args.operation in ("prepare", "publish") and action["kind"] != "bundle":
            plan = load(workspace / "built-plan.json")
        policy, signer, verifier = protected_setup(plan, workspace, check_key=args.operation == "authorize")
        if args.operation == "authorize":
            check_public_version(plan, policy, action["kind"] == "bundle")
        elif args.operation == "prepare":
            bundle = restore_bundle(plan, action, workspace) if action["kind"] == "bundle" else workspace / "bundle"
            if action["kind"] != "bundle":
                # A reconciled intent can be signed by a later publisher run;
                # preserve the producer request, bind the actual signing run.
                plan = {**plan, "publisherRun": int(os.environ["GITHUB_RUN_ID"]), "publisherAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "publisherSource": os.environ["GITHUB_SHA"]}
                prepare_bundle.prepare(plan, policy, workspace / "candidates", bundle, signer, verifier)
                save(workspace / "signed-plan.json", plan)
            else:
                prepare_bundle.validate_bundles(plan, policy, bundle, verifier)
        else:
            if action["kind"] != "bundle":
                plan = load(workspace / "signed-plan.json")
            publish_pair(plan, policy, workspace / "bundle", verifier, workspace / "publication-evidence")
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError) as error:
        print(f"Desktop release stopped: {error}", file=sys.stderr)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as stream:
                stream.write(f"## Release stopped\n\n{error}\n\nNo success is claimed. Retained signed bundles/intents must be reconciled on retry; never manually patch or regenerate published bytes.\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
