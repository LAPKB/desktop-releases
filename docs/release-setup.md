# One-time administrator setup (separate approval required)

This source change does **not** install tools, copy keys, change grants, deploy a
receiver/policy, merge main, or approve a production release. Do these once only
after the isolated publisher CI evidence and the exact source changes pass review.
Normal project-manager releases need no terminal or artifact handling.

## Protected authorization

After the separate one-time owner approval, create two protected environments
in `LAPKB/desktop-releases`. Use **Selected branches and tags**, with an exact
**branch** rule (not a tag rule) for each:

- `desktop-release-integration`: publisher branch `launcher` only.
- `desktop-release-main`: publisher branch `main` only.

Main releases use the project managers' existing authorized repository write /
Actions workflow-dispatch permissions. Do **not** add required reviewers,
prevent-self-review, a wait timer or an owner approval for each routine release.
Both setup-check and publication jobs enter the environment automatically; this
is not two manual approvals. One-time key/grant/policy/setup approval remains
mandatory and unconsumed. No environments from this proposal are installed;
this document does not remove or weaken any existing configured protection.
If existing permissions or a future policy require another actor to unblock a
PM dispatch, report that concrete permission gate before claiming one-click
releases; do not silently add owner intervention as automation.

Keep source review and protected `main`, including review controls for workflow,
coordinator and policy edits. The workflow's event/ref/mode guards, fixed product
mapping, immutable SHA checks and environment branch restrictions jointly exclude
PRs, tags, forks and arbitrary refs from signing/publication. There is no source-ref
input. Runner/workflow control changes need separate approval. Per-app publication
is serialized across both modes and running publication is never cancelled.

## Narrow dispatch/read credential

Install a GitHub App on **only** these five repositories: `LAPKB/Launcher`,
`LAPKB/Pmetrics-Papir`, `LAPKB/BestDose`, `LAPKB/BDautodial`, `LAPKB/Checkerboard`.
Repository permissions: **Actions read/write** (dispatch + exact run/job/artifact
read), **Contents read**, and GitHub's mandatory Metadata read. No Contents write,
SSH export authority, organization administration or general repository grant.

Publisher repository variable: `RELEASE_APP_ID`. Publisher repository secret:
`RELEASE_APP_PRIVATE_KEY` (the approved App credential, not an app signing key).
CI requests tokens for one selected repository only; planning/read recovery asks
for Actions read, a persisted original or explicit retry dispatch asks for Actions write. Tokens renew
inside the bounded coordinator wait and are never artifacts or job outputs.
The publisher's own `GITHUB_TOKEN` needs only Contents read + Actions read.

Papir's existing **public** pilot lease-verification inputs also require publisher
variables `RELEASE_PAPIR_SIGNING_KID` and `RELEASE_PAPIR_SIGNING_PUBLIC_KEY`. Use the
currently approved values, not new keys. They are forwarded to its existing
producer input/guard; this does not change account/licence authority. Launcher
still needs its existing public build variables/private dependency read identity
in its own repository. Other existing producer dependency/trust grants stay there.

The manual publisher workflow must be registered on GitHub's default branch.
If GitHub refuses an integration dispatch because main still contains the old
workflow-call interface, a separately reviewed default-branch registration change
is required. This invocation does not make that main change or create a PR.

## Existing signing-key custody: source → target (no values)

Only copy each product's **existing archive/updater key**, with owner approval,
from its original controlled release/recovery custody to its matching secret in
**each approved publisher environment**:

| Product | Existing custody source | Publisher environment secret |
|---|---|---|
| Launcher | Owner's `private-updater-custody/launcher-updater.key`; same key already in Launcher `LAUNCHER_UPDATER_PRIVATE_KEY` | `LAUNCHER_UPDATER_PRIVATE_KEY` |
| Papir | Owner's existing Papir archive Minisign signing custody | `PAPIR_UPDATER_PRIVATE_KEY` |
| BestDose | Owner's existing BestDose archive Minisign signing custody | `BESTDOSE_UPDATER_PRIVATE_KEY` |
| BDautodial | Owner's existing BDautodial archive Minisign signing custody | `BDAUTODIAL_UPDATER_PRIVATE_KEY` |
| Checkmate | Owner's existing Checkmate archive Minisign signing custody | `CHECKMATE_UPDATER_PRIVATE_KEY` |

Launcher key ID **A9451C0DCEAC5076 remains unchanged**. The four app custody
locations/access must be identified by the owner before copying; do not infer
private custody from public keys. Keys stay distinct from licence/account,
authorization, App and SSH keys. No new/rotated keys, Apple keys, Authenticode keys
or payments. Mac bundles retain free ad-hoc seals. The existing Launcher archive
signatures/bytes are verified and copied, never re-signed/repacked by the publisher.

## Native tools and forced receive-only transport

The dispatch/wait/collection job is fixed to the existing **rust / self-hosted /
Linux / ARM64** publisher lane, never Default/X64 or an optional routing default.
Producer Windows jobs need the scarce Default/X64 worker. Setup/key/native-tool
authorization uses X64 **before** collection; signing/publication uses X64 **after**
collection, so neither holds that worker while waiting for its child producer.
Existing publisher native-verifier run **37236680808/1**, source
`1618e4e24d7dc56666ef17c447d3ac0f5ba9997a`, job **111537072604** on `mhovd-pgx`
in group `rust` demonstrates repository access, Linux ARM64 and Python execution.
Its artifact also records OpenSSL-backed Cargo, **not** proof of Python 3.11+ or
the `/usr/bin/openssl` CLI. Those exact runtime prerequisites remain to be verified
on this lane in approved CI; the job checks them before retaining/dispatching any
intent and fails early if absent. No runtime installation, runner/grant change
or assumed GitHub-hosted capacity is included here. Any missing runtime needs
separately approved one-time provisioning, not PM artifact handling.

Provision reviewed **Linux X64 native** signing/verification tools on the approved
Default runner, outside any product download directory. Both lanes require Python
3.11+; the coordinator uses `/usr/bin/openssl` for standard GitHub App JWT authentication. The release verifier is the existing
locked `host/verifier` implementation, built/tested only in approved CI; retain
its exact source/run/attempt/ABI/hash receipt. Do not install an ARM64/Mac export
on the X64 worker or execute a downloaded product/helper.

Use the existing Tauri CLI signing format/version **2.11.4**, with a reviewed,
standalone CI-native executable and exact SHA-256 receipt. The former workstation
npm wrapper/symlink is not a safe CI-native executable or complete closure pin;
do not copy it blindly. Provisioning this native signer is a setup gate, not a
workflow-time install/build. All tools/ancestors must be protected, non-linked
regular files, executable and root/runner owned. Variables in each environment:

- `RELEASE_VERIFIER_PATH`, `RELEASE_VERIFIER_SHA256`.
- `RELEASE_SIGNER_PATH`, `RELEASE_SIGNER_SHA256`.
- `RELEASE_PUBLISHER_POLICY`: exact reviewed JSON policy bytes, no uploaded trust.
- `RELEASE_RECEIVER_POLICY_SHA256`: SHA-256 of those **exact** deployed bytes.
- `LAPKB_DOWNLOAD_HOST`, `LAPKB_DOWNLOAD_USER`; optional `LAPKB_DOWNLOAD_PORT`.
- `LAPKB_DOWNLOAD_HOST_KEY_ALIAS` only when needed for the existing exact pin.

Environment secrets `PUBLISH_SSH_KEY` and `PUBLISH_KNOWN_HOSTS` must come from the
existing **forced receive-v1** publisher credential/pin custody. Do **not** copy
the workstation's general SSH candidate-export authority. Existing transport
configuration is host `100.84.10.45`, host-key alias `192.168.0.74`; retain the
existing verified pin, user and port, without network keyscan/trust adoption.
The only remote command remains
`python3 /home/siel/bin/publish_remote.py --receive-v1`.
Network reachability and actual installed policy/verifier compatibility still
need approved end-to-end evidence; a syntax/hash check cannot prove them.

## App Mac + Windows policy update (not applied here)

Deploy the reviewed maintained contract/receiver correction and a reviewed policy
copy together, preserving existing root/origin, keys, aliases, records and bytes.
Launcher stays `allowedCoverages: ["launcher-desktop"]` and canonical `latest.json`.
For each other app configure exactly `["macos-arm64", "windows-x64"]`, stable only,
with the current genuine NSIS profile and current Mac package identity/profiles:
required installer DMG + required signed `app.tar.gz` updater. Preserve each app's
bundle ID/executable and original public key/key ID.

The protected stable channel's `macFeedUrl` must be the **current compiled reader**
URL, not a new updater protocol:

- Papir: `https://licenses-staging.lapkb.org/papir/latest.json`; keep its `papir`
  legacy mirror and existing HTTPS route serving the same canonical bytes.
- BestDose: `https://hermes.lapkb.org/downloads/bestdose/stable/latest.json`.
- BDautodial: `https://hermes.lapkb.org/downloads/bdautodial/stable/latest.json`.
- Checkmate: `https://hermes.lapkb.org/downloads/checkerboard/stable/latest.json`.

Mac archive URLs use that exact feed origin/directory, as the existing reader
requires. Windows keeps `latest-windows.json` and its existing receipt filename.
Mac app metadata uses `build-attestation-V-macos-arm64.json` and
`release-receipt-V-macos-arm64.json` so its immutable metadata cannot collide with
same-version Windows metadata. Both bundles derive from one successful exact
source/run/attempt and validate before either is promoted. No history relabeling
or fabricated six-target coverage. The incomplete example policy intentionally
fails closed; it is not deployment permission.

## Exact future main transition (not applied here)

1. Finish/reconcile any pending journal under the old approved policy. Do not
   change policy mid-transaction, initialize history again, or discard input.
2. With the existing publisher lock/quiescent state, capture **every complete
   canonical durable history record** and its SHA-256 plus current public byte,
   mode, key and policy receipts. Parent/owner review must approve each record.
3. In the protected prepared policy, set the app's active branch to `main` and
   add a sorted `retainedSourceRecords` array containing only explicitly approved
   whole-record hashes for that app's old-source records. Keep repositories,
   package profiles and keys fixed. No branch allowlist, partial-record digest,
   automatic adoption or rewrite. The existing independent
   `retainedManualRecords` pin is also necessary for genuine Launcher 0.1.9/0.1.10;
   it is not replaced by the source pin. The observed genuine 0.1.9 whole-record
   hash is `e8e69d23ae2f3385391e93f00cf5d76d3b490efdcfc382c6935e8538f1dfa69b`;
   verify the complete fresh durable record again before approval. Do not invent
   other pins or treat this document as authorization to install that hash.
4. After isolated retained-history/tampering/fresh-old-branch rejection tests
   pass, separately approve/install the exact code/policy bytes and verify old
   history/current files under the derived per-record policy without modification.
   Fresh uploads always require active main; an old exact upload cannot borrow a
   retired record's authority. Update protected CI policy/hash to the same bytes.
5. Only after separately approved source merges/registration, run this same PM
   workflow in main mode for a coherently **newer** version. Capture genuine
   automated build → sign → publish → public-feed/page evidence for both targets.

## Retry and acceptance

Use Actions **Re-run all jobs** on the original failed release workflow. It
recovers that run's captured source even if the product branch has since moved.
Before any new build it searches exact version/source-bound retained publisher
artifacts: signed bundles first, then a persisted dispatch intent. A new version
cannot bypass an older signed bundle with missing/partial public verification:
its exact source-bound completion and successful publisher attempt are required,
not just an artifact upload or a green build. Expired, duplicate, mixed, different-source or
untrusted artifacts fail closed. An interrupted publish reuses the exact signed
bytes/receipts and the existing transaction/retry path. It never regenerates
signatures, silently overwrites a version or selects a latest successful build.
Artifacts are retained for 90 days; beyond that, an administrator must reconcile
missing evidence with the existing durable state before any publication, not
invent a fresh same-version bundle. A transient failed/cancelled producer needs no version bump or manual artifact
handling. **Re-run all jobs** on the original coordinator: only that explicit rerun
may create one new correlated producer run at the identical source/config/version,
and only after proving the exact predecessor failed/cancelled. The new plan records
the predecessor plan hash/request/run/attempt and is uploaded before the one POST.
Both successful target jobs, proofs and artifacts must bind the new exact producer
run/attempt/request; a target from the failed run cannot complete the pair. Retry
intents form one validated predecessor chain, not a latest-success selection.
Signed bundles always win before any retry/rebuild and keep their original bytes.

If a dispatch outcome is uncertain or its run is not found, retries only join that
persisted request; they never blindly submit it again. Duplicate/disconnected
intents or runs stop. This correction uses a fresh producer dispatch, not manual
producer Re-run jobs: its first attempt is explicitly bound, and unexpected producer
attempts are rejected. The existing producer source/ref guards are unchanged, so a
retry requires the trusted product branch still to have the frozen source head.
Branch movement/source corrections need a coherently versioned new release; they
cannot substitute new source into the failed same-version request.

A green fixture suite or queued build is **not** live end-to-end acceptance.
Before opening a PR, the owner requires actual automated two-target build/test,
original handoff, genuine signing, receive-v1 promotion and public reader/feed/
installer/catalog/page verification without manual artifact handling. Do not
republish Launcher 0.1.12 or bump any product in this source invocation.
