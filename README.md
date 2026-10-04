# LAPKB desktop releases

Public downloads do not grant protected application access. Monthly licences,
genuine SDK Permits, device binding and application authorization are separate.
This repository publishes release metadata and immutable assets; it does not
implement another updater, installer worker or authorization service.

## One release contract and writer

The workstation client (`scripts/publish_artifact.py`), forced SSH receiver and
on-origin pickup all use `host/release_contract.py` and `host/publish_remote.py`.
The origin accepts only the fixed framed receive command. Uploaded data cannot
choose a root, key, origin, package profile, legacy alias or administrative flag.

The protected `/etc/lapkb/publisher.json` selects the canonical root and HTTPS
origin, approved source repositories/branches, minimum Checkmate version,
configured channels, coverage and package profiles. The deliberately incomplete
`host/publisher-trust.example.json` is not usable trust. The workstation can read
a separately reviewed protected copy through `LAPKB_PUBLISHER_CONFIG`.

Known app IDs are `launcher`, `papir`, `bestdose`, `bdautodial`, `checkerboard`.
Known channels are `stable` and `beta`; an omitted channel is disabled, not an
invitation to invent its key. Aliases must name the same configured channels.
`allowedCoverages` defaults to `full-six` when omitted:

- `full-six`: exactly Darwin, Windows and Linux, each ARM64 and x64, with
  `latest.json`. All six configured target profiles and updater roles remain
  mandatory for this coverage.
- `windows-x64`: exactly `windows-x86_64`, stable, with
  `latest-windows.json`. Windows-only policy needs only that actual profile, not
  fake beta keys or unavailable six-target packages.

Each app's fixed bundle identifier, display name, executable, architecture and
version must match policy. Checkmate's installed executable is
`checkmate-desktop.exe`, **not** the exported CI alias `checkmate.exe`.
Windows packages use current-user NSIS. BestDose does not require a fabricated
MSI; other coverage formats remain explicitly configured, never guessed.

## Four signed Windows apps

Papir 0.1.5+, BDautodial 0.2.4+, BestDose 1.0.11+ and Checkmate 0.8.2+ use their
unchanged individual genuine Minisign keys. A complete bundle contains:

- the final immutable `{app}-{version}-{target}-{sha256}.exe`;
- canonical `build-attestation-{version}.json` and its detached `.sig`;
- canonical `release-receipt-{version}.json` and its detached `.sig`;
- the exact canonical policy-derived `latest-windows.json`.

The existing `lapkb-build-attestation-v1` and `release-receipt-v1` schemas are
maintained in place. Windows coverage binds source repository/branch, a full
40-character source commit and the staging tag `publish-{app}-{channel}-{version}`.
Its sole target records `build = {runId, runAttempt, profile: public-staging}`
and `windowsPayload = {schema: lapkb-windows-payload-v1, productName, executable,
architecture: x86_64, version, installMode: currentUser, files}`. The complete
installed file list is sorted and contains exact relative paths, sizes and
SHA-256 hashes, including the real executable and every bundled resource/DLL.
NSIS installer support is not silently treated as application payload.

The receipt also binds `coverage`, `feed` and the genuinely verified final
`installerSignature`. Its single NSIS artifact has roles `[installer, updater]`
and the same configured key ID. Receipt, attestation and installer signatures
are all verified. No uploaded key or arbitrary unsigned payload can qualify an
app. Windows limits match the committed Launcher reader: 1 MiB receipt,
256 MiB installer, 4096 files/1 GiB expanded payload, bounded source/run/attempt,
and 16 KiB encoded installer/receipt signatures. The feed remains standard Tauri
`{version, optional notes/pub_date, platforms: {target: {url, signature}}}`.

The publisher authenticates the producer's package claim and exact final bytes;
it does not independently unpack NSIS. Genuine current-source CI package proof,
complete payload inspection and custody must reach the existing signer before
those claims are signed. A synthetic fixture is never product evidence.

## Manual Launcher bootstrap

Launcher Windows 0.1.9+ is explicitly manual/checksum-only in the **same** writer.
Its stable Windows-only channel sets `manualTargets: [windows-x86_64]`,
`publicKey: null`, `keyId: null`; the one required NSIS profile has only the
`installer` role. This exception is restricted to Launcher stable Windows x64.
It cannot be enabled for the four protected apps, beta or full-six.

The attestation and deterministic receipt explicitly contain
`distribution: manual-checksum`. Their source, package and complete payload
provenance requirements remain; there are **no** detached signatures,
`signatureKeyId` is null, receipt `roles.updater` is null and there is no
`installerSignature`. Extra signature claims are rejected. The manual
`latest-windows.json` identifies `lapkb-manual-download-v1`, Launcher/channel/
coverage/distribution, and `installers[target] = {url, sha256, size, kind}`.
It is not a signed Tauri updater feed. The website labels it as manual/checksum
and makes no signature, Authenticode or self-update claim. Standard Launcher
self-update remains deferred; no fake updater key is required.

## Durable history and recovery

Coverage, fixed feed, exact target set and distribution are durable identities,
not switches used only during manifest validation. State/current selection,
version checks, plan and journal all bind them. Versions are monotonic for each
affected target; same-version publication requires the exact durable record and
inventory. Conflicting or stale retries fail before new publication intent.
The mutable feed is never promoted as an immutable asset. Windows publication
never writes `latest.json` or legacy aliases.

The existing descriptor-confined RootFS, global cross-process lock, private
staging, no-follow/single-link checks, create-new immutable promotion, fsync and
durable journal remain. Initial apply and restart use the same promotion and
recovery functions. Recovery revalidates the staged release and fixed scope,
requires the exact prior-history extension, then completes feed, private state,
catalog and index updates. This is ordered recovery, **not** an atomic multi-file
commit. Cleanup never discards journaled input to create another staging folder.

Catalogs retain every known historical asset. Current versions are reported per
target/feed; a channel-wide `version` is present only when true for every current
target. Windows versions do not relabel old Mac packages. Website links separate
signed release metadata, manual/checksum installers and observed historical
entries. Opaque files are not made into authenticated releases by their names.
Historical bytes/modes, including old 0600 archives and Papir's legacy mirror,
remain protected; catalog/page regeneration does not normalize archive modes.

## Explicit historical initialization

Ordinary receive and pickup **never** adopt a populated root without state.
The existing core has a separate, explicit **local administrative** command:

```text
python3 host/publish_remote.py --initialize-history-v1 \
  --inventory /protected/fresh-reviewed-history.json --sha256 <reviewed-input-sha256>
```

This command is not accepted by the forced SSH wrapper. Its canonical, owned,
single-link 0600 review input has `schema: lapkb-historical-inventory-v1`, exact
`root`, `origin`, fresh UTC `observedAt`, `inventory`, `catalog`, and `current`.
Freshness is at most 24 hours (five minutes of forward clock tolerance).

`inventory` covers the **complete public root**, including `.` and all files and
directories, but excluding only the publisher's private state and lock. Directory
entries contain integer `mode` and `kind: directory`; file entries additionally
contain exact `size` and `sha256`. `catalog` is the observed existing catalog.
Every canonical historical feed target is explicitly listed in sorted `current`
records `{app, channel, target, version, feed: latest.json, artifact}` and checked
against its actual feed and inventoried catalog asset. No inferred signatures,
package architecture proof, six-target receipt or source commit is invented.

Under the existing lock, initialization refuses existing state/journal, checks
all actual paths/bytes/modes twice and binds the observed feed documents. It
creates only protected `lapkb-observed-history-v1` state within the maintained
state schema. It does not rewrite any public asset, feed, catalog or page.
A restart verifies retained files/modes. Later release transactions preserve the
exact historical state rather than adopting another inventory through recovery.

The frozen 44-entry October 3 proposals are **not** fresh host validation and
cannot be used as activation approval. Fresh host inventory, parent review and
separate activation approval are still necessary. No initialization/deployment
was performed by this source packet.

## Workstation client and pickup

The workstation validates the complete bundle, uses pinned SSH with explicit
`LAPKB_PUBLISH_KEY`, `LAPKB_PUBLISH_KNOWN_HOSTS`, `LAPKB_PUBLISH_USER`,
`LAPKB_PUBLISH_HOST` and optional port, then verifies the exact fixed served feed
and every immutable file over the configured HTTPS origin. Response coverage,
feed, targets, distribution, version and inventory digest must match the locally
validated release. Proxies, redirects, ambient SSH agents and credential fallback
remain disabled. The wrapper accepts exactly
`python3 /home/siel/bin/publish_remote.py --receive-v1` and executes that fixed
receiver with `/usr/bin/python3`; positional, extra and administrative arguments
are rejected.

If the same approved origin is reached at a different address, optional
`LAPKB_PUBLISH_HOST_KEY_ALIAS` selects its **existing exact pin** in the explicit
known-hosts file. For the established transport, set `LAPKB_PUBLISH_HOST=100.84.10.45`
and `LAPKB_PUBLISH_HOST_KEY_ALIAS=192.168.0.74`. The alias must be a nonempty ASCII
host token (letters, digits, dots and hyphens, starting with a letter or digit).
Leaving it unset uses the destination host normally; empty/whitespace/options are
rejected. This does not add a key/pin or enable SSH config, proxies or agents.

The default verifier remains `/usr/local/libexec/lapkb-release-verifier`.
A workstation without access to that installation directory can explicitly set
`LAPKB_PUBLISHER_VERIFIER` to its already-custodied compatible native verifier.
The override must be an absolute, owned, single-link private regular file with
safe no-follow ancestors; the same signature checks still apply. The origin
always uses its own fixed native verifier, never this workstation path.

```text
python3 scripts/publish_artifact.py --app <approved-app> --channel stable \
  --bundle-dir <complete-reviewed-current-source-bundle>
```

Pickup requires protected private config/token/state. It tracks GitHub release/
asset IDs, sizes and digests plus fixed scope, refuses changed/disappeared tags,
and marks a tag only after the same core succeeds and its result matches the
exact downloaded inventory. GitHub bearer tokens go only to the fixed API asset
endpoint, never to its explicitly allowed HTTPS CDN redirect. Scheduled pickup
cannot initialize history or change trust.

## CI evidence and deferred work

The existing validation workflow defaults to the approved Default self-hosted
Linux X64 group. Its manual `runner_arch` choice can select native Linux ARM64
on the existing `rust` group; it does not create capacity or change runner grants.
Manual ARM64 export uses Rust 1.97.1 in the same private identity-bound jobs2
directory. It fetches locked dependencies separately without credentials, then
builds/tests only the verifier offline with two jobs. Rust's bundled linker and
musl standard library produce `aarch64-unknown-linux-musl`; export rejects any
external loader or shared-library requirement and records the actual ELF header,
toolchain, source/run/attempt and SHA-256. It never builds the signer example or
runs the fixed-path Python fixture on the CI host. Default X64 validation keeps
the pinned Docker-based full publisher regressions and their networkless test
layers. Both modes reuse the maintained identity-confined cleanup and artifact
output.
`npm test` validates schemas/catalogs and structural schema regressions;
`scripts/test-publisher.sh` builds/tests the locked verifier and exercises real
synthetic-signature publisher/client/pickup, mixed-history, conflict/retry,
bootstrap and every journal checkpoint regression. Run these **only in approved
CI**, not on the owner's application workstation. The fixed-path wrapper seam
fixture runs only in that credential-free container with its explicit
`LAPKB_PUBLISHER_ISOLATED_CI=1` marker; it refuses existing fixed-path files,
uses the maintained receiver/contract and locked verifier with synthetic trust,
and removes its fixtures. It is not product signing or origin activation.

These checks do not establish genuine release custody/signatures, publication,
native Windows installation or application acceptance. The existing legacy
`stage-release.yml`, `publish-download.yml` and `publish-smoke.yml` two-file
interfaces remain **not release-approved** and must not be invoked. No duplicate
writer or unsigned protected-app bypass was added. Full Deploy automation, Linux
completion, scientific/oracle work and Launcher self-update remain deferred and
do not gate the first Windows website release through the reviewed client/core.
