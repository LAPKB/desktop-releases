// Structural schema fixtures only. Placeholder hashes/signatures are NOT
// binaries, trusted build evidence or genuine release signatures.
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import Ajv2020 from "ajv/dist/2020.js";

const ajv = new Ajv2020({ strict: true, allErrors: true });
const schemas = {};
for (const name of ["build-attestation", "release-receipt", "publisher-trust", "pickup-config"]) {
  schemas[name] = JSON.parse(readFileSync(new URL(`../schemas/${name}-v1.schema.json`, import.meta.url), "utf8"));
  ajv.addSchema(schemas[name]);
}
const validators = Object.fromEntries(Object.entries(schemas).map(([name, schema]) => [name, ajv.compile(schema)]));
const hash = "a".repeat(64);
const source = { repository: "LAPKB/structural-only", branch: "reviewed", commit: "a".repeat(40), tag: "publish-papir-stable-0.1.5" };
const identity = { bundleIdentifier: "com.papir.app", displayName: "Papir", executable: "papir-v3", architecture: "x86_64", version: "0.1.5" };
const build = { runId: "12345", runAttempt: 1, profile: "public-staging" };
const windowsPayload = { schema: "lapkb-windows-payload-v1", productName: "Papir", executable: "papir-v3.exe", architecture: "x86_64", version: "0.1.5", installMode: "currentUser", files: [{ path: "papir-v3.exe", size: 10, sha256: hash }] };
const artifact = { name: `papir-0.1.5-windows-x86_64-${hash}.exe`, kind: "nsis", roles: ["installer", "updater"], size: 10, sha256: hash, signatureKeyId: "0123456789ABCDEF", updaterSignature: "STRUCTURAL-ONLY-NOT-A-SIGNATURE" };
const attestation = { schema: "lapkb-build-attestation-v1", app: "papir", channel: "stable", version: "0.1.5", coverage: "windows-x64", source, targets: { "windows-x86_64": { packageIdentity: identity, artifacts: [artifact], build, windowsPayload } } };
const { updaterSignature: ignored, ...receiptArtifact } = artifact;
const receipt = { schema: "release-receipt-v1", app: "papir", channel: "stable", version: "0.1.5", coverage: "windows-x64", feed: "latest-windows.json", source, buildAttestationSha256: hash, manifestSha256: hash, signatureKeyId: artifact.signatureKeyId, targets: { "windows-x86_64": { packageIdentity: identity, roles: { installer: [artifact.name], updater: artifact.name }, artifacts: [receiptArtifact], build, windowsPayload, installerSignature: artifact.updaterSignature } } };

function accepts(name, value) {
  assert.equal(validators[name](value), true, JSON.stringify(validators[name].errors));
}
function rejects(name, value) {
  assert.equal(validators[name](value), false, `unexpected schema acceptance: ${name}`);
}

test("existing schemas accept exact signed Windows coverage and reject feed/target/provenance confusion", () => {
  accepts("build-attestation", attestation);
  accepts("release-receipt", receipt);
  rejects("release-receipt", { ...receipt, feed: "latest.json" });
  rejects("release-receipt", { ...receipt, coverage: "full-six" });
  for (const name of ["build-attestation", "release-receipt"]) {
    const original = name === "build-attestation" ? attestation : receipt;
    for (const change of [
      (v) => { v.targets["darwin-aarch64"] = v.targets["windows-x86_64"]; },
      (v) => { v.targets["windows-x86_64"].build.runAttempt = true; },
      (v) => { v.targets["windows-x86_64"].build.profile = "development"; },
      (v) => { v.targets["windows-x86_64"].windowsPayload.installMode = "perMachine"; },
      (v) => { v.targets["windows-x86_64"].windowsPayload.files[0].path = "../escaped.exe"; },
      (v) => { v.targets["windows-x86_64"].windowsPayload.files[0].path = "resources/ConOut$.bin"; },
      (v) => { v.targets["windows-x86_64"].windowsPayload.files[0].path = "resources/trailing. "; },
      (v) => { v.targets["windows-x86_64"].artifacts[0].kind = "msi"; },
      (v) => { v.targets["windows-x86_64"].artifacts[0].roles = ["installer"]; },
      (v) => { v.source.commit = "a".repeat(64); },
    ]) {
      const changed = structuredClone(original);
      change(changed);
      rejects(name, changed);
    }
  }
});

test("manual Launcher is explicitly installer/checksum only, never an unsigned protected app", () => {
  const manualAttestation = structuredClone(attestation);
  const manualVersion = "0.1.9";
  const manualName = `launcher-${manualVersion}-windows-x86_64-${hash}.exe`;
  const manualIdentity = { bundleIdentifier: "org.lapkb.launcher", displayName: "LAPKB Launcher", executable: "lapkb-launcher", architecture: "x86_64", version: manualVersion };
  const manualPayload = { ...windowsPayload, productName: "LAPKB Launcher", executable: "lapkb-launcher.exe", version: manualVersion, files: [{ path: "lapkb-launcher.exe", size: 10, sha256: hash }] };
  manualAttestation.app = "launcher";
  manualAttestation.version = manualVersion;
  manualAttestation.source.tag = `publish-launcher-stable-${manualVersion}`;
  manualAttestation.distribution = "manual-checksum";
  manualAttestation.targets["windows-x86_64"].packageIdentity = manualIdentity;
  manualAttestation.targets["windows-x86_64"].windowsPayload = manualPayload;
  const a = manualAttestation.targets["windows-x86_64"].artifacts[0];
  a.name = manualName;
  a.roles = ["installer"];
  a.signatureKeyId = null;
  a.updaterSignature = null;
  accepts("build-attestation", manualAttestation);
  const manualReceipt = structuredClone(receipt);
  manualReceipt.app = "launcher";
  manualReceipt.version = manualVersion;
  manualReceipt.source.tag = `publish-launcher-stable-${manualVersion}`;
  manualReceipt.distribution = "manual-checksum";
  manualReceipt.signatureKeyId = null;
  const target = manualReceipt.targets["windows-x86_64"];
  target.packageIdentity = manualIdentity;
  target.windowsPayload = manualPayload;
  target.artifacts[0].name = manualName;
  target.roles.installer = [manualName];
  target.roles.updater = null;
  target.artifacts[0].roles = ["installer"];
  target.artifacts[0].signatureKeyId = null;
  delete target.installerSignature;
  accepts("release-receipt", manualReceipt);
  rejects("build-attestation", { ...manualAttestation, app: "papir" });
  rejects("release-receipt", { ...manualReceipt, app: "papir" });
  rejects("release-receipt", { ...manualReceipt, signatureKeyId: artifact.signatureKeyId });
  const falseSignature = structuredClone(manualReceipt);
  falseSignature.targets["windows-x86_64"].installerSignature = "NOT-A-SIGNATURE";
  rejects("release-receipt", falseSignature);
  rejects("build-attestation", { ...manualAttestation, version: "0.1.11" });
  rejects("release-receipt", { ...manualReceipt, version: "0.1.11" });
});

test("signed Launcher bootstrap is exactly two targets with actual per-target provenance", () => {
  const version = "0.1.11";
  const name = `launcher-${version}-windows-x86_64-${hash}.exe`;
  const tarName = `launcher-${version}-darwin-aarch64-${hash}.app.tar.gz`;
  const launcherIdentity = { ...identity, bundleIdentifier: "org.lapkb.launcher", displayName: "LAPKB Launcher", executable: "lapkb-launcher", version };
  const launcherPayload = { ...windowsPayload, productName: "LAPKB Launcher", executable: "lapkb-launcher.exe", version, files: [{ path: "lapkb-launcher.exe", size: 10, sha256: hash }] };
  const launcherSource = { ...source, repository: "LAPKB/Launcher", branch: "launcher-authorization-repair-20261002", tag: `publish-launcher-stable-${version}` };
  const windowsArtifact = { ...artifact, name };
  const macArtifact = { ...artifact, name: tarName, kind: "app-tar-gz" };
  const two = { ...attestation, app: "launcher", version, coverage: "launcher-desktop", source: launcherSource, targets: {
    "windows-x86_64": { packageIdentity: launcherIdentity, artifacts: [windowsArtifact], build, windowsPayload: launcherPayload },
    "darwin-aarch64": { packageIdentity: { ...launcherIdentity, architecture: "aarch64" }, artifacts: [macArtifact], build },
  } };
  const { updaterSignature: _windowsSignature, ...windowsReceiptArtifact } = windowsArtifact;
  const { updaterSignature: _macSignature, ...macReceiptArtifact } = macArtifact;
  const twoReceipt = { ...receipt, app: "launcher", version, coverage: "launcher-desktop", feed: "latest.json", source: launcherSource, targets: {
    "windows-x86_64": { ...two.targets["windows-x86_64"], artifacts: [windowsReceiptArtifact], roles: { installer: [name], updater: name }, installerSignature: artifact.updaterSignature },
    "darwin-aarch64": { ...two.targets["darwin-aarch64"], artifacts: [macReceiptArtifact], roles: { installer: [tarName], updater: tarName } },
  } };
  accepts("build-attestation", two);
  accepts("release-receipt", twoReceipt);
  for (const schema of ["build-attestation", "release-receipt"]) {
    const original = schema === "build-attestation" ? two : twoReceipt;
    for (const change of [
      (v) => { delete v.targets["darwin-aarch64"]; },
      (v) => { v.targets["linux-x86_64"] = v.targets["windows-x86_64"]; },
      (v) => { delete v.targets["darwin-aarch64"].build; },
      (v) => { v.targets["darwin-aarch64"].build.profile = "development"; },
      (v) => { v.targets["darwin-aarch64"].artifacts[0].size = 134217729; },
      (v) => { v.signatureKeyId = null; v.distribution = "manual-checksum"; },
      (v) => { v.app = "papir"; },
    ]) {
      const changed = structuredClone(original); change(changed); rejects(schema, changed);
    }
  }
});

test("full-six still requires six targets, with no Windows-only payload relabeling", () => {
  const full = structuredClone(attestation);
  delete full.coverage;
  rejects("build-attestation", full);
  delete full.targets["windows-x86_64"].build;
  delete full.targets["windows-x86_64"].windowsPayload;
  const sample = full.targets["windows-x86_64"];
  for (const target of ["darwin-aarch64", "darwin-x86_64", "windows-aarch64", "linux-aarch64", "linux-x86_64"]) {
    full.targets[target] = structuredClone(sample);
    full.targets[target].packageIdentity.architecture = target.endsWith("aarch64") ? "aarch64" : "x86_64";
  }
  accepts("build-attestation", full);
  delete full.targets["linux-x86_64"];
  rejects("build-attestation", full);
});

test("honest Mac ARM64 app scope shares the signed protocol, not a fabricated six-target release", () => {
  const tarName = `papir-0.1.5-darwin-aarch64-${hash}.app.tar.gz`;
  const dmgName = `papir-0.1.5-darwin-aarch64-${hash}.dmg`;
  const macIdentity = { ...identity, architecture: "aarch64" };
  const tar = { ...artifact, name: tarName, kind: "app-tar-gz", roles: ["updater"] };
  const dmg = { ...artifact, name: dmgName, kind: "dmg", roles: ["installer"], signatureKeyId: null, updaterSignature: null };
  const mac = { ...attestation, coverage: "macos-arm64", targets: { "darwin-aarch64": { packageIdentity: macIdentity, artifacts: [tar, dmg], build } } };
  const { updaterSignature: _tarSignature, ...tarReceipt } = tar;
  const { updaterSignature: _dmgSignature, ...dmgReceipt } = dmg;
  const macReceipt = { ...receipt, coverage: "macos-arm64", feed: "latest.json", targets: { "darwin-aarch64": { packageIdentity: macIdentity, artifacts: [tarReceipt, dmgReceipt], build, roles: { installer: [dmgName], updater: tarName } } } };
  accepts("build-attestation", mac);
  accepts("release-receipt", macReceipt);
  rejects("release-receipt", { ...macReceipt, feed: "latest-windows.json" });
  rejects("build-attestation", { ...mac, app: "launcher" });
  for (const name of ["build-attestation", "release-receipt"]) {
    const original = name === "build-attestation" ? mac : macReceipt;
    for (const change of [
      (v) => { v.targets["windows-x86_64"] = v.targets["darwin-aarch64"]; },
      (v) => { delete v.targets["darwin-aarch64"].build; },
      (v) => { v.targets["darwin-aarch64"].artifacts[0].size = 268435457; },
      (v) => { v.source.commit = "a".repeat(64); },
      (v) => { v.distribution = "manual-checksum"; },
    ]) { const changed = structuredClone(original); change(changed); rejects(name, changed); }
  }
});

test("publisher trust permits only configured known channels and explicit Windows profiles", () => {
  const apps = {};
  const legacyAliases = {};
  const bundles = { launcher: "org.lapkb.launcher", papir: "com.papir.app", bestdose: "org.lapkb.bestdose", bdautodial: "com.bdautodial.desktop", checkerboard: "org.lapkb.checkmate" };
  for (const [app, bundleIdentifier] of Object.entries(bundles)) {
    const manual = app === "launcher";
    apps[app] = { sourceRepository: "LAPKB/structural-only", branch: "reviewed", bundleIdentifier, executable: app === "checkerboard" ? "checkmate-desktop" : app, allowedCoverages: ["windows-x64"], channels: { stable: { publicKey: manual ? null : "STRUCTURAL-ONLY-PUBLIC-KEY", keyId: manual ? null : "0123456789ABCDEF", manualTargets: manual ? ["windows-x86_64"] : [], profiles: { "windows-x86_64": [{ id: "nsis", extension: "exe", kind: "nsis", roles: manual ? ["installer"] : ["installer", "updater"], required: true }] } } } };
    legacyAliases[app] = { stable: app };
  }
  const trust = { schema: "lapkb-publisher-trust-v1", root: "/private/public", origin: "https://downloads.example.test", pickupRepository: "LAPKB/desktop-releases", checkmateMinimumVersion: "0.8.0", apps, legacyAliases };
  accepts("publisher-trust", trust);
  const desktop = structuredClone(trust);
  desktop.apps.launcher.allowedCoverages = ["launcher-desktop"];
  desktop.apps.launcher.retainedManualRecords = { "0.1.9": hash };
  desktop.apps.launcher.channels.stable = { publicKey: "STRUCTURAL-ONLY-PUBLIC-KEY", keyId: "0123456789ABCDEF", profiles: {
    "windows-x86_64": [{ id: "nsis", extension: "exe", kind: "nsis", roles: ["installer", "updater"], required: true }],
    "darwin-aarch64": [{ id: "app-tar", extension: "app.tar.gz", kind: "app-tar-gz", roles: ["installer", "updater"], required: true }],
  } };
  accepts("publisher-trust", desktop);
  desktop.apps.launcher.retainedSourceRecords = [hash];
  for (const app of ["papir", "bestdose", "bdautodial", "checkerboard"]) {
    desktop.apps[app].allowedCoverages = ["macos-arm64", "windows-x64"];
    desktop.apps[app].channels.stable.profiles["darwin-aarch64"] = structuredClone(desktop.apps.launcher.channels.stable.profiles["darwin-aarch64"]);
    desktop.apps[app].channels.stable.macFeedUrl = `https://downloads.example.test/downloads/${app}/stable/latest.json`;
  }
  accepts("publisher-trust", desktop);
  const missingMac = structuredClone(desktop); delete missingMac.apps.papir.channels.stable.macFeedUrl;
  rejects("publisher-trust", missingMac);
  const fakeMac = structuredClone(desktop); fakeMac.apps.papir.allowedCoverages = ["macos-arm64"];
  rejects("publisher-trust", fakeMac);
  const badPin = structuredClone(desktop); badPin.apps.launcher.retainedSourceRecords = ["not a durable-record hash"];
  rejects("publisher-trust", badPin);
  for (const change of [
    (v) => { v.apps.launcher.retainedManualRecords["0.1.11"] = hash; },
    (v) => { v.apps.papir.retainedManualRecords = { "0.1.9": hash }; },
    (v) => { v.apps.launcher.allowedCoverages.push("windows-x64"); },
    (v) => { v.apps.launcher.channels.stable.profiles["darwin-aarch64"][0].extension = "app.zip"; },
    (v) => { v.apps.launcher.channels.stable.profiles["darwin-aarch64"][0].required = false; },
    (v) => { v.apps.launcher.channels.stable.publicKey = null; },
  ]) {
    const malformed = structuredClone(desktop); change(malformed); rejects("publisher-trust", malformed);
  }
  const disabled = structuredClone(trust);
  disabled.apps.papir.channels.nightly = disabled.apps.papir.channels.stable;
  rejects("publisher-trust", disabled);
  const fakeFull = structuredClone(trust);
  fakeFull.apps.papir.allowedCoverages = ["full-six"];
  rejects("publisher-trust", fakeFull);
  const unsignedApp = structuredClone(trust);
  unsignedApp.apps.papir.channels.stable = unsignedApp.apps.launcher.channels.stable;
  rejects("publisher-trust", unsignedApp);
  for (const change of [
    (v) => { v.apps.papir.channels.stable.profiles["windows-x86_64"][0].kind = "msi"; },
    (v) => { v.apps.papir.channels.stable.profiles["windows-x86_64"][0].roles = ["installer"]; },
    (v) => { v.apps.papir.channels.stable.profiles["windows-x86_64"][0].required = false; },
  ]) {
    const malformed = structuredClone(trust);
    change(malformed);
    rejects("publisher-trust", malformed);
  }
  accepts("pickup-config", { schema: "lapkb-pickup-v1", enabled: true, repository: "LAPKB/desktop-releases" });
  rejects("pickup-config", { schema: "lapkb-pickup-v1", enabled: true, repository: "LAPKB/desktop-releases", root: "/attacker" });
});
