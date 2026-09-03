import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function readJson(relativePath) {
  try {
    return JSON.parse(readFileSync(join(repositoryRoot, relativePath), "utf8"));
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(`Could not read ${relativePath}: ${reason}`, { cause: error });
  }
}

function describeErrors(errors) {
  return (errors ?? [])
    .map((error) => `${error.instancePath || "/"} ${error.message}`)
    .join("; ");
}

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const schemas = {
  source: readJson("schemas/app-source-v1.schema.json"),
  launcher: readJson("schemas/launcher-catalog-v1.schema.json"),
  update: readJson("schemas/update-catalog-v1.schema.json"),
};

for (const [name, schema] of Object.entries(schemas)) {
  try {
    ajv.compile(schema);
  } catch (error) {
    throw new Error(`Invalid ${name} schema: ${error.message}`);
  }
}

const validateUpdateCatalog = ajv.compile(schemas.update);
const failures = [];
const validCatalogs = new Map();

for (const channel of ["stable", "beta"]) {
  const relativePath = `channels/${channel}.json`;
  const catalog = readJson(relativePath);

  if (!validateUpdateCatalog(catalog)) {
    failures.push(`${relativePath}: ${describeErrors(validateUpdateCatalog.errors)}`);
    continue;
  }

  if (catalog.apps.length === 0) {
    failures.push(`${relativePath}: apps must not be empty`);
  }

  const seenIds = new Set();
  for (const app of catalog.apps) {
    if (seenIds.has(app.id)) {
      failures.push(`${relativePath}: app id ${JSON.stringify(app.id)} is duplicated`);
    }
    seenIds.add(app.id);
  }

  if (catalog.channel !== channel) {
    failures.push(`${relativePath}: channel must be ${channel}`);
    continue;
  }

  validCatalogs.set(channel, catalog);
}

const stableCatalog = validCatalogs.get("stable");
const betaCatalog = validCatalogs.get("beta");
if (stableCatalog && betaCatalog) {
  if (stableCatalog.apps.length !== betaCatalog.apps.length) {
    failures.push("stable and beta catalogs must contain the same apps in the same order");
  }

  const comparedApps = Math.min(stableCatalog.apps.length, betaCatalog.apps.length);
  for (let index = 0; index < comparedApps; index += 1) {
    const stableApp = stableCatalog.apps[index];
    const betaApp = betaCatalog.apps[index];
    if (
      stableApp.id !== betaApp.id ||
      stableApp.displayName !== betaApp.displayName
    ) {
      failures.push(
        `stable and beta apps[${index}] must use the same id and displayName in the same order`,
      );
    }
  }
}

if (failures.length > 0) {
  process.stderr.write(`${failures.map((failure) => `- ${failure}`).join("\n")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("Validated v1 schemas and stable/beta update catalogs.\n");
}
