import Ajv from "ajv";
import addFormats from "ajv-formats";

const SCHEMA_HOST = (process.env.SCHEMA_HOST || "https://www.commandlayer.org").replace(/\/+$/, "");
const FETCH_TIMEOUT_MS = Number(process.env.SCHEMA_FETCH_TIMEOUT_MS || 15000);
const COMPILE_TIMEOUT_MS = Number(process.env.SCHEMA_VALIDATE_BUDGET_MS || 15000);

const schemaCache = new Map();   // url -> { t, json }
const validatorCache = new Map(); // verb -> validate

function normalizeUrl(url) {
  let u = String(url || "");
  u = u.replace(/^http:\/\//i, "https://");
  u = u.replace(/^https:\/\/commandlayer\.org/i, "https://www.commandlayer.org");
  return u;
}

async function withTimeout(p, ms, label) {
  return await Promise.race([
    p,
    new Promise((_, rej) => setTimeout(() => rej(new Error(label || "timeout")), ms)),
  ]);
}

async function fetchJson(url) {
  const u = normalizeUrl(url);
  const hit = schemaCache.get(u);
  if (hit) return hit.json;

  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
  try {
    const resp = await fetch(u, { headers: { accept: "application/json" }, signal: ac.signal, redirect: "follow" });
    if (!resp.ok) throw new Error(`schema fetch failed: ${resp.status} ${resp.statusText}`);
    const json = await resp.json();
    schemaCache.set(u, { t: Date.now(), json });
    return json;
  } finally {
    clearTimeout(t);
  }
}

function makeAjv() {
  const ajv = new Ajv({
    allErrors: true,
    strict: false,
    validateSchema: false,
    loadSchema: async (uri) => await fetchJson(uri),
  });
  addFormats(ajv);
  return ajv;
}

export function receiptSchemaUrlForVerb(verb) {
  return `${SCHEMA_HOST}/schemas/v1.0.0/commercial/${verb}/receipts/${verb}.receipt.schema.json`;
}

export async function getValidatorForVerb(verb) {
  if (validatorCache.has(verb)) return validatorCache.get(verb);

  const ajv = makeAjv();

  // best-effort preload common refs
  const shared = [
    `${SCHEMA_HOST}/schemas/v1.0.0/_shared/receipt.base.schema.json`,
    `${SCHEMA_HOST}/schemas/v1.0.0/_shared/x402.schema.json`,
    `${SCHEMA_HOST}/schemas/v1.0.0/_shared/identity.schema.json`,
    `${SCHEMA_HOST}/schemas/v1.0.0/_shared/trace.schema.json`,
    `${SCHEMA_HOST}/schemas/v1.0.0/commercial/_shared/payment.amount.schema.json`,
    `${SCHEMA_HOST}/schemas/v1.0.0/commercial/_shared/payment.settlement.schema.json`,
  ];
  await Promise.all(shared.map((u) => fetchJson(u).catch(() => null)));

  const schema = await fetchJson(receiptSchemaUrlForVerb(verb));
  const validate = await withTimeout(ajv.compileAsync(schema), COMPILE_TIMEOUT_MS, "ajv_compile_timeout");
  validatorCache.set(verb, validate);
  return validate;
}

export function ajvErrorsToSimple(errors) {
  if (!Array.isArray(errors)) return null;
  return errors.slice(0, 25).map((e) => ({
    instancePath: e.instancePath,
    schemaPath: e.schemaPath,
    keyword: e.keyword,
    message: e.message,
  }));
}

export function debugState() {
  return {
    schema_host: SCHEMA_HOST,
    cached_validators: Array.from(validatorCache.keys()),
    cached_schemas: schemaCache.size,
  };
}
