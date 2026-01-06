import Ajv from "ajv";
import addFormats from "ajv-formats";

const schemaJsonCache = new Map(); // url -> { fetchedAt, schema }
const validatorCache = new Map(); // verb -> { compiledAt, validate }
const inflightValidator = new Map(); // verb -> Promise<validate>

const SCHEMA_FETCH_TIMEOUT_MS = Number(process.env.SCHEMA_FETCH_TIMEOUT_MS || 15000);
const SCHEMA_VALIDATE_BUDGET_MS = Number(process.env.SCHEMA_VALIDATE_BUDGET_MS || 15000);

const MAX_JSON_CACHE_ENTRIES = Number(process.env.MAX_JSON_CACHE_ENTRIES || 256);
const JSON_CACHE_TTL_MS = Number(process.env.JSON_CACHE_TTL_MS || 10 * 60 * 1000);
const MAX_VALIDATOR_CACHE_ENTRIES = Number(process.env.MAX_VALIDATOR_CACHE_ENTRIES || 128);
const VALIDATOR_CACHE_TTL_MS = Number(process.env.VALIDATOR_CACHE_TTL_MS || 30 * 60 * 1000);

// edge-safe: if true, /verify?schema=1 never compiles/fetches
const VERIFY_SCHEMA_CACHED_ONLY = String(process.env.VERIFY_SCHEMA_CACHED_ONLY || "1") === "1";

// prewarm
const PREWARM_TOTAL_BUDGET_MS = Number(process.env.PREWARM_TOTAL_BUDGET_MS || 12000);
const PREWARM_PER_VERB_BUDGET_MS = Number(process.env.PREWARM_PER_VERB_BUDGET_MS || 5000);

function cachePrune(map, { ttlMs, maxEntries, tsField = "fetchedAt" } = {}) {
  const now = Date.now();
  if (ttlMs && ttlMs > 0) {
    for (const [k, v] of map.entries()) {
      const t = v?.[tsField] || 0;
      if (now - t > ttlMs) map.delete(k);
    }
  }
  if (maxEntries && maxEntries > 0 && map.size > maxEntries) {
    const entries = Array.from(map.entries()).sort((a, b) => (a[1]?.[tsField] || 0) - (b[1]?.[tsField] || 0));
    const toDelete = entries.slice(0, map.size - maxEntries);
    for (const [k] of toDelete) map.delete(k);
  }
}

function normalizeSchemaFetchUrl(url) {
  if (!url) return url;
  let u = String(url);
  u = u.replace(/^http:\/\//i, "https://");
  // normalize to www to avoid redirect issues
  u = u.replace(/^https:\/\/commandlayer\.org/i, "https://www.commandlayer.org");
  u = u.replace(/^https:\/\/www\.commandlayer\.org\/+/, "https://www.commandlayer.org/");
  return u;
}

async function withTimeout(promise, ms, label = "timeout") {
  if (!ms || ms <= 0) return await promise;
  return await Promise.race([promise, new Promise((_, rej) => setTimeout(() => rej(new Error(label)), ms))]);
}

async function fetchJsonWithTimeout(url, timeoutMs) {
  const u = normalizeSchemaFetchUrl(url);
  cachePrune(schemaJsonCache, { ttlMs: JSON_CACHE_TTL_MS, maxEntries: MAX_JSON_CACHE_ENTRIES, tsField: "fetchedAt" });

  const cached = schemaJsonCache.get(u);
  if (cached) return cached.schema;

  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), timeoutMs);
  try {
    const resp = await fetch(u, {
      method: "GET",
      headers: { accept: "application/json" },
      signal: ac.signal,
      redirect: "follow",
    });
    if (!resp.ok) throw new Error(`schema fetch failed: ${resp.status} ${resp.statusText}`);
    const schema = await resp.json();
    schemaJsonCache.set(u, { fetchedAt: Date.now(), schema });
    return schema;
  } finally {
    clearTimeout(t);
  }
}

function makeAjv() {
  const ajv = new Ajv({
    allErrors: true,
    strict: false,
    validateSchema: false,
    loadSchema: async (uri) => await fetchJsonWithTimeout(uri, SCHEMA_FETCH_TIMEOUT_MS),
  });
  addFormats(ajv);
  return ajv;
}

export function receiptSchemaUrlForVerb({ verb, schemaHost }) {
  const host = (schemaHost || "https://www.commandlayer.org").replace(/\/+$/, "");
  return `${host}/schemas/v1.0.0/commercial/${verb}/receipts/${verb}.receipt.schema.json`;
}

export async function getValidatorForVerb(verb, schemaHost) {
  cachePrune(validatorCache, { ttlMs: VALIDATOR_CACHE_TTL_MS, maxEntries: MAX_VALIDATOR_CACHE_ENTRIES, tsField: "compiledAt" });

  const hit = validatorCache.get(verb);
  if (hit?.validate) return hit.validate;

  if (inflightValidator.has(verb)) return await inflightValidator.get(verb);

  const build = (async () => {
    const ajv = makeAjv();
    const url = receiptSchemaUrlForVerb({ verb, schemaHost });

    // preload shared refs (best effort)
    try {
      const host = (schemaHost || "https://www.commandlayer.org").replace(/\/+$/, "");
      const shared = [
        `${host}/schemas/v1.0.0/_shared/receipt.base.schema.json`,
        `${host}/schemas/v1.0.0/_shared/x402.schema.json`,
        `${host}/schemas/v1.0.0/_shared/identity.schema.json`,
        `${host}/schemas/v1.0.0/_shared/trace.schema.json`,
        `${host}/schemas/v1.0.0/commercial/_shared/payment.amount.schema.json`,
        `${host}/schemas/v1.0.0/commercial/_shared/payment.settlement.schema.json`,
      ];
      await Promise.all(shared.map((u) => fetchJsonWithTimeout(u, SCHEMA_FETCH_TIMEOUT_MS).catch(() => null)));
    } catch {
      // ignore
    }

    const schema = await fetchJsonWithTimeout(url, SCHEMA_FETCH_TIMEOUT_MS);
    const validate = await withTimeout(ajv.compileAsync(schema), SCHEMA_VALIDATE_BUDGET_MS, "ajv_compile_budget_exceeded");

    validatorCache.set(verb, { compiledAt: Date.now(), validate });
    return validate;
  })().finally(() => inflightValidator.delete(verb));

  inflightValidator.set(verb, build);
  return await build;
}

getValidatorForVerb.peek = (verb) => validatorCache.get(verb)?.validate || null;
getValidatorForVerb.cachedOnly = () => VERIFY_SCHEMA_CACHED_ONLY;

export function hasValidatorCached(verb) {
  return !!validatorCache.get(verb)?.validate;
}

export function ajvErrorsToSimple(errors) {
  if (!errors || !Array.isArray(errors)) return null;
  return errors.slice(0, 25).map((e) => ({
    instancePath: e.instancePath,
    schemaPath: e.schemaPath,
    keyword: e.keyword,
    message: e.message,
  }));
}

// warm queue
const warmQueue = new Set();
let warmRunning = false;

export function queueWarm(verb) {
  warmQueue.add(verb);
}

export function startWarmWorker() {
  if (warmRunning) return;
  warmRunning = true;

  setTimeout(async () => {
    const started = Date.now();
    try {
      while (warmQueue.size > 0) {
        if (Date.now() - started > PREWARM_TOTAL_BUDGET_MS) break;

        const verb = warmQueue.values().next().value;
        warmQueue.delete(verb);

        if (hasValidatorCached(verb)) continue;

        try {
          await withTimeout(getValidatorForVerb(verb, process.env.SCHEMA_HOST), PREWARM_PER_VERB_BUDGET_MS, "prewarm_per_verb_timeout");
        } catch {
          // swallow
        }
      }
    } finally {
      warmRunning = false;
      if (warmQueue.size > 0) startWarmWorker();
    }
  }, 0);
}

export function ajvConfirmReceiptIfWanted({ wantSchema, receipt, schemaHost }) {
  // helper left intentionally minimal
  return { wantSchema: !!wantSchema, schemaHost };
}

getValidatorForVerb.debugState = () => ({
  ok: true,
  cached: Array.from(validatorCache.keys()),
  cache_sizes: { schemaJsonCache: schemaJsonCache.size, validatorCache: validatorCache.size },
  inflight: Array.from(inflightValidator.keys()),
  warm_queue_size: warmQueue.size,
  warm_running: warmRunning,
  verify_schema_cached_only: VERIFY_SCHEMA_CACHED_ONLY,
});
