// server.mjs
import express from "express";
import crypto from "crypto";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { ethers } from "ethers";
import net from "net";

const app = express();
app.use(express.json({ limit: "2mb" }));

// ---- basic CORS (no dependency)
app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  if (req.method === "OPTIONS") return res.status(204).end();
  next();
});

const PORT = Number(process.env.PORT || 8080);

// ---- runtime config
const ENABLED_VERBS = (process.env.ENABLED_VERBS || "fetch,describe,format,clean,parse,summarize,convert,explain,analyze,classify")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const SIGNER_ID = process.env.RECEIPT_SIGNER_ID || process.env.ENS_NAME || "runtime";
const PRIV_PEM_B64 = process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64 || "";
const PUB_PEM_B64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "";

// ---- service identity / discovery
const SERVICE_NAME = process.env.SERVICE_NAME || "commandlayer-runtime";
const SERVICE_VERSION = process.env.SERVICE_VERSION || "1.0.0";
const CANONICAL_BASE = (process.env.CANONICAL_BASE_URL || "https://runtime.commandlayer.org").replace(/\/+$/, "");
const API_VERSION = process.env.API_VERSION || "1.0.0";

// ENS verifier config
const ETH_RPC_URL = process.env.ETH_RPC_URL || "";
const VERIFIER_ENS_NAME = process.env.VERIFIER_ENS_NAME || process.env.ENS_NAME || SIGNER_ID || "";
const ENS_PUBKEY_TEXT_KEY = process.env.ENS_PUBKEY_TEXT_KEY || "cl.receipt.pubkey.pem";

// IMPORTANT: AJV should fetch schemas from www, but schemas' $id/refs may be commandlayer.org.
// We normalize fetch URLs to https://www.commandlayer.org to avoid redirect/host mismatches.
const SCHEMA_HOST = (process.env.SCHEMA_HOST || "https://www.commandlayer.org").replace(/\/+$/, "");
const SCHEMA_FETCH_TIMEOUT_MS = Number(process.env.SCHEMA_FETCH_TIMEOUT_MS || 15000);
const SCHEMA_VALIDATE_BUDGET_MS = Number(process.env.SCHEMA_VALIDATE_BUDGET_MS || 15000);

// ---- scaling + safety knobs (server-side caps)
const MAX_JSON_CACHE_ENTRIES = Number(process.env.MAX_JSON_CACHE_ENTRIES || 256);
const JSON_CACHE_TTL_MS = Number(process.env.JSON_CACHE_TTL_MS || 10 * 60 * 1000);
const MAX_VALIDATOR_CACHE_ENTRIES = Number(process.env.MAX_VALIDATOR_CACHE_ENTRIES || 128);
const VALIDATOR_CACHE_TTL_MS = Number(process.env.VALIDATOR_CACHE_TTL_MS || 30 * 60 * 1000);
const SERVER_MAX_HANDLER_MS = Number(process.env.SERVER_MAX_HANDLER_MS || 12000);

// fetch hardening
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 8000);
const FETCH_MAX_BYTES = Number(process.env.FETCH_MAX_BYTES || 256 * 1024);
const ENABLE_SSRF_GUARD = String(process.env.ENABLE_SSRF_GUARD || "1") === "1";
const ALLOW_FETCH_HOSTS = (process.env.ALLOW_FETCH_HOSTS || "")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);

// verify hardening
const VERIFY_MAX_MS = Number(process.env.VERIFY_MAX_MS || 30000);

// CRITICAL: edge-safe schema verify behavior
// If true, /verify?schema=1 will NEVER compile or fetch; it will only validate if cached,
// otherwise it returns 202 and queues warm.
// Default true (this is what prevents Railway edge 502s).
const VERIFY_SCHEMA_CACHED_ONLY = String(process.env.VERIFY_SCHEMA_CACHED_ONLY || "1") === "1";

// Prewarm knobs
const PREWARM_MAX_VERBS = Number(process.env.PREWARM_MAX_VERBS || 25);
const PREWARM_TOTAL_BUDGET_MS = Number(process.env.PREWARM_TOTAL_BUDGET_MS || 12000);
const PREWARM_PER_VERB_BUDGET_MS = Number(process.env.PREWARM_PER_VERB_BUDGET_MS || 5000);

function nowIso() {
  return new Date().toISOString();
}

function randId(prefix = "trace_") {
  return prefix + crypto.randomBytes(6).toString("hex");
}

// Stable stringify (deterministic object key order)
function stableStringify(value) {
  const seen = new WeakSet();
  const helper = (v) => {
    if (v === null || typeof v !== "object") return v;
    if (seen.has(v)) return "[Circular]";
    seen.add(v);
    if (Array.isArray(v)) return v.map(helper);
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = helper(v[k]);
    return out;
  };
  return JSON.stringify(helper(value));
}

function sha256Hex(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

function pemFromB64(b64) {
  if (!b64) return null;
  const pem = Buffer.from(b64, "base64").toString("utf8");
  return pem.includes("BEGIN") ? pem : null;
}

function normalizePem(text) {
  if (!text) return null;
  const pem = String(text).replace(/\\n/g, "\n").trim();
  return pem.includes("BEGIN") ? pem : null;
}

function signEd25519Base64(messageUtf8) {
  const pem = pemFromB64(PRIV_PEM_B64);
  if (!pem) throw new Error("Missing RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64");
  const key = crypto.createPrivateKey(pem);
  const sig = crypto.sign(null, Buffer.from(messageUtf8, "utf8"), key);
  return sig.toString("base64");
}

function verifyEd25519Base64(messageUtf8, signatureB64, pubPem) {
  const key = crypto.createPublicKey(pubPem);
  return crypto.verify(null, Buffer.from(messageUtf8, "utf8"), key, Buffer.from(signatureB64, "base64"));
}

function makeError(code, message, extra = {}) {
  return { status: "error", code, message, ...extra };
}

function enabled(verb) {
  return ENABLED_VERBS.includes(verb);
}

function requireBody(req, res) {
  if (!req.body || typeof req.body !== "object") {
    res.status(400).json(makeError(400, "Invalid JSON body"));
    return false;
  }
  return true;
}

// -----------------------
// SSRF guard for fetch()
// -----------------------
function isPrivateIp(ip) {
  if (!net.isIP(ip)) return false;
  if (net.isIP(ip) === 6) return true; // block ipv6 by default
  const parts = ip.split(".").map((n) => Number(n));
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 0) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}

async function resolveARecords(hostname) {
  const dns = await import("dns/promises");
  try {
    const addrs = await dns.resolve4(hostname);
    return Array.isArray(addrs) ? addrs : [];
  } catch {
    return [];
  }
}

async function ssrfGuardOrThrow(urlStr) {
  if (!ENABLE_SSRF_GUARD) return;
  let u;
  try {
    u = new URL(urlStr);
  } catch {
    throw new Error("fetch requires a valid absolute URL");
  }
  if (!/^https?:$/.test(u.protocol)) throw new Error("fetch only allows http(s)");
  const host = (u.hostname || "").toLowerCase();

  if (ALLOW_FETCH_HOSTS.length) {
    const ok = ALLOW_FETCH_HOSTS.some((h) => host === h || host.endsWith("." + h));
    if (!ok) throw new Error("fetch host not allowed");
  }

  if (host === "localhost" || host.endsWith(".localhost")) throw new Error("fetch host blocked");
  if (host === "169.254.169.254") throw new Error("fetch host blocked");

  if (net.isIP(host) && isPrivateIp(host)) throw new Error("fetch to private IP blocked");

  const addrs = await resolveARecords(host);
  if (addrs.some(isPrivateIp)) throw new Error("fetch DNS resolves to private IP (blocked)");
}

// -----------------------
// ENS TXT pubkey fetch (ethers v6)
// -----------------------
let ensCache = {
  fetched_at: 0,
  ttl_ms: 10 * 60 * 1000,
  pem: null,
  error: null,
  source: null,
};

function hasRpc() {
  return !!ETH_RPC_URL;
}

async function withTimeout(promise, ms, label = "timeout") {
  if (!ms || ms <= 0) return await promise;
  return await Promise.race([promise, new Promise((_, rej) => setTimeout(() => rej(new Error(label)), ms))]);
}

async function fetchEnsPubkeyPem({ refresh = false } = {}) {
  const now = Date.now();
  if (!refresh && ensCache.pem && now - ensCache.fetched_at < ensCache.ttl_ms) {
    return { ok: true, pem: ensCache.pem, source: ensCache.source, cache: { ...ensCache } };
  }
  if (!VERIFIER_ENS_NAME) {
    ensCache = { ...ensCache, fetched_at: now, pem: null, error: "Missing VERIFIER_ENS_NAME", source: null };
    return { ok: false, pem: null, source: null, error: ensCache.error, cache: { ...ensCache } };
  }
  if (!ETH_RPC_URL) {
    ensCache = { ...ensCache, fetched_at: now, pem: null, error: "Missing ETH_RPC_URL", source: null };
    return { ok: false, pem: null, source: null, error: ensCache.error, cache: { ...ensCache } };
  }
  try {
    const provider = new ethers.JsonRpcProvider(ETH_RPC_URL);
    const resolver = await withTimeout(provider.getResolver(VERIFIER_ENS_NAME), 6000, "ens_resolver_timeout");
    if (!resolver) throw new Error("No resolver for ENS name");
    const txt = await withTimeout(resolver.getText(ENS_PUBKEY_TEXT_KEY), 6000, "ens_text_timeout");
    const pem = normalizePem(txt);
    if (!pem) throw new Error(`ENS text ${ENS_PUBKEY_TEXT_KEY} missing/invalid PEM`);
    ensCache = { ...ensCache, fetched_at: now, pem, error: null, source: "ens" };
    return { ok: true, pem, source: "ens", cache: { ...ensCache } };
  } catch (e) {
    ensCache = { ...ensCache, fetched_at: now, pem: null, error: e?.message || "ens fetch failed", source: null };
    return { ok: false, pem: null, source: null, error: ensCache.error, cache: { ...ensCache } };
  }
}

// -----------------------
// AJV schema validation
// -----------------------
const schemaJsonCache = new Map(); // url -> { fetchedAt, schema }
const validatorCache = new Map(); // verb -> { compiledAt, validate }
const inflightValidator = new Map(); // verb -> Promise<validate>

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
  u = u.replace(/^https:\/\/commandlayer\.org/i, "https://www.commandlayer.org");
  u = u.replace(/^https:\/\/www\.commandlayer\.org\/+/, "https://www.commandlayer.org/");
  if (SCHEMA_HOST.startsWith("https://www.commandlayer.org")) {
    u = u.replace(/^https:\/\/commandlayer\.org/i, "https://www.commandlayer.org");
  }
  return u;
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
    loadSchema: async (uri) => {
      return await fetchJsonWithTimeout(uri, SCHEMA_FETCH_TIMEOUT_MS);
    },
  });
  addFormats(ajv);
  return ajv;
}

function receiptSchemaUrlForVerb(verb) {
  return `${SCHEMA_HOST}/schemas/v1.0.0/commons/${verb}/receipts/${verb}.receipt.schema.json`;
}

async function getValidatorForVerb(verb) {
  cachePrune(validatorCache, {
    ttlMs: VALIDATOR_CACHE_TTL_MS,
    maxEntries: MAX_VALIDATOR_CACHE_ENTRIES,
    tsField: "compiledAt",
  });

  const hit = validatorCache.get(verb);
  if (hit?.validate) return hit.validate;

  if (inflightValidator.has(verb)) return await inflightValidator.get(verb);

  const build = (async () => {
    const ajv = makeAjv();
    const url = receiptSchemaUrlForVerb(verb);

    // Preload shared refs (best effort)
    try {
      const shared = [
        `${SCHEMA_HOST}/schemas/v1.0.0/_shared/receipt.base.schema.json`,
        `${SCHEMA_HOST}/schemas/v1.0.0/_shared/x402.schema.json`,
        `${SCHEMA_HOST}/schemas/v1.0.0/_shared/identity.schema.json`,
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

function ajvErrorsToSimple(errors) {
  if (!errors || !Array.isArray(errors)) return null;
  return errors.slice(0, 25).map((e) => ({
    instancePath: e.instancePath,
    schemaPath: e.schemaPath,
    keyword: e.keyword,
    message: e.message,
  }));
}

// -----------------------
// Warm queue (edge-safe)
// -----------------------
const warmQueue = new Set(); // verbs to warm
let warmRunning = false;

function hasValidatorCached(verb) {
  const hit = validatorCache.get(verb);
  return !!hit?.validate;
}

function startWarmWorker() {
  if (warmRunning) return;
  warmRunning = true;

  setTimeout(async () => {
    const started = Date.now();
    try {
      while (warmQueue.size > 0) {
        if (Date.now() - started > PREWARM_TOTAL_BUDGET_MS) break;

        const verb = warmQueue.values().next().value;
        warmQueue.delete(verb);

        if (!handlers[verb]) continue;
        if (hasValidatorCached(verb)) continue;

        try {
          await withTimeout(getValidatorForVerb(verb), PREWARM_PER_VERB_BUDGET_MS, "prewarm_per_verb_timeout");
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

// -----------------------
// receipts (receipt_id excluded from canonical hash)
// -----------------------
function makeReceipt({ x402, trace, result, status = "success", error = null, delegation_result = null, actor = null }) {
  const receipt = {
    status,
    x402,
    trace,
    ...(delegation_result ? { delegation_result } : {}),
    ...(error ? { error } : {}),
    ...(status === "success" ? { result } : {}),
    metadata: {
      proof: {
        alg: "ed25519-sha256",
        canonical: "json-stringify",
        signer_id: SIGNER_ID,
        hash_sha256: null,
        signature_b64: null,
      },
      receipt_id: "",
    },
  };

  if (actor) receipt.metadata.actor = actor;

  const unsigned = structuredClone(receipt);
  unsigned.metadata.proof.hash_sha256 = "";
  unsigned.metadata.proof.signature_b64 = "";
  unsigned.metadata.receipt_id = "";

  const canonical = stableStringify(unsigned);
  const hash = sha256Hex(canonical);
  const sigB64 = signEd25519Base64(hash);

  receipt.metadata.proof.hash_sha256 = hash;
  receipt.metadata.proof.signature_b64 = sigB64;
  receipt.metadata.receipt_id = hash;

  return receipt;
}

// -----------------------
// deterministic verb implementations
// -----------------------
async function doFetch(body) {
  const url = body?.source || body?.input?.source || body?.input?.url;
  if (!url || typeof url !== "string") throw new Error("fetch requires source (url)");

  await ssrfGuardOrThrow(url);

  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
  let resp;
  try {
    resp = await fetch(url, { method: "GET", signal: ac.signal });
  } finally {
    clearTimeout(t);
  }

  const reader = resp.body?.getReader?.();
  let received = 0;
  const chunks = [];

  if (reader) {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > FETCH_MAX_BYTES) break;
      chunks.push(value);
    }
  }

  const buf = chunks.length ? Buffer.concat(chunks.map((u) => Buffer.from(u))) : Buffer.from(await resp.text());
  const text = buf.toString("utf8");
  const preview = text.slice(0, 2000);

  return {
    items: [
      {
        source: url,
        query: body?.query ?? null,
        include_metadata: body?.include_metadata ?? null,
        ok: resp.ok,
        http_status: resp.status,
        headers: Object.fromEntries(resp.headers.entries()),
        body_preview: preview,
        bytes_read: Math.min(received || buf.length, FETCH_MAX_BYTES),
        truncated: (received || buf.length) > FETCH_MAX_BYTES,
      },
    ],
  };
}

function doDescribe(body) {
  const input = body?.input || {};
  const subject = String(input.subject || "").trim();
  if (!subject) throw new Error("describe.input.subject required");
  const audience = input.audience || "general";
  const detail = input.detail_level || "short";
  const bullets = [
    "Schemas define meaning (requests + receipts).",
    "Runtimes can be swapped without breaking interoperability.",
    "Receipts can be independently verified (hash + signature).",
  ];
  const description =
    detail === "short"
      ? `**${subject}** is a standard “API meaning” contract agents can call using published schemas and receipts.`
      : `**${subject}** is a semantic contract for agents. It standardizes verbs, strict JSON Schemas (requests + receipts), and verifiable receipts so different runtimes can execute the same intent without semantic drift.`;
  return { description, bullets, properties: { verb: "describe", version: "1.0.0", audience, detail_level: detail } };
}

function doFormat(body) {
  const input = body?.input || {};
  const content = String(input.content ?? "");
  const target = input.target_style || "text";
  if (!content.trim()) throw new Error("format.input.content required");
  let formatted = content;
  let style = target;
  if (target === "table") {
    const lines = content
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    const rows = [];
    for (const ln of lines) {
      const m = ln.match(/^([^:]+):\s*(.*)$/);
      if (m) rows.push([m[1].trim(), m[2].trim()]);
    }
    formatted = `| key | value |\n|---|---|\n` + rows.map(([k, v]) => `| ${k} | ${v} |`).join("\n");
    style = "table";
  }
  return {
    formatted_content: formatted,
    style,
    original_length: content.length,
    formatted_length: formatted.length,
    notes: "Deterministic reference formatter (non-LLM).",
  };
}

function doClean(body) {
  const input = body?.input || {};
  let content = String(input.content ?? "");
  if (!content) throw new Error("clean.input.content required");
  const ops = Array.isArray(input.operations) ? input.operations : [];
  const issues = [];
  const apply = (op) => {
    if (op === "normalize_newlines") content = content.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    if (op === "collapse_whitespace") content = content.replace(/[ \t]+/g, " ");
    if (op === "trim") content = content.trim();
    if (op === "remove_empty_lines") content = content.split("\n").filter((l) => l.trim() !== "").join("\n");
    if (op === "redact_emails") {
      const before = content;
      content = content.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[redacted-email]");
      if (content !== before) issues.push("emails_redacted");
    }
  };
  for (const op of ops) apply(op);
  return {
    cleaned_content: content,
    original_length: String(input.content ?? "").length,
    cleaned_length: content.length,
    operations_applied: ops,
    issues_detected: issues,
  };
}

function parseYamlBestEffort(text) {
  const out = {};
  const lines = text.split(/\r?\n/);
  for (const ln of lines) {
    const m = ln.match(/^\s*([^:#]+)\s*:\s*(.*?)\s*$/);
    if (m) out[m[1].trim()] = m[2].trim();
  }
  return out;
}

function doParse(body) {
  const input = body?.input || {};
  const content = String(input.content ?? "");
  if (!content.trim()) throw new Error("parse.input.content required");
  const contentType = (input.content_type || "").toLowerCase();
  const mode = input.mode || "best_effort";
  let parsed = null;
  let confidence = 0.75;
  const warnings = [];

  if (contentType === "json") {
    try {
      parsed = JSON.parse(content);
      confidence = 0.98;
    } catch {
      if (mode === "strict") throw new Error("invalid json");
      warnings.push("Invalid JSON; returned empty object in best_effort.");
      parsed = {};
      confidence = 0.2;
    }
  } else if (contentType === "yaml") {
    parsed = parseYamlBestEffort(content);
    confidence = 0.75;
  } else {
    try {
      parsed = JSON.parse(content);
      confidence = 0.9;
    } catch {
      parsed = parseYamlBestEffort(content);
      confidence = Object.keys(parsed).length ? 0.6 : 0.3;
      if (!Object.keys(parsed).length) warnings.push("Could not confidently parse content.");
    }
  }

  const result = { parsed, confidence };
  if (warnings.length) result.warnings = warnings;
  if (input.target_schema) result.target_schema = String(input.target_schema);
  return result;
}

function doSummarize(body) {
  const input = body?.input || {};
  const content = String(input.content ?? "");
  if (!content.trim()) throw new Error("summarize.input.content required");
  const style = input.summary_style || "text";
  const format = (input.format_hint || "text").toLowerCase();
  const sentences = content.split(/(?<=[.!?])\s+/).filter(Boolean);

  let summary = "";
  if (style === "bullet_points") {
    const picks = sentences.slice(0, 3).map((s) => s.replace(/\s+/g, " ").trim());
    summary = picks.join(" ");
  } else {
    summary = sentences.slice(0, 2).join(" ").trim();
  }
  if (!summary) summary = content.slice(0, 400).trim();

  const srcHash = sha256Hex(content);
  const cr = summary.length ? Number((content.length / summary.length).toFixed(3)) : 0;

  return { summary, format: format === "markdown" ? "markdown" : "text", compression_ratio: cr, source_hash: srcHash };
}

function doConvert(body) {
  const input = body?.input || {};
  const content = String(input.content ?? "");
  const src = String(input.source_format ?? "").toLowerCase();
  const tgt = String(input.target_format ?? "").toLowerCase();
  if (!content.trim()) throw new Error("convert.input.content required");
  if (!src) throw new Error("convert.input.source_format required");
  if (!tgt) throw new Error("convert.input.target_format required");

  let converted = content;
  const warnings = [];
  let lossy = false;

  if (src === "json" && tgt === "csv") {
    let obj;
    try {
      obj = JSON.parse(content);
    } catch {
      throw new Error("convert json->csv requires valid JSON");
    }
    if (obj && typeof obj === "object" && !Array.isArray(obj)) {
      const keys = Object.keys(obj);
      const vals = keys.map((k) => String(obj[k]));
      converted = `${keys.join(",")}\n${vals.join(",")}`;
      lossy = true;
      warnings.push("JSON->CSV is lossy (types/nesting may be flattened).");
    } else {
      throw new Error("convert json->csv supports only flat JSON objects");
    }
  } else {
    warnings.push(`No deterministic converter for ${src}->${tgt}; echoing content.`);
  }

  return { converted_content: converted, source_format: src, target_format: tgt, lossy, warnings };
}

function doExplain(body) {
  const input = body?.input || {};
  const subject = String(input.subject || "").trim();
  if (!subject) throw new Error("explain.input.subject required");
  const audience = input.audience || "general";
  const style = input.style || "plain";
  const detail = input.detail_level || "short";

  const core = [
    `A “receipt” is verifiable evidence that an execution happened under a specific verb + schema version.`,
    `It includes the structured output plus a cryptographic hash and signature.`,
    `Because the schema is public, anyone can independently validate the receipt later.`,
  ];

  const steps = [
    "1) Validate the request against the published request schema.",
    "2) Execute the verb and produce structured output.",
    "3) Build the receipt (base fields + result).",
    "4) Canonicalize + hash the unsigned receipt.",
    "5) Sign the hash with the runtime signer key.",
    "6) Anyone can verify schema validity + hash match + signature (optionally resolving pubkey from ENS).",
  ];

  let explanation = "";
  if (audience === "novice") {
    explanation = `**${subject}** are like “tamper-proof receipts” for agent actions.\n\n` + core.map((s) => `- ${s}`).join("\n");
  } else {
    explanation =
      `**${subject}** are cryptographically verifiable execution artifacts that bind intent (verb+version), semantics (schema), and output into a signed proof.\n\n` +
      core.map((s) => `- ${s}`).join("\n");
  }

  const result = { explanation };
  if (detail !== "short" || style === "step-by-step") result.steps = steps;
  result.summary = "Receipts are evidence, not logs: validate schema + hash + signature.";
  result.references = [
    "https://www.commandlayer.org/schemas/v1.0.0/_shared/receipt.base.schema.json",
    "https://www.commandlayer.org/schemas/v1.0.0/_shared/x402.schema.json",
  ];
  return result;
}

function doAnalyze(body) {
  const input = String(body?.input ?? "");
  if (!input.trim()) throw new Error("analyze.input required (string)");
  const goal = String(body?.goal ?? "").trim();
  const hints = Array.isArray(body?.hints) ? body.hints.map(String) : [];
  const lines = input.split(/\r?\n/).filter((l) => l.trim() !== "");
  const words = input.trim().split(/\s+/).filter(Boolean);

  const containsUrls = /\bhttps?:\/\/[^\s]+/i.test(input);
  const containsEmails = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(input);
  const containsJsonMarkers = /[{[\]}]/.test(input);
  const containsNumbers = /\b\d+(\.\d+)?\b/.test(input);

  const labels = [];
  if (containsJsonMarkers) labels.push("structured");
  if (containsUrls) labels.push("contains_urls");
  if (containsEmails) labels.push("contains_emails");

  const topTerms = input
    .toLowerCase()
    .replace(/[^a-z0-9\s._:-]/g, " ")
    .split(/\s+/)
    .filter(Boolean)
    .reduce((acc, w) => ((acc[w] = (acc[w] || 0) + 1), acc), {});

  const top = Object.entries(topTerms)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([k]) => k);

  let score = 0;
  if (containsEmails) score += 0.25;
  if (containsUrls) score += 0.2;
  if (containsJsonMarkers) score += 0.1;
  if (containsNumbers) score += 0.05;
  score = Math.min(1, Number(score.toFixed(3)));

  const summary = `Deterministic analysis: ${labels.join(",") || "plain_text"}. Goal="${goal || "n/a"}". Score=${score}.`;
  const insights = [
    `Input length: ${input.length} chars; ~${words.length} words; ${lines.length} non-empty lines.`,
    goal ? `Goal: ${goal}` : "Goal: (none)",
    `Hints provided: ${hints.length}.`,
  ];
  if (containsJsonMarkers) insights.push("Content appears to include JSON/structured data markers.");
  if (containsUrls) insights.push("Content includes URL(s).");
  if (containsEmails) insights.push("Content includes email-like strings.");
  if (containsNumbers) insights.push("Content includes numeric values.");
  insights.push(`Top terms: ${top.join(", ")}`);

  return { summary, insights, labels, score };
}

function doClassify(body) {
  // Accept both "actor" at top-level (old) and x402.tenant (newer),
  // but keep deterministic error if neither exists.
  const actor =
    String(body?.actor ?? "").trim() ||
    String(body?.x402?.tenant ?? "").trim();

  if (!actor) throw new Error("classify.actor required");

  const input = body?.input || {};
  const content = String(input.content ?? "");
  if (!content.trim()) throw new Error("classify.input.content required");
  const maxLabels = Number(body?.limits?.max_labels || 5);

  const labels = [];
  const scores = [];
  const hasUrl = /\bhttps?:\/\/[^\s]+/i.test(content);
  const hasEmail = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(content);
  const hasCode = /\b(error|exception|stack|trace|cannot get|http\/1\.1|curl)\b/i.test(content.toLowerCase());
  const hasFinance = /\b(invoice|payment|usd|\$|bank|wire|crypto)\b/i.test(content.toLowerCase());

  const push = (lbl, sc) => {
    labels.push(lbl);
    scores.push(Number(sc.toFixed(6)));
  };

  if (hasUrl) push("contains_urls", 0.733333);
  if (hasEmail) push("contains_emails", 0.5);
  if (hasCode) push("code_or_logs", 0.4375);
  if (hasFinance) push("finance", 0.25);
  if (!labels.length) push("general", 0.25);

  const trimmedLabels = labels.slice(0, Math.min(128, maxLabels));
  const trimmedScores = scores.slice(0, trimmedLabels.length);

  return { labels: trimmedLabels, scores: trimmedScores, taxonomy: ["root", trimmedLabels[0] || "general"] };
}

// Router: dispatch by verb
const handlers = {
  fetch: doFetch,
  describe: async (b) => doDescribe(b),
  format: async (b) => doFormat(b),
  clean: async (b) => doClean(b),
  parse: async (b) => doParse(b),
  summarize: async (b) => doSummarize(b),
  convert: async (b) => doConvert(b),
  explain: async (b) => doExplain(b),
  analyze: async (b) => doAnalyze(b),
  classify: async (b) => doClassify(b),
};

async function handleVerb(verb, req, res) {
  if (!enabled(verb)) return res.status(404).json(makeError(404, `Verb not enabled: ${verb}`));
  if (!requireBody(req, res)) return;

  const started = Date.now();

  // -----------------------
  // TRACE (schema-correct)
  // - receipt.trace.trace_id        = runtime execution id (minted here)
  // - receipt.trace.parent_trace_id = upstream/workflow trace id (if provided)
  //
  // Accept upstream trace_id from:
  //   - req.body.trace.trace_id (your composer sends this UUID)
  //   - req.body.trace_id (legacy)
  // Accept explicit parent_trace_id from:
  //   - req.body.trace.parent_trace_id
  //   - req.body.x402.extras.parent_trace_id (legacy hook)
  // -----------------------
  const rawInboundTraceId =
    req.body?.trace?.trace_id ??
    req.body?.trace_id ??
    null;

  const inboundTraceId =
    typeof rawInboundTraceId === "string" && rawInboundTraceId.trim().length
      ? rawInboundTraceId.trim()
      : null;

  const rawExplicitParent =
    req.body?.trace?.parent_trace_id ??
    req.body?.x402?.extras?.parent_trace_id ??
    null;

  const explicitParentTraceId =
    typeof rawExplicitParent === "string" && rawExplicitParent.trim().length
      ? rawExplicitParent.trim()
      : null;

  // Prefer explicit parent_trace_id if present; otherwise treat inbound trace_id as the parent/workflow id.
  const parentTraceId = explicitParentTraceId || inboundTraceId || null;

  const trace = {
    trace_id: randId("trace_"), // runtime span/execution id
    ...(parentTraceId ? { parent_trace_id: parentTraceId } : {}),
    started_at: nowIso(),
    completed_at: null,
    duration_ms: null,
    provider: process.env.RAILWAY_SERVICE_NAME || "runtime",
  };

  try {
    const x402 = req.body?.x402 || { verb, version: "1.0.0", entry: `x402://${verb}agent.eth/${verb}/v1.0.0` };

    const callerTimeout = Number(req.body?.limits?.timeout_ms || req.body?.limits?.max_latency_ms || 0);
    const timeoutMs = Math.min(
      SERVER_MAX_HANDLER_MS,
      callerTimeout && callerTimeout > 0 ? callerTimeout : SERVER_MAX_HANDLER_MS
    );

    const work = Promise.resolve(handlers[verb](req.body));
    const result = timeoutMs
      ? await Promise.race([work, new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), timeoutMs))])
      : await work;

    trace.completed_at = nowIso();
    trace.duration_ms = Date.now() - started;

    const actor = req.body?.actor
      ? { id: String(req.body.actor), role: "user" }
      : req.body?.x402?.tenant
      ? { id: String(req.body.x402.tenant), role: "tenant" }
      : null;

    const receipt = makeReceipt({ x402, trace, result, status: "success", actor });
    return res.json(receipt);
  } catch (e) {
    trace.completed_at = nowIso();
    trace.duration_ms = Date.now() - started;

    const x402 = req.body?.x402 || { verb, version: "1.0.0", entry: `x402://${verb}agent.eth/${verb}/v1.0.0` };

    const actor = req.body?.actor
      ? { id: String(req.body.actor), role: "user" }
      : req.body?.x402?.tenant
      ? { id: String(req.body.x402.tenant), role: "tenant" }
      : null;

    const err = {
      code: String(e?.code || "INTERNAL_ERROR"),
      message: String(e?.message || "unknown error").slice(0, 2048),
      retryable: String(e?.message || "").includes("timeout"),
      details: { verb },
    };

    const receipt = makeReceipt({ x402, trace, status: "error", error: err, actor });
    return res.status(500).json(receipt);
  }
}

// -----------------------
// health/index/debug
// -----------------------
app.get("/", (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  const verbs = (ENABLED_VERBS || []).map((v) => `/${v}/v${API_VERSION}`);
  return res.status(200).end(
    JSON.stringify({
      ok: true,
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      api_version: API_VERSION,
      base: CANONICAL_BASE,
      health: "/health",
      verify: "/verify",
      verbs,
      docs: "https://commandlayer.org/runtime.html",
      schemas: "https://commandlayer.org/schemas",
      time: nowIso(),
    })
  );
});

app.get("/health", (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  return res.status(200).end(
    JSON.stringify({
      ok: true,
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      api_version: API_VERSION,
      base: CANONICAL_BASE,
      node: process.version,
      port: PORT,
      enabled_verbs: ENABLED_VERBS,
      signer_id: SIGNER_ID,
      signer_ok: !!pemFromB64(PRIV_PEM_B64),
      time: nowIso(),
    })
  );
});

app.get("/debug/env", (req, res) => {
  res.json({
    ok: true,
    node: process.version,
    port: PORT,
    service: process.env.RAILWAY_SERVICE_NAME || "runtime",
    enabled_verbs: ENABLED_VERBS,
    signer_id: SIGNER_ID,
    signer_ok: !!pemFromB64(PRIV_PEM_B64),
    has_priv_b64: !!PRIV_PEM_B64,
    has_pub_b64: !!PUB_PEM_B64,
    verifier_ens_name: VERIFIER_ENS_NAME || null,
    ens_pubkey_text_key: ENS_PUBKEY_TEXT_KEY,
    has_rpc: hasRpc(),
    schema_host: SCHEMA_HOST,
    schema_fetch_timeout_ms: SCHEMA_FETCH_TIMEOUT_MS,
    schema_validate_budget_ms: SCHEMA_VALIDATE_BUDGET_MS,
    verify_schema_cached_only: VERIFY_SCHEMA_CACHED_ONLY,

    enable_ssrf_guard: ENABLE_SSRF_GUARD,
    fetch_timeout_ms: FETCH_TIMEOUT_MS,
    fetch_max_bytes: FETCH_MAX_BYTES,
    verify_max_ms: VERIFY_MAX_MS,
    cache: {
      max_json_cache_entries: MAX_JSON_CACHE_ENTRIES,
      json_cache_ttl_ms: JSON_CACHE_TTL_MS,
      max_validator_cache_entries: MAX_VALIDATOR_CACHE_ENTRIES,
      validator_cache_ttl_ms: VALIDATOR_CACHE_TTL_MS,
    },
    server_max_handler_ms: SERVER_MAX_HANDLER_MS,
    prewarm: {
      max_verbs: PREWARM_MAX_VERBS,
      total_budget_ms: PREWARM_TOTAL_BUDGET_MS,
      per_verb_budget_ms: PREWARM_PER_VERB_BUDGET_MS,
    },
    service_name: SERVICE_NAME,
    service_version: SERVICE_VERSION,
    api_version: API_VERSION,
    canonical_base_url: CANONICAL_BASE,
  });
});

app.get("/debug/enskey", async (req, res) => {
  const refresh = String(req.query.refresh || "0") === "1";
  const out = await fetchEnsPubkeyPem({ refresh });
  res.json({
    ok: !!out.ok,
    pubkey_source: out.source || null,
    ens_name: VERIFIER_ENS_NAME || null,
    txt_key: ENS_PUBKEY_TEXT_KEY,
    cache: out.cache ? { fetched_at: new Date(out.cache.fetched_at).toISOString(), ttl_ms: out.cache.ttl_ms } : null,
    preview: out.pem ? out.pem.slice(0, 80) + "..." : null,
    error: out.error || null,
  });
});

app.get("/debug/schemafetch", (req, res) => {
  const verb = String(req.query.verb || "").trim();
  if (!verb) return res.status(400).json({ ok: false, error: "missing verb" });
  const url = receiptSchemaUrlForVerb(verb);
  res.json({
    ok: true,
    url,
    id: `https://commandlayer.org/schemas/v1.0.0/commons/${verb}/receipts/${verb}.receipt.schema.json`,
    hasRefs: true,
  });
});

app.get("/debug/validators", (req, res) => {
  res.json({
    ok: true,
    cached: Array.from(validatorCache.keys()),
    cache_sizes: { schemaJsonCache: schemaJsonCache.size, validatorCache: validatorCache.size },
    inflight: Array.from(inflightValidator.keys()),
    warm_queue_size: warmQueue.size,
    warm_running: warmRunning,
  });
});

// -----------------------
// EDGE-SAFE prewarm: responds immediately, warms AFTER response
// -----------------------
app.post("/debug/prewarm", (req, res) => {
  const verbs = Array.isArray(req.body?.verbs) ? req.body.verbs : [];
  const cleaned = verbs
    .map((v) => String(v || "").trim())
    .filter(Boolean)
    .slice(0, PREWARM_MAX_VERBS);

  const supported = cleaned.filter((v) => handlers[v]);

  for (const v of supported) warmQueue.add(v);

  res.json({
    ok: true,
    queued: supported,
    already_cached: supported.filter(hasValidatorCached),
    queue_size: warmQueue.size,
    note: "Warming runs after response; poll /debug/validators for cached validators.",
  });

  startWarmWorker();
});

// -----------------------
// verb routes: /<verb>/v1.0.0
// -----------------------
for (const v of Object.keys(handlers)) {
  app.post(`/${v}/v1.0.0`, (req, res) => handleVerb(v, req, res));
}

// -----------------------
// verify endpoint (schema validation + ENS pubkey)
// - schema=1 (default off) is EDGE-SAFE:
//     if VERIFY_SCHEMA_CACHED_ONLY=1, it only validates if cached; otherwise returns 202 and queues warm.
// - ens=1 resolves pubkey from ENS (still bounded by VERIFY_MAX_MS)
// -----------------------
app.post("/verify", async (req, res) => {
  const work = (async () => {
    const receipt = req.body;
    const wantEns = String(req.query.ens || "0") === "1";
    const refresh = String(req.query.refresh || "0") === "1";
    const wantSchema = String(req.query.schema || "0") === "1";

    const fail = (httpCode, message, patch = {}) => {
      return res.status(httpCode).json({
        ok: false,
        checks: { schema_valid: false, hash_matches: false, signature_valid: false },
        values: {
          verb: receipt?.x402?.verb ?? null,
          signer_id: receipt?.metadata?.proof?.signer_id ?? null,
          alg: receipt?.metadata?.proof?.alg ?? null,
          canonical: receipt?.metadata?.proof?.canonical ?? null,
          claimed_hash: receipt?.metadata?.proof?.hash_sha256 ?? null,
          recomputed_hash: null,
          pubkey_source: null,
        },
        errors: { schema_errors: null, signature_error: message },
        error: message,
        ...patch,
      });
    };

    try {
      const proof = receipt?.metadata?.proof;
      if (!proof?.signature_b64 || !proof?.hash_sha256) {
        return fail(400, "missing metadata.proof.signature_b64 or hash_sha256");
      }

      const unsigned = structuredClone(receipt);
      unsigned.metadata.proof.hash_sha256 = "";
      unsigned.metadata.proof.signature_b64 = "";
      if (unsigned?.metadata) unsigned.metadata.receipt_id = "";
      const canonical = stableStringify(unsigned);
      const recomputed = sha256Hex(canonical);

      const hashMatches = recomputed === proof.hash_sha256;

      let pubPem = pemFromB64(PUB_PEM_B64);
      let pubSrc = pubPem ? "env-b64" : null;

      if (wantEns) {
        const ensOut = await fetchEnsPubkeyPem({ refresh });
        if (ensOut.ok && ensOut.pem) {
          pubPem = ensOut.pem;
          pubSrc = "ens";
        } else if (!pubPem) {
          pubSrc = null;
        }
      }

      let sigOk = false;
      let sigErr = null;

      if (pubPem) {
        try {
          sigOk = verifyEd25519Base64(proof.hash_sha256, proof.signature_b64, pubPem);
        } catch (e) {
          sigOk = false;
          sigErr = e?.message || "signature verify failed";
        }
      } else {
        sigOk = false;
        sigErr = "no public key available (set RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 or pass ens=1 with ETH_RPC_URL)";
      }

      // Schema validation (edge-safe)
      let schemaOk = true;
      let schemaErrors = null;

      if (wantSchema) {
        schemaOk = false;
        const verb = String(receipt?.x402?.verb || "").trim();

        if (!verb) {
          schemaErrors = [{ message: "missing receipt.x402.verb" }];
        } else if (VERIFY_SCHEMA_CACHED_ONLY && !hasValidatorCached(verb)) {
          // Do NOT compile/fetch here; queue warm and return 202
          warmQueue.add(verb);
          startWarmWorker();
          schemaErrors = [{ message: "validator_not_warmed_yet" }];

          return res.status(202).json({
            ok: false,
            checks: { schema_valid: false, hash_matches: hashMatches, signature_valid: sigOk },
            values: {
              verb: receipt?.x402?.verb ?? null,
              signer_id: proof.signer_id ?? null,
              alg: proof.alg ?? null,
              canonical: proof.canonical ?? null,
              claimed_hash: proof.hash_sha256 ?? null,
              recomputed_hash: recomputed,
              pubkey_source: pubSrc,
            },
            errors: { schema_errors: schemaErrors, signature_error: sigErr },
            retry_after_ms: 1000,
          });
        } else {
          try {
            const validate = VERIFY_SCHEMA_CACHED_ONLY ? validatorCache.get(verb)?.validate : await getValidatorForVerb(verb);

            if (!validate) {
              schemaOk = false;
              schemaErrors = [{ message: "validator_missing" }];
            } else {
              const ok = validate(receipt);
              schemaOk = !!ok;
              if (!ok) schemaErrors = ajvErrorsToSimple(validate.errors) || [{ message: "schema validation failed" }];
            }
          } catch (e) {
            schemaOk = false;
            schemaErrors = [{ message: e?.message || "schema validation error" }];
          }
        }
      }

      return res.json({
        ok: hashMatches && sigOk && schemaOk,
        checks: { schema_valid: schemaOk, hash_matches: hashMatches, signature_valid: sigOk },
        values: {
          verb: receipt?.x402?.verb ?? null,
          signer_id: proof.signer_id ?? null,
          alg: proof.alg ?? null,
          canonical: proof.canonical ?? null,
          claimed_hash: proof.hash_sha256 ?? null,
          recomputed_hash: recomputed,
          pubkey_source: pubSrc,
        },
        errors: { schema_errors: schemaErrors, signature_error: sigErr },
      });
    } catch (e) {
      return res.status(500).json({
        ok: false,
        error: e?.message || "verify failed",
        checks: { schema_valid: false, hash_matches: false, signature_valid: false },
        values: {
          verb: receipt?.x402?.verb ?? null,
          signer_id: receipt?.metadata?.proof?.signer_id ?? null,
          alg: receipt?.metadata?.proof?.alg ?? null,
          canonical: receipt?.metadata?.proof?.canonical ?? null,
          claimed_hash: receipt?.metadata?.proof?.hash_sha256 ?? null,
          recomputed_hash: null,
          pubkey_source: null,
        },
        errors: { schema_errors: null, signature_error: e?.message || "verify failed" },
      });
    }
  })();

  try {
    await Promise.race([work, new Promise((_, rej) => setTimeout(() => rej(new Error("verify_timeout")), VERIFY_MAX_MS))]);
  } catch (e) {
    return res.status(500).json({
      ok: false,
      error: e?.message || "verify failed",
      checks: { schema_valid: false, hash_matches: false, signature_valid: false },
      values: {
        verb: req.body?.x402?.verb ?? null,
        signer_id: req.body?.metadata?.proof?.signer_id ?? null,
        alg: req.body?.metadata?.proof?.alg ?? null,
        canonical: req.body?.metadata?.proof?.canonical ?? null,
        claimed_hash: req.body?.metadata?.proof?.hash_sha256 ?? null,
        recomputed_hash: null,
        pubkey_source: null,
      },
      errors: { schema_errors: [{ message: e?.message || "verify failed" }], signature_error: null },
    });
  }
});

app.listen(PORT, () => {
  console.log(`runtime listening on :${PORT}`);
});
