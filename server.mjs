// server.mjs
import express from "express";
import crypto from "crypto";

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

const ENABLED_VERBS = (process.env.ENABLED_VERBS ||
  "fetch,describe,format,clean,parse,summarize,convert,explain,analyze,classify")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const SIGNER_ID = process.env.RECEIPT_SIGNER_ID || process.env.ENS_NAME || "runtime";

const PRIV_PEM_B64 = process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64 || "";
const PUB_PEM_B64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "";

// ENS verifier
const VERIFIER_ENS_NAME = process.env.VERIFIER_ENS_NAME || SIGNER_ID;
const ENS_PUBKEY_TEXT_KEY = process.env.ENS_PUBKEY_TEXT_KEY || "cl.receipt.pubkey.pem";
const ETH_RPC_URL = process.env.ETH_RPC_URL || "";
const ENS_LOOKUP_TIMEOUT_MS = Number(process.env.ENS_LOOKUP_TIMEOUT_MS || 2500);

// AJV/schema (ONLY when schema=1)
const SCHEMA_CACHE_TTL_MS = Number(process.env.SCHEMA_CACHE_TTL_MS || 600000);
const SCHEMA_FETCH_TIMEOUT_MS = Number(process.env.SCHEMA_FETCH_TIMEOUT_MS || 5000);
const AJV_COMPILE_TIMEOUT_MS = Number(process.env.AJV_COMPILE_TIMEOUT_MS || 4000);
const SCHEMA_VALIDATE_TIMEOUT_MS = Number(process.env.SCHEMA_VALIDATE_TIMEOUT_MS || 2500);

// Use www host to avoid redirect/ref mismatch
const SCHEMA_HOST = process.env.SCHEMA_HOST || "https://www.commandlayer.org";

// -------------------------
// Utils
// -------------------------
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

function withTimeout(promise, ms, label = "timeout") {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`${label} after ${ms}ms`)), ms)),
  ]);
}

// -------------------------
// Fetch helper (Node 22 has global fetch)
// -------------------------
async function getFetch() {
  if (typeof globalThis.fetch === "function") return globalThis.fetch.bind(globalThis);
  const mod = await import("node-fetch");
  return mod.default;
}

// -------------------------
// Receipt builder
// -------------------------
function makeReceipt({ x402, trace, result }) {
  const receipt = {
    status: "success",
    x402,
    trace,
    result,
    metadata: {
      proof: {
        alg: "ed25519-sha256",
        canonical: "json-stringify",
        signer_id: SIGNER_ID,
        hash_sha256: null,
        signature_b64: null,
      },
    },
  };

  const unsigned = structuredClone(receipt);
  unsigned.metadata.proof.hash_sha256 = "";
  unsigned.metadata.proof.signature_b64 = "";

  const canonical = stableStringify(unsigned);
  const hash = sha256Hex(canonical);
  const sigB64 = signEd25519Base64(hash);

  receipt.metadata.proof.hash_sha256 = hash;
  receipt.metadata.proof.signature_b64 = sigB64;

  return receipt;
}

// -------------------------
// ENS pubkey resolver (ethers) — HARD TIMEOUT
// -------------------------
let ensKeyCache = {
  fetched_at: null,
  ttl_ms: 600000,
  pubkey_pem: null,
  error: null,
};

function ensCacheFresh() {
  if (!ensKeyCache.fetched_at) return false;
  return Date.now() - ensKeyCache.fetched_at.getTime() < ensKeyCache.ttl_ms;
}

async function resolveEnsPubkeyPem({ refresh = false } = {}) {
  if (!ETH_RPC_URL) {
    ensKeyCache.error = "missing ETH_RPC_URL";
    ensKeyCache.pubkey_pem = null;
    ensKeyCache.fetched_at = new Date();
    return { ok: false, pubkey_pem: null, error: ensKeyCache.error };
  }

  if (!refresh && ensCacheFresh() && ensKeyCache.pubkey_pem) {
    return { ok: true, pubkey_pem: ensKeyCache.pubkey_pem, error: null, cache: ensKeyCache };
  }

  try {
    const { ethers } = await import("ethers");
    const provider = new ethers.JsonRpcProvider(ETH_RPC_URL);

    const txt = await withTimeout(
      provider.getText(VERIFIER_ENS_NAME, ENS_PUBKEY_TEXT_KEY),
      ENS_LOOKUP_TIMEOUT_MS,
      "ens lookup timeout"
    );

    if (!txt || typeof txt !== "string" || !txt.includes("BEGIN PUBLIC KEY")) {
      ensKeyCache.pubkey_pem = null;
      ensKeyCache.error = `TXT missing/invalid: ${VERIFIER_ENS_NAME} ${ENS_PUBKEY_TEXT_KEY}`;
      ensKeyCache.fetched_at = new Date();
      return { ok: false, pubkey_pem: null, error: ensKeyCache.error, cache: ensKeyCache };
    }

    ensKeyCache.pubkey_pem = txt;
    ensKeyCache.error = null;
    ensKeyCache.fetched_at = new Date();

    return { ok: true, pubkey_pem: txt, error: null, cache: ensKeyCache };
  } catch (e) {
    ensKeyCache.pubkey_pem = null;
    ensKeyCache.error = e?.message || "ENS pubkey resolve failed";
    ensKeyCache.fetched_at = new Date();
    return { ok: false, pubkey_pem: null, error: ensKeyCache.error, cache: ensKeyCache };
  }
}

// -------------------------
// AJV schema validation — ONLY when schema=1 (HARD TIMEOUTS)
// -------------------------
let ajv = null;

function normalizeSchemaUrl(uri) {
  if (!uri || typeof uri !== "string") return uri;
  try {
    const u = new URL(uri);
    if (u.hostname === "commandlayer.org" || u.hostname === "www.commandlayer.org") {
      const host = new URL(SCHEMA_HOST);
      u.protocol = host.protocol;
      u.hostname = host.hostname;
      return u.toString();
    }
    return uri;
  } catch {
    return uri;
  }
}

const schemaFetchCache = new Map(); // url -> { fetchedAt, json }
async function fetchSchemaJson(uri) {
  const norm = normalizeSchemaUrl(uri);
  const now = Date.now();

  const cached = schemaFetchCache.get(norm);
  if (cached && now - cached.fetchedAt < SCHEMA_CACHE_TTL_MS) return cached.json;

  const fetchFn = await getFetch();
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), SCHEMA_FETCH_TIMEOUT_MS);

  try {
    const resp = await fetchFn(norm, {
      method: "GET",
      headers: { Accept: "application/json" },
      redirect: "follow",
      signal: controller.signal,
    });
    if (!resp.ok) throw new Error(`schema fetch failed ${resp.status} for ${norm}`);
    const json = await resp.json();
    schemaFetchCache.set(norm, { fetchedAt: Date.now(), json });
    return json;
  } finally {
    clearTimeout(t);
  }
}

async function getAjv() {
  if (ajv) return ajv;

  const AjvMod = await import("ajv");
  const Ajv = AjvMod.default || AjvMod;
  const FormatsMod = await import("ajv-formats");
  const addFormats = FormatsMod.default || FormatsMod;

  const inst = new Ajv({
    strict: false,
    allErrors: true,
    loadSchema: async (uri) => fetchSchemaJson(uri),
  });
  addFormats(inst);

  ajv = inst;
  return ajv;
}

function receiptSchemaIdForVerb(verb) {
  const v = String(verb || "").trim();
  return `${SCHEMA_HOST}/schemas/v1.0.0/commons/${v}/receipts/${v}.receipt.schema.json`;
}

const validatorCache = new Map(); // schemaId -> { validate, fetchedAt }
const inflightValidators = new Map(); // schemaId -> Promise

async function getReceiptValidator(verb) {
  const schemaId = receiptSchemaIdForVerb(verb);
  const now = Date.now();

  const cached = validatorCache.get(schemaId);
  if (cached && now - cached.fetchedAt < SCHEMA_CACHE_TTL_MS) return cached.validate;

  if (inflightValidators.has(schemaId)) return await inflightValidators.get(schemaId);

  const p = (async () => {
    const ajvInst = await getAjv();
    const compileP = ajvInst.compileAsync({ $ref: schemaId });
    const validate = await withTimeout(compileP, AJV_COMPILE_TIMEOUT_MS, "ajv compile timeout");
    validatorCache.set(schemaId, { validate, fetchedAt: Date.now() });
    return validate;
  })();

  inflightValidators.set(schemaId, p);
  try {
    return await p;
  } finally {
    inflightValidators.delete(schemaId);
  }
}

// -------------------------
// Verb implementations (deterministic ref versions)
// -------------------------
async function doFetch(body) {
  const url = body?.source || body?.input?.source || body?.input?.url;
  if (!url || typeof url !== "string") throw new Error("fetch requires source (url)");
  const fetchFn = await getFetch();
  const resp = await fetchFn(url, { method: "GET" });
  const text = await resp.text();
  return {
    items: [
      {
        source: url,
        query: body?.query ?? null,
        include_metadata: body?.include_metadata ?? null,
        ok: resp.ok,
        http_status: resp.status,
        headers: Object.fromEntries(resp.headers.entries?.() ?? []),
        body_preview: text.slice(0, 2000),
      },
    ],
  };
}

function doDescribe(body) {
  const input = body?.input || {};
  const subject = String(input.subject || "").trim();
  if (!subject) throw new Error("describe.input.subject required");
  const detail = input.detail_level || "short";

  const bullets = [
    "Schemas define meaning (requests + receipts).",
    "Runtimes can be swapped without breaking interoperability.",
    "Receipts can be independently verified (schema + hash + signature).",
  ];

  const description =
    detail === "short"
      ? `**${subject}** is a semantic contract for agents: published verbs + schemas + verifiable receipts.`
      : `**${subject}** standardizes agent verbs using strict JSON Schemas and cryptographically verifiable receipts.`;

  return { description, bullets };
}

function doFormat(body) {
  const input = body?.input || {};
  const content = String(input.content ?? "");
  const target = input.target_style || "text";
  if (!content.trim()) throw new Error("format.input.content required");

  let formatted = content;
  let style = target;

  if (target === "table") {
    const lines = content.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
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
  return result;
}

function doSummarize(body) {
  const input = body?.input || {};
  const content = String(input.content ?? "");
  if (!content.trim()) throw new Error("summarize.input.content required");

  const style = input.summary_style || "text";
  const sentences = content.split(/(?<=[.!?])\s+/).filter(Boolean);

  let summary = "";
  if (style === "bullet_points") {
    summary = sentences.slice(0, 3).map((s) => s.replace(/\s+/g, " ").trim()).join(" ");
  } else {
    summary = sentences.slice(0, 2).join(" ").trim();
  }
  if (!summary) summary = content.slice(0, 400).trim();

  return {
    summary,
    source_hash: sha256Hex(content),
  };
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

  return { converted_content: converted, lossy, warnings };
}

function doExplain(body) {
  const input = body?.input || {};
  const subject = String(input.subject || "").trim();
  if (!subject) throw new Error("explain.input.subject required");

  return {
    explanation: `**${subject}** are verifiable execution artifacts: schema-valid output + hash + signature.`,
    summary: "Receipts are evidence, not logs.",
    references: [
      `${SCHEMA_HOST}/schemas/v1.0.0/_shared/receipt.base.schema.json`,
      `${SCHEMA_HOST}/schemas/v1.0.0/_shared/x402.schema.json`,
    ],
  };
}

function tokenizeWords(s) {
  return (String(s || "").toLowerCase().match(/[a-z0-9]+/g) || []).slice(0, 256);
}

function doAnalyze(body) {
  const inputText = String(body?.input ?? "").trim();
  if (!inputText) throw new Error("analyze.input required");

  const goal = String(body?.goal ?? "").trim() || "analysis";
  const hints = Array.isArray(body?.hints) ? body.hints.map((x) => String(x)) : [];

  const containsUrl = /\bhttps?:\/\/\S+/i.test(inputText);
  const containsEmail = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(inputText);
  const containsJsony = /[{[\]}:]/.test(inputText);
  const containsNumber = /\b\d+(\.\d+)?\b/.test(inputText);

  const labels = [];
  if (containsJsony) labels.push("structured");
  if (containsUrl) labels.push("contains_urls");
  if (containsEmail) labels.push("contains_emails");
  if (containsNumber) labels.push("contains_numbers");

  const words = tokenizeWords(inputText);
  const freq = new Map();
  for (const w of words) freq.set(w, (freq.get(w) || 0) + 1);
  const topTerms = [...freq.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([w]) => w);

  const score =
    0.1 +
    (containsUrl ? 0.15 : 0) +
    (containsEmail ? 0.15 : 0) +
    (containsJsony ? 0.1 : 0) +
    (containsNumber ? 0.05 : 0) +
    Math.min(0.45, inputText.length / 400);

  const insights = [
    `Input length: ${inputText.length} chars; ~${words.length} words.`,
    `Goal: ${goal}`,
    `Hints provided: ${hints.length}.`,
  ];
  if (containsJsony) insights.push("Content appears to include JSON/structured markers.");
  if (containsUrl) insights.push("Content includes URL(s).");
  if (containsEmail) insights.push("Content includes email-like strings.");
  if (containsNumber) insights.push("Content includes numeric values.");
  if (topTerms.length) insights.push(`Top terms: ${topTerms.join(", ")}`);

  const summary = `Deterministic analysis: ${labels.length ? labels.join(", ") : "no_flags"}. Goal="${goal}". Score=${Number(
    Math.min(1, score).toFixed(3)
  )}.`;

  return {
    summary,
    insights,
    labels: labels.length ? labels : [],
    score: Number(Math.min(1, score).toFixed(3)),
  };
}

function doClassify(body) {
  const actor = String(body?.actor ?? "").trim();
  if (!actor) throw new Error("classify.actor required");

  const limits = body?.limits || {};
  const maxLabels = Number(limits?.max_labels || 5);

  const content = String(body?.input?.content ?? "").trim();
  if (!content) throw new Error("classify.input.content required");

  const tax = Array.isArray(body?.input?.taxonomy) ? body.input.taxonomy.map((s) => String(s)) : [];

  const containsUrl = /\bhttps?:\/\/\S+/i.test(content);
  const containsEmail = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(content);
  const looksLikeLogs = /\b(error|exception|stack|trace|cannot|get|post|http\/1\.1)\b/i.test(content);

  const labels = [];
  if (containsUrl) labels.push("contains_urls");
  if (containsEmail) labels.push("contains_emails");
  if (looksLikeLogs) labels.push("code_or_logs");

  const finance = /\b(invoice|payment|usd|\$|card|checkout|charge)\b/i.test(content);
  if (finance) labels.push("finance");

  if (!labels.length) labels.push("general");

  let finalLabels = labels;
  if (tax.length) {
    const lowerTax = new Set(tax.map((t) => t.toLowerCase()));
    const picked = labels.filter((l) => lowerTax.has(l.toLowerCase()));
    if (picked.length) finalLabels = picked;
  }

  finalLabels = finalLabels.slice(0, Math.max(1, Math.min(128, maxLabels)));

  const scores = finalLabels.map((l) => {
    if (l === "contains_urls") return 0.7333333333333333;
    if (l === "contains_emails") return 0.5;
    if (l === "code_or_logs") return 0.4375;
    if (l === "finance") return finance ? 0.6 : 0;
    return 0;
  });

  return { labels: finalLabels, scores, taxonomy: ["root", finalLabels[0]] };
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

// -------------------------
// health/debug
// -------------------------
app.get("/health", (req, res) => res.status(200).send("ok"));

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
    verifier_ens_name: VERIFIER_ENS_NAME,
    ens_pubkey_text_key: ENS_PUBKEY_TEXT_KEY,
    has_rpc: !!ETH_RPC_URL,
    ens_lookup_timeout_ms: ENS_LOOKUP_TIMEOUT_MS,
    schema_cache_ttl_ms: SCHEMA_CACHE_TTL_MS,
    schema_fetch_timeout_ms: SCHEMA_FETCH_TIMEOUT_MS,
    ajv_compile_timeout_ms: AJV_COMPILE_TIMEOUT_MS,
    schema_validate_timeout_ms: SCHEMA_VALIDATE_TIMEOUT_MS,
    schema_host: SCHEMA_HOST,
  });
});

app.get("/debug/enskey", async (req, res) => {
  const refresh = String(req.query.refresh || "") === "1";
  const out = await resolveEnsPubkeyPem({ refresh });
  res.json({
    ok: out.ok,
    pubkey_source: out.ok ? "ens" : null,
    ens_name: VERIFIER_ENS_NAME,
    txt_key: ENS_PUBKEY_TEXT_KEY,
    cache: {
      fetched_at: ensKeyCache.fetched_at ? ensKeyCache.fetched_at.toISOString() : null,
      ttl_ms: ensKeyCache.ttl_ms,
    },
    preview: out.pubkey_pem ? out.pubkey_pem.slice(0, 90) + "..." : null,
    error: out.error || null,
  });
});

app.get("/debug/validators", (req, res) => {
  res.json({
    ok: true,
    cached: [...validatorCache.entries()].map(([id, v]) => ({
      id,
      fetched_at: new Date(v.fetchedAt).toISOString(),
      ttl_ms: SCHEMA_CACHE_TTL_MS,
    })),
    inflight: [...inflightValidators.keys()],
  });
});

// -------------------------
// Verb handler
// -------------------------
async function handleVerb(verb, req, res) {
  if (!enabled(verb)) return res.status(404).json(makeError(404, `Verb not enabled: ${verb}`));
  if (!handlers[verb]) return res.status(404).json(makeError(404, `Verb unsupported: ${verb}`));
  if (!requireBody(req, res)) return;

  const started = Date.now();
  const trace = {
    trace_id: randId("trace_"),
    started_at: nowIso(),
    completed_at: null,
    duration_ms: null,
    provider: process.env.RAILWAY_SERVICE_NAME || "commandlayer-runtime",
  };

  try {
    const x402 = req.body?.x402 || { verb, version: "1.0.0", entry: `x402://${verb}agent.eth/${verb}/v1.0.0` };

    const timeoutMs = Number(req.body?.limits?.timeout_ms || req.body?.limits?.max_latency_ms || 0);
    const work = Promise.resolve(handlers[verb](req.body));
    const result = timeoutMs
      ? await Promise.race([work, new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), timeoutMs))])
      : await work;

    trace.completed_at = nowIso();
    trace.duration_ms = Date.now() - started;

    const receipt = makeReceipt({ x402, trace, result });
    return res.json(receipt);
  } catch (e) {
    trace.completed_at = nowIso();
    trace.duration_ms = Date.now() - started;
    return res.status(500).json(makeError(500, e?.message || "unknown error", { verb, trace }));
  }
}

// Routes: /<verb>/v1.0.0
for (const v of Object.keys(handlers)) {
  app.post(`/${v}/v1.0.0`, (req, res) => handleVerb(v, req, res));
}

// -------------------------
// /verify — ALWAYS fast by default
// - hash + signature always
// - ENS only if ens=1 (hard-timeout, optional fallback)
// - AJV only if schema=1 (hard-timeout; returns schema_valid=false on timeout)
// -------------------------
app.post("/verify", async (req, res) => {
  try {
    const receipt = req.body;
    const proof = receipt?.metadata?.proof;

    if (!proof?.signature_b64 || !proof?.hash_sha256) {
      return res.status(400).json({
        ok: false,
        checks: { schema_valid: false, hash_matches: false, signature_valid: false },
        values: {
          verb: null,
          signer_id: null,
          alg: null,
          canonical: null,
          claimed_hash: null,
          recomputed_hash: null,
          pubkey_source: null,
        },
        errors: { schema_errors: null, signature_error: "missing signature/hash" },
        error: "missing metadata.proof.signature_b64 or hash_sha256",
      });
    }

    const verb = receipt?.x402?.verb ?? null;

    // 1) Recompute hash from canonical unsigned receipt (FAST)
    const unsigned = structuredClone(receipt);
    unsigned.metadata.proof.hash_sha256 = "";
    unsigned.metadata.proof.signature_b64 = "";
    const canonical = stableStringify(unsigned);
    const recomputed = sha256Hex(canonical);
    const hashMatches = recomputed === proof.hash_sha256;

    // 2) Pubkey selection (FAST default: env; ENS only if ens=1)
    const wantEns = String(req.query.ens || "") === "1";
    const refresh = String(req.query.refresh || "") === "1";
    const allowFallback = String(req.query.fallback || "") === "1" || true; // default allow fallback

    let pubPem = null;
    let pubSrc = null;
    let sigErr = null;

    if (wantEns) {
      const ens = await resolveEnsPubkeyPem({ refresh });
      if (ens.ok && ens.pubkey_pem) {
        pubPem = ens.pubkey_pem;
        pubSrc = "ens";
      } else if (allowFallback) {
        pubPem = pemFromB64(PUB_PEM_B64);
        pubSrc = pubPem ? "env-b64" : null;
        sigErr = ens.error || "ens pubkey resolve failed; used env fallback";
      } else {
        pubPem = null;
        pubSrc = null;
        sigErr = ens.error || "ens pubkey resolve failed";
      }
    } else {
      pubPem = pemFromB64(PUB_PEM_B64);
      pubSrc = pubPem ? "env-b64" : null;
      if (!pubPem) sigErr = "missing env public key";
    }

    // 3) Verify signature (FAST)
    let sigOk = false;
    if (pubPem) {
      try {
        sigOk = verifyEd25519Base64(proof.hash_sha256, proof.signature_b64, pubPem);
      } catch (e) {
        sigOk = false;
        sigErr = e?.message || "signature verify error";
      }
    }

    // 4) Schema validation (ONLY if schema=1, HARD TIMEOUT)
    const wantSchema = String(req.query.schema || "") === "1";
    let schemaValid = true;
    let schemaErrors = null;

    if (wantSchema) {
      if (!verb) {
        schemaValid = false;
        schemaErrors = [{ message: "missing receipt.x402.verb" }];
      } else {
        try {
          const validateFn = await withTimeout(
            getReceiptValidator(verb),
            AJV_COMPILE_TIMEOUT_MS,
            "schema validator timeout"
          );

          const ok = await withTimeout(
            Promise.resolve(validateFn(receipt)),
            SCHEMA_VALIDATE_TIMEOUT_MS,
            "schema validate timeout"
          );

          if (!ok) {
            schemaValid = false;
            schemaErrors = (validateFn.errors || []).map((e) => ({
              instancePath: e.instancePath,
              schemaPath: e.schemaPath,
              keyword: e.keyword,
              message: e.message,
              params: e.params,
            }));
          }
        } catch (e) {
          schemaValid = false;
          schemaErrors = [{ message: e?.message || "schema validation failed" }];
        }
      }
    }

    const ok = (wantSchema ? schemaValid : true) && hashMatches && sigOk;

    return res.json({
      ok,
      checks: {
        schema_valid: wantSchema ? schemaValid : true, // if you didn't ask for schema, we don't block the call
        hash_matches: hashMatches,
        signature_valid: sigOk,
      },
      values: {
        verb,
        signer_id: proof.signer_id ?? null,
        alg: proof.alg ?? null,
        canonical: proof.canonical ?? null,
        claimed_hash: proof.hash_sha256 ?? null,
        recomputed_hash: recomputed,
        pubkey_source: pubSrc,
      },
      errors: {
        schema_errors: wantSchema ? schemaErrors : null,
        signature_error: sigErr,
      },
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || "verify failed" });
  }
});

app.listen(PORT, () => {
  console.log(`runtime listening on :${PORT}`);
});
