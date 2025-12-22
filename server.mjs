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

// -------------------------
// Runtime config
// -------------------------
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

// AJV / schema validation
const SCHEMA_CACHE_TTL_MS = Number(process.env.SCHEMA_CACHE_TTL_MS || 600000);
const SCHEMA_FETCH_TIMEOUT_MS = Number(process.env.SCHEMA_FETCH_TIMEOUT_MS || 8000);
const AJV_COMPILE_TIMEOUT_MS = Number(process.env.AJV_COMPILE_TIMEOUT_MS || 12000);

// Normalize schemas to www host (avoids redirect weirdness / ref mismatches)
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

// Stable stringify (deterministic key order)
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
  return crypto.verify(
    null,
    Buffer.from(messageUtf8, "utf8"),
    key,
    Buffer.from(signatureB64, "base64")
  );
}

function makeError(code, message, extra = {}) {
  return { status: "error", code, message, ...extra };
}

// -------------------------
// Fetch helper (Node 22 has global fetch, but keep fallback)
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
// ENS pubkey resolver (ethers)
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

function parseEnsTxtRecords(result) {
  // ethers v6: getText(name, key) returns string or null
  return result || null;
}

async function resolveEnsPubkeyPem({ refresh = false } = {}) {
  if (!ETH_RPC_URL) {
    ensKeyCache.error = "missing ETH_RPC_URL";
    ensKeyCache.pubkey_pem = null;
    ensKeyCache.fetched_at = new Date();
    return { ok: false, source: "ens", pubkey_pem: null, error: ensKeyCache.error };
  }

  if (!refresh && ensCacheFresh() && ensKeyCache.pubkey_pem) {
    return { ok: true, source: "ens", pubkey_pem: ensKeyCache.pubkey_pem, error: null, cache: ensKeyCache };
  }

  try {
    const { ethers } = await import("ethers");
    const provider = new ethers.JsonRpcProvider(ETH_RPC_URL);

    const txt = await provider.getText(VERIFIER_ENS_NAME, ENS_PUBKEY_TEXT_KEY);
    const pem = parseEnsTxtRecords(txt);

    if (!pem || typeof pem !== "string" || !pem.includes("BEGIN PUBLIC KEY")) {
      ensKeyCache.pubkey_pem = null;
      ensKeyCache.error = `TXT missing/invalid: ${VERIFIER_ENS_NAME} ${ENS_PUBKEY_TEXT_KEY}`;
      ensKeyCache.fetched_at = new Date();
      return { ok: false, source: "ens", pubkey_pem: null, error: ensKeyCache.error, cache: ensKeyCache };
    }

    ensKeyCache.pubkey_pem = pem;
    ensKeyCache.error = null;
    ensKeyCache.fetched_at = new Date();
    return { ok: true, source: "ens", pubkey_pem: pem, error: null, cache: ensKeyCache };
  } catch (e) {
    ensKeyCache.pubkey_pem = null;
    ensKeyCache.error = e?.message || "ENS pubkey resolve failed";
    ensKeyCache.fetched_at = new Date();
    return { ok: false, source: "ens", pubkey_pem: null, error: ensKeyCache.error, cache: ensKeyCache };
  }
}

// -------------------------
// AJV schema validation support
// -------------------------
let ajv = null;
let addFormats = null;

async function getAjv() {
  if (ajv) return ajv;
  const AjvMod = await import("ajv");
  const Ajv = AjvMod.default || AjvMod;
  const FormatsMod = await import("ajv-formats");
  addFormats = FormatsMod.default || FormatsMod;

  const instance = new Ajv({
    strict: false,
    allErrors: true,
    loadSchema: async (uri) => fetchSchemaJson(uri),
  });

  addFormats(instance);
  ajv = instance;
  return ajv;
}

function normalizeSchemaUrl(uri) {
  if (!uri || typeof uri !== "string") return uri;

  // If the schema points at commandlayer.org (non-www), rewrite to SCHEMA_HOST (www by default)
  // Preserve path.
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

const schemaFetchCache = new Map(); // uri -> { fetchedAt, json }
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

    if (!resp.ok) {
      throw new Error(`schema fetch failed ${resp.status} for ${norm}`);
    }

    const json = await resp.json();

    // IMPORTANT: normalize $id + $ref in the loaded schema so AJV stays consistent.
    // We cannot rewrite every nested ref safely, but we can normalize common direct strings.
    const rewritten = rewriteSchemaRefsToWww(json);

    schemaFetchCache.set(norm, { fetchedAt: Date.now(), json: rewritten });
    return rewritten;
  } finally {
    clearTimeout(t);
  }
}

function rewriteSchemaRefsToWww(schema) {
  // Deep walk and normalize string values of "$id" and "$ref" only.
  // Keeps schemas consistent so AJV doesn't mix hosts.
  const walk = (v) => {
    if (v === null || typeof v !== "object") return v;
    if (Array.isArray(v)) return v.map(walk);

    const out = {};
    for (const [k, val] of Object.entries(v)) {
      if ((k === "$id" || k === "$ref") && typeof val === "string") out[k] = normalizeSchemaUrl(val);
      else out[k] = walk(val);
    }
    return out;
  };
  return walk(schema);
}

function receiptSchemaIdForVerb(verb) {
  // receipts live at: /schemas/v1.0.0/commons/<verb>/receipts/<verb>.receipt.schema.json
  const v = String(verb || "").trim();
  return `${SCHEMA_HOST}/schemas/v1.0.0/commons/${v}/receipts/${v}.receipt.schema.json`;
}

const validatorCache = new Map(); // schemaId -> { validate, fetchedAt }
const inflightValidators = new Map(); // schemaId -> Promise<validateFn>

async function getReceiptValidator(verb) {
  const schemaId = receiptSchemaIdForVerb(verb);
  const now = Date.now();

  const cached = validatorCache.get(schemaId);
  if (cached && now - cached.fetchedAt < SCHEMA_CACHE_TTL_MS) return cached.validate;

  if (inflightValidators.has(schemaId)) return await inflightValidators.get(schemaId);

  const p = (async () => {
    const ajvInst = await getAjv();
    const compilePromise = ajvInst.compileAsync({ $ref: schemaId });

    const validate = await Promise.race([
      compilePromise,
      new Promise((_, rej) =>
        setTimeout(
          () => rej(new Error(`ajv compile timeout after ${AJV_COMPILE_TIMEOUT_MS}ms for ${schemaId}`)),
          AJV_COMPILE_TIMEOUT_MS
        )
      ),
    ]);

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
// Verb handlers (deterministic reference implementations)
// -------------------------
async function doFetch(body) {
  const url = body?.source || body?.input?.source || body?.input?.url;
  if (!url || typeof url !== "string") throw new Error("fetch requires source (url)");
  const fetchFn = await getFetch();
  const resp = await fetchFn(url, { method: "GET" });
  const text = await resp.text();
  const preview = text.slice(0, 2000);
  return {
    items: [
      {
        source: url,
        query: body?.query ?? null,
        include_metadata: body?.include_metadata ?? null,
        ok: resp.ok,
        http_status: resp.status,
        headers: Object.fromEntries(resp.headers.entries?.() ?? []),
        body_preview: preview,
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
    "Receipts can be independently verified (schema + hash + signature).",
  ];

  const description =
    detail === "short"
      ? `**${subject}** is a semantic contract for agents: published verbs + schemas + verifiable receipts.`
      : `**${subject}** standardizes agent verbs using strict JSON Schemas (requests + receipts) and cryptographically verifiable receipts so different runtimes can execute the same intent without semantic drift.`;

  return {
    description,
    bullets,
    properties: { verb: "describe", version: "1.0.0", audience, detail_level: detail },
  };
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

  return {
    summary,
    format: format === "markdown" ? "markdown" : "text",
    compression_ratio: cr,
    source_hash: srcHash,
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

  return {
    converted_content: converted,
    source_format: src,
    target_format: tgt,
    lossy,
    warnings,
  };
}

function doExplain(body) {
  const input = body?.input || {};
  const subject = String(input.subject || "").trim();
  if (!subject) throw new Error("explain.input.subject required");

  const audience = input.audience || "general";
  const style = input.style || "plain";
  const detail = input.detail_level || "short";

  const core = [
    `A receipt is verifiable evidence that an execution happened under a verb + schema version.`,
    `It includes structured output plus a hash and signature.`,
    `Because schemas are public, anyone can validate receipts later.`,
  ];

  const steps = [
    "1) Validate request against request schema.",
    "2) Execute the verb and produce structured output.",
    "3) Build receipt (base fields + result).",
    "4) Canonicalize + hash unsigned receipt.",
    "5) Sign hash with runtime signer key.",
    "6) Verify schema + hash + signature (optionally resolve pubkey from ENS).",
  ];

  let explanation = "";
  if (audience === "novice") {
    explanation = `**${subject}** are like tamper-proof receipts for agent actions.\n\n` + core.map((s) => `- ${s}`).join("\n");
  } else {
    explanation =
      `**${subject}** are cryptographically verifiable execution artifacts that bind intent (verb+version), semantics (schema), and output.\n\n` +
      core.map((s) => `- ${s}`).join("\n");
  }

  const result = { explanation };
  if (detail !== "short" || style === "step-by-step") result.steps = steps;

  result.summary = "Receipts are evidence, not logs: validate schema + hash + signature.";
  result.references = [
    `${SCHEMA_HOST}/schemas/v1.0.0/_shared/receipt.base.schema.json`,
    `${SCHEMA_HOST}/schemas/v1.0.0/_shared/x402.schema.json`,
  ];

  return result;
}

function tokenizeWords(s) {
  return (String(s || "").toLowerCase().match(/[a-z0-9]+/g) || []).slice(0, 256);
}

function doAnalyze(body) {
  // Matches your analyze.request schema shape: input is a string (not input.content)
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
  const topTerms = [...freq.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([w]) => w);

  const lines = inputText.split(/\r?\n/).filter((l) => l.trim() !== "");
  const score =
    0.1 +
    (containsUrl ? 0.15 : 0) +
    (containsEmail ? 0.15 : 0) +
    (containsJsony ? 0.1 : 0) +
    (containsNumber ? 0.05 : 0) +
    Math.min(0.45, inputText.length / 400);

  const insights = [
    `Input length: ${inputText.length} chars; ~${words.length} words; ${lines.length} non-empty lines.`,
    `Goal: ${goal}`,
    `Hints provided: ${hints.length}.`,
  ];
  if (containsJsony) insights.push("Content appears to include JSON/structured data markers.");
  if (containsUrl) insights.push("Content includes URL(s).");
  if (containsEmail) insights.push("Content includes email-like strings.");
  if (containsNumber) insights.push("Content includes numeric values.");
  if (topTerms.length) insights.push(`Top terms: ${topTerms.join(", ")}`);

  const summary = `Deterministic analysis: ${labels.length ? labels.join(", ") : "no_flags"}. Goal="${goal}". Score=${Number(score.toFixed(3))}.`;

  return {
    summary,
    insights,
    labels: labels.length ? labels : undefined,
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

  // Lightweight “finance” heuristic (example)
  const finance = /\b(invoice|payment|usd|\$|card|checkout|charge)\b/i.test(content);
  if (finance) labels.push("finance");

  if (!labels.length) labels.push("general");

  // If caller provided taxonomy candidates, prefer intersection
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

  const taxonomyPath = ["root", finalLabels[0]];

  return {
    labels: finalLabels,
    scores,
    taxonomy: taxonomyPath,
  };
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
// Health + debug
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
    schema_cache_ttl_ms: SCHEMA_CACHE_TTL_MS,
    schema_fetch_timeout_ms: SCHEMA_FETCH_TIMEOUT_MS,
    ajv_compile_timeout_ms: AJV_COMPILE_TIMEOUT_MS,
    schema_host: SCHEMA_HOST,
  });
});

app.get("/debug/enskey", async (req, res) => {
  const refresh = String(req.query.refresh || "") === "1";
  const out = await resolveEnsPubkeyPem({ refresh });
  const preview = out.pubkey_pem
    ? out.pubkey_pem.slice(0, 80) + (out.pubkey_pem.length > 80 ? "..." : "")
    : null;

  res.json({
    ok: out.ok,
    pubkey_source: out.ok ? "ens" : null,
    ens_name: VERIFIER_ENS_NAME,
    txt_key: ENS_PUBKEY_TEXT_KEY,
    cache: {
      fetched_at: ensKeyCache.fetched_at ? ensKeyCache.fetched_at.toISOString() : null,
      ttl_ms: ensKeyCache.ttl_ms,
    },
    preview,
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
    ajv_compile_timeout_ms: AJV_COMPILE_TIMEOUT_MS,
    schema_fetch_timeout_ms: SCHEMA_FETCH_TIMEOUT_MS,
  });
});

// -------------------------
// Verb endpoint handler
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

    // enforce a hard timeout if caller asks
    const timeoutMs = Number(req.body?.limits?.timeout_ms || req.body?.limits?.max_latency_ms || 0);
    const work = Promise.resolve(handlers[verb](req.body));
    const result = timeoutMs
      ? await Promise.race([
          work,
          new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), timeoutMs)),
        ])
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
// /verify — schema + hash + signature (+ ENS pubkey if ens=1)
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

    // 1) Schema validation (AJV)
    let schemaValid = true;
    let schemaErrors = null;

    const verb = receipt?.x402?.verb || null;
    if (!verb) {
      schemaValid = false;
      schemaErrors = [{ message: "missing receipt.x402.verb" }];
    } else {
      try {
        const validate = await getReceiptValidator(verb);
        const ok = validate(receipt);
        if (!ok) {
          schemaValid = false;
          schemaErrors = (validate.errors || []).map((e) => ({
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

    // 2) Recompute hash from canonical unsigned receipt
    const unsigned = structuredClone(receipt);
    unsigned.metadata.proof.hash_sha256 = "";
    unsigned.metadata.proof.signature_b64 = "";
    const canonical = stableStringify(unsigned);
    const recomputed = sha256Hex(canonical);

    const hashMatches = recomputed === proof.hash_sha256;

    // 3) Choose pubkey source
    const wantEns = String(req.query.ens || "") === "1";
    const refresh = String(req.query.refresh || "") === "1";
    const allowFallback = String(req.query.fallback || "") === "1";

    let pubPem = null;
    let pubSrc = null;
    let sigOk = false;
    let sigErr = null;

    if (wantEns) {
      const ens = await resolveEnsPubkeyPem({ refresh });
      if (ens.ok && ens.pubkey_pem) {
        pubPem = ens.pubkey_pem;
        pubSrc = "ens";
      } else if (allowFallback) {
        pubPem = pemFromB64(PUB_PEM_B64);
        pubSrc = pubPem ? "env-b64" : null;
        if (!pubPem) sigErr = "no pubkey available (ens failed + env missing)";
      } else {
        return res.status(400).json({
          ok: false,
          checks: { schema_valid: schemaValid, hash_matches: hashMatches, signature_valid: false },
          values: {
            verb,
            signer_id: proof.signer_id ?? null,
            alg: proof.alg ?? null,
            canonical: proof.canonical ?? null,
            claimed_hash: proof.hash_sha256 ?? null,
            recomputed_hash: recomputed,
            pubkey_source: null,
          },
          errors: { schema_errors: schemaErrors, signature_error: ens.error || "ENS pubkey resolve failed" },
          error: "ens pubkey resolve failed (pass fallback=1 to allow env)",
        });
      }
    } else {
      pubPem = pemFromB64(PUB_PEM_B64);
      pubSrc = pubPem ? "env-b64" : null;
      if (!pubPem) sigErr = "missing env public key";
    }

    // 4) Verify signature (if we have a pubkey)
    if (pubPem) {
      try {
        sigOk = verifyEd25519Base64(proof.hash_sha256, proof.signature_b64, pubPem);
      } catch (e) {
        sigOk = false;
        sigErr = e?.message || "signature verify error";
      }
    } else {
      sigOk = false;
    }

    const ok = schemaValid && hashMatches && sigOk;

    return res.json({
      ok,
      checks: {
        schema_valid: schemaValid,
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
        schema_errors: schemaErrors,
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
