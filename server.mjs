// server.mjs
import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { JsonRpcProvider } from "ethers";

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

const ENABLED_VERBS = (process.env.ENABLED_VERBS || "fetch")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const SIGNER_ID =
  process.env.RECEIPT_SIGNER_ID || process.env.ENS_NAME || "runtime";

const PRIV_PEM_B64 = process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64 || "";
const PUB_PEM_B64 = process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "";

const VERIFIER_ENS_NAME =
  process.env.VERIFIER_ENS_NAME || process.env.ENS_NAME || SIGNER_ID;

const ENS_PUBKEY_TEXT_KEY =
  process.env.ENS_PUBKEY_TEXT_KEY || "cl.receipt.pubkey.pem";

const ETH_RPC_URL = process.env.ETH_RPC_URL || "";

// Use the canonical host that avoids your 307 issues
const SCHEMA_HOST = process.env.SCHEMA_HOST || "https://www.commandlayer.org";

const ENS_CACHE_TTL_MS = Number(process.env.ENS_CACHE_TTL_MS || 600_000);
const SCHEMA_CACHE_TTL_MS = Number(process.env.SCHEMA_CACHE_TTL_MS || 600_000);

// Tight timeouts so /verify never hangs
const SCHEMA_FETCH_TIMEOUT_MS = Number(
  process.env.SCHEMA_FETCH_TIMEOUT_MS || 8000
);
const AJV_COMPILE_TIMEOUT_MS = Number(
  process.env.AJV_COMPILE_TIMEOUT_MS || 12000
);

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

// Handle ENS TXT values that contain literal "\n"
function normalizePem(maybePem) {
  if (!maybePem) return null;
  let s = String(maybePem).trim();
  s = s.replace(/\\n/g, "\n"); // convert literal \n into real newlines
  // strip accidental wrapping quotes
  if (
    (s.startsWith('"') && s.endsWith('"')) ||
    (s.startsWith("'") && s.endsWith("'"))
  ) {
    s = s.slice(1, -1).trim();
  }
  if (!s.includes("BEGIN PUBLIC KEY")) return null;
  return s;
}

function signEd25519Base64(messageUtf8) {
  const pem = pemFromB64(PRIV_PEM_B64);
  if (!pem) throw new Error("Missing RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64");
  const key = crypto.createPrivateKey(pem);
  const sig = crypto.sign(null, Buffer.from(messageUtf8, "utf8"), key); // Ed25519 -> null
  return sig.toString("base64");
}

function verifyEd25519Base64(messageUtf8, signatureB64, pubPem) {
  const normalized = normalizePem(pubPem) || pubPem;
  const key = crypto.createPublicKey(normalized);
  return crypto.verify(
    null,
    Buffer.from(messageUtf8, "utf8"),
    key,
    Buffer.from(signatureB64, "base64")
  );
}

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

function makeError(code, message, extra = {}) {
  return { status: "error", code, message, ...extra };
}

// -------------------- ENS PUBKEY RESOLUTION (ethers v6 correct)

const ensCache = {
  fetched_at: null,
  ttl_ms: ENS_CACHE_TTL_MS,
  value_pem: null,
  error: null,
};

async function resolveEnsPubkeyPem({ refresh = false } = {}) {
  const now = Date.now();
  if (
    !refresh &&
    ensCache.fetched_at &&
    now - ensCache.fetched_at < ENS_CACHE_TTL_MS
  ) {
    return {
      ok: !!ensCache.value_pem,
      pem: ensCache.value_pem,
      source: "ens-cache",
      error: ensCache.error,
      fetched_at: ensCache.fetched_at,
    };
  }

  if (!ETH_RPC_URL) {
    ensCache.fetched_at = now;
    ensCache.value_pem = null;
    ensCache.error = "Missing ETH_RPC_URL";
    return { ok: false, pem: null, source: "ens", error: ensCache.error };
  }

  try {
    const provider = new JsonRpcProvider(ETH_RPC_URL);

    const resolver = await provider.getResolver(VERIFIER_ENS_NAME);
    if (!resolver) throw new Error(`No ENS resolver for ${VERIFIER_ENS_NAME}`);

    const txt = await resolver.getText(ENS_PUBKEY_TEXT_KEY);
    const pem = normalizePem(txt);

    ensCache.fetched_at = now;
    ensCache.value_pem = pem;
    ensCache.error = pem ? null : `TXT missing/invalid PEM for ${ENS_PUBKEY_TEXT_KEY}`;

    return { ok: !!pem, pem, source: "ens", error: ensCache.error, fetched_at: now };
  } catch (e) {
    ensCache.fetched_at = now;
    ensCache.value_pem = null;
    ensCache.error = e?.message || "ENS lookup failed";
    return { ok: false, pem: null, source: "ens", error: ensCache.error, fetched_at: now };
  }
}

// -------------------- AJV (optional verify-time schema validation)

const schemaCache = new Map(); // url -> { fetched_at, json }
const validatorCache = new Map(); // verb -> { compiled_at, validateFn }
const inflightCompile = new Map(); // verb -> Promise

function withTimeout(promise, ms, label = "timeout") {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), ms);
  const raced = Promise.race([
    promise(controller.signal),
    new Promise((_, rej) => setTimeout(() => rej(new Error(label)), ms)),
  ]);
  raced.finally(() => clearTimeout(t));
  return raced;
}

async function fetchJson(url) {
  const now = Date.now();
  const cached = schemaCache.get(url);
  if (cached && now - cached.fetched_at < SCHEMA_CACHE_TTL_MS) return cached.json;

  const json = await withTimeout(
    async (signal) => {
      const r = await fetch(url, { method: "GET", signal });
      if (!r.ok) throw new Error(`schema fetch failed ${r.status} for ${url}`);
      return r.json();
    },
    SCHEMA_FETCH_TIMEOUT_MS,
    `schema_fetch_timeout ${SCHEMA_FETCH_TIMEOUT_MS}ms`
  );

  schemaCache.set(url, { fetched_at: now, json });
  return json;
}

// AJV instance with remote ref loading
const ajv = new Ajv({
  strict: false,
  allErrors: true,
  loadSchema: async (uri) => {
    // Normalize any non-www host to www host (your redirects were biting you)
    const fixed = String(uri).replace(/^https:\/\/commandlayer\.org\//, `${SCHEMA_HOST}/`);
    return fetchJson(fixed);
  },
});
addFormats(ajv);

function receiptSchemaUrlForVerb(verb) {
  // commons only for now
  return `${SCHEMA_HOST}/schemas/v1.0.0/commons/${verb}/receipts/${verb}.receipt.schema.json`;
}

async function getReceiptValidatorForVerb(verb) {
  const cached = validatorCache.get(verb);
  if (cached) return cached.validateFn;

  if (inflightCompile.has(verb)) return inflightCompile.get(verb);

  const p = (async () => {
    const schemaUrl = receiptSchemaUrlForVerb(verb);

    const validateFn = await withTimeout(
      async () => {
        // compileAsync will pull remote refs via loadSchema
        return ajv.compileAsync({ $ref: schemaUrl });
      },
      AJV_COMPILE_TIMEOUT_MS,
      `ajv_compile_timeout ${AJV_COMPILE_TIMEOUT_MS}ms`
    );

    validatorCache.set(verb, { compiled_at: Date.now(), validateFn });
    inflightCompile.delete(verb);
    return validateFn;
  })().catch((e) => {
    inflightCompile.delete(verb);
    throw e;
  });

  inflightCompile.set(verb, p);
  return p;
}

// ---- health/debug
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
    schema_host: SCHEMA_HOST,
    schema_cache_ttl_ms: SCHEMA_CACHE_TTL_MS,
    schema_fetch_timeout_ms: SCHEMA_FETCH_TIMEOUT_MS,
    ajv_compile_timeout_ms: AJV_COMPILE_TIMEOUT_MS,
  });
});

app.get("/debug/enskey", async (req, res) => {
  const refresh = String(req.query.refresh || "") === "1";
  const out = await resolveEnsPubkeyPem({ refresh });
  const preview = out.pem ? out.pem.slice(0, 80) + "..." : null;
  res.json({
    ok: true,
    pubkey_source: out.source,
    ens_name: VERIFIER_ENS_NAME,
    txt_key: ENS_PUBKEY_TEXT_KEY,
    cache: { fetched_at: out.fetched_at ? new Date(out.fetched_at).toISOString() : null, ttl_ms: ENS_CACHE_TTL_MS },
    preview,
    error: out.error || null,
  });
});

app.get("/debug/validators", (req, res) => {
  const cached = [];
  for (const [verb, v] of validatorCache.entries()) {
    cached.push({ verb, compiled_at: new Date(v.compiled_at).toISOString() });
  }
  res.json({ ok: true, cached });
});

// ---- deterministic verb implementations

async function doFetch(body) {
  const url = body?.source || body?.input?.source || body?.input?.url;
  if (!url || typeof url !== "string") throw new Error("fetch requires source (url)");
  const resp = await fetch(url, { method: "GET" });
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
        headers: Object.fromEntries(resp.headers.entries()),
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
    "Receipts can be independently verified (hash + signature).",
  ];

  const description =
    detail === "short"
      ? `**${subject}** is a concept: a standard “API meaning” contract agents can call using published schemas and receipts.`
      : `**${subject}** is a semantic contract for agents. It standardizes verbs, strict JSON Schemas (requests + receipts), and verifiable receipts so different runtimes can execute the same intent without semantic drift.`;

  return {
    description,
    bullets,
    properties: {
      verb: "describe",
      version: "1.0.0",
      audience,
      detail_level: detail,
    },
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
    formatted =
      `| key | value |\n|---|---|\n` +
      rows.map(([k, v]) => `| ${k} | ${v} |`).join("\n");
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
    explanation =
      `**${subject}** are like “tamper-proof receipts” for agent actions.\n\n` +
      core.map((s) => `- ${s}`).join("\n");
  } else {
    explanation =
      `**${subject}** are cryptographically verifiable execution artifacts that bind intent (verb+version), semantics (schema), and output into a signed proof.\n\n` +
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

function doAnalyze(body) {
  const inputText = String(body?.input ?? "").trim();
  if (!inputText) throw new Error("analyze.input (string) required");
  const goal = String(body?.goal ?? "").trim();

  const lines = inputText.split(/\r?\n/).filter((l) => l.trim() !== "");
  const words = inputText.split(/\s+/).filter(Boolean);

  const hasUrl = /https?:\/\/\S+/i.test(inputText);
  const hasEmail = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(inputText);
  const hasNumber = /\b\d+(\.\d+)?\b/.test(inputText);
  const looksJson = /[{[\]]/.test(inputText);

  const labels = [];
  if (looksJson) labels.push("structured");
  if (hasUrl) labels.push("contains_urls");
  if (hasEmail) labels.push("contains_emails");

  let score = 0;
  if (hasUrl) score += 0.2;
  if (hasEmail) score += 0.25;
  if (looksJson) score += 0.1;
  if (hasNumber) score += 0.05;
  score = Math.max(0, Math.min(1, Number(score.toFixed(3))));

  const topTerms = words
    .slice(0, 32)
    .map((w) => w.toLowerCase().replace(/[^\w.@:/-]+/g, ""))
    .filter(Boolean);

  const insights = [
    `Input length: ${inputText.length} chars; ~${words.length} words; ${lines.length} non-empty lines.`,
    goal ? `Goal: ${goal}` : "Goal: (none)",
    `Hints provided: ${Array.isArray(body?.hints) ? body.hints.length : 0}.`,
    looksJson ? "Content appears to include JSON/structured data markers." : "No strong structured-data markers detected.",
    hasUrl ? "Content includes URL(s)." : "No URL detected.",
    hasEmail ? "Content includes email-like strings." : "No email-like strings detected.",
    hasNumber ? "Content includes numeric values." : "No numeric values detected.",
    `Top terms: ${topTerms.slice(0, 12).join(", ") || "(none)"}`,
  ];

  const summary = `Deterministic analysis: ${labels.join(", ") || "no_flags"}. ${goal ? `Goal="${goal}". ` : ""}Score=${score}.`;

  return { summary, insights, labels, score };
}

function doClassify(body) {
  const input = body?.input || {};
  const content = String(input.content ?? "").trim();
  if (!content) throw new Error("classify.input.content required");

  const maxLabels = Number(body?.limits?.max_labels ?? 5);
  const hasUrl = /https?:\/\/\S+/i.test(content);
  const hasEmail = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(content);
  const looksCode = /(error:|stack|trace|cannot get|exception)/i.test(content);

  const labels = [];
  const scores = [];

  const push = (label, score) => {
    if (labels.length >= maxLabels) return;
    labels.push(label);
    scores.push(Number(score.toFixed(6)));
  };

  if (hasUrl) push("contains_urls", 0.7333333333333333);
  if (hasEmail) push("contains_emails", 0.5);
  if (looksCode) push("code_or_logs", 0.4375);

  // keep deterministic filler
  push("general", labels.length ? 0 : 0.2);

  const taxonomy = ["root", labels[0] || "general"];
  return { labels, scores, taxonomy };
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

async function handleVerb(verb, req, res) {
  if (!enabled(verb)) return res.status(404).json(makeError(404, `Verb not enabled: ${verb}`));
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

// Verify endpoint: hash + signature, optionally ENS pubkey, optionally schema validation
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

    // recompute hash from canonical unsigned receipt
    const unsigned = structuredClone(receipt);
    unsigned.metadata.proof.hash_sha256 = "";
    unsigned.metadata.proof.signature_b64 = "";
    const canonical = stableStringify(unsigned);
    const recomputed = sha256Hex(canonical);
    const hashMatches = recomputed === proof.hash_sha256;

    // pubkey selection
    const wantEns = String(req.query.ens || "") === "1";
    const refreshEns = String(req.query.refresh || "") === "1";

    let pubPem = null;
    let pubSrc = null;
    let sigOk = false;
    let signatureError = null;

    try {
      if (wantEns) {
        const out = await resolveEnsPubkeyPem({ refresh: refreshEns });
        if (out.pem) {
          pubPem = out.pem;
          pubSrc = "ens";
        } else {
          // ENS requested but missing -> treat as failure
          pubPem = null;
          pubSrc = "ens";
          signatureError = out.error || "ENS pubkey missing";
        }
      } else {
        pubPem = pemFromB64(PUB_PEM_B64);
        pubSrc = pubPem ? "env-b64" : null;
      }

      if (pubPem) {
        sigOk = verifyEd25519Base64(proof.hash_sha256, proof.signature_b64, pubPem);
      } else {
        sigOk = false;
      }
    } catch (e) {
      sigOk = false;
      signatureError = e?.message || "signature verify failed";
    }

    // schema validation (OFF by default)
    const wantSchema = String(req.query.schema || "") === "1";
    let schemaValid = true;
    let schemaErrors = null;

    if (wantSchema) {
      try {
        const verb = String(receipt?.x402?.verb || "").trim();
        if (!verb) throw new Error("missing x402.verb");
        const validate = await getReceiptValidatorForVerb(verb);
        const ok = validate(receipt);
        schemaValid = !!ok;
        schemaErrors = ok ? null : (validate.errors || []).map((e) => ({
          instancePath: e.instancePath,
          schemaPath: e.schemaPath,
          keyword: e.keyword,
          message: e.message,
          params: e.params,
        }));
      } catch (e) {
        schemaValid = false;
        schemaErrors = [{ message: e?.message || "schema validation failed" }];
      }
    }

    return res.json({
      ok: hashMatches && sigOk && schemaValid,
      checks: {
        schema_valid: schemaValid,
        hash_matches: hashMatches,
        signature_valid: sigOk,
      },
      values: {
        verb: receipt?.x402?.verb ?? null,
        signer_id: proof.signer_id ?? null,
        alg: proof.alg ?? null,
        canonical: proof.canonical ?? null,
        claimed_hash: proof.hash_sha256 ?? null,
        recomputed_hash: recomputed,
        pubkey_source: pubSrc,
      },
      errors: {
        schema_errors: schemaErrors,
        signature_error: signatureError,
      },
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: e?.message || "verify failed" });
  }
});

app.listen(PORT, () => {
  console.log(`runtime listening on :${PORT}`);
});
