// server.mjs
import express from "express";
import crypto from "crypto";
import Ajv from "ajv";
import addFormats from "ajv-formats";

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

// ---- ENS verifier pubkey resolution (requires `ethers`)
const VERIFIER_ENS_NAME = process.env.VERIFIER_ENS_NAME || SIGNER_ID;
const ENS_PUBKEY_TEXT_KEY =
  process.env.ENS_PUBKEY_TEXT_KEY || "cl.receipt.pubkey.pem";
const ENS_CACHE_TTL_MS = Number(process.env.ENS_CACHE_TTL_MS || 10 * 60 * 1000);

const ensCache = {
  fetched_at: 0,
  ens_name: VERIFIER_ENS_NAME,
  key: ENS_PUBKEY_TEXT_KEY,
  pubkey_pem: null,
  error: null,
};

// ---- AJV schema validation (cached, compiled)
const SCHEMA_CACHE_TTL_MS = Number(
  process.env.SCHEMA_CACHE_TTL_MS || 10 * 60 * 1000
);

function normalizeSchemaUrl(uri) {
  if (!uri || typeof uri !== "string") return uri;
  // Avoid Vercel 307 redirect from commandlayer.org -> www.commandlayer.org
  return uri.replace(
    "https://commandlayer.org/",
    "https://www.commandlayer.org/"
  );
}

const ajv = new Ajv({
  strict: true,
  allErrors: true,
  loadSchema: async (uri) => {
    const fixed = normalizeSchemaUrl(uri);

    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000); // hard timeout: 8s
    try {
      const r = await fetch(fixed, {
        method: "GET",
        redirect: "follow",
        signal: ctrl.signal,
        headers: { accept: "application/json" },
      });

      if (!r.ok) throw new Error(`schema fetch failed ${r.status} for ${fixed}`);

      const text = await r.text();

      // Defensive: reject HTML/"Redirecting..." bodies that would break JSON.parse
      const trimmed = text.trim();
      if (
        trimmed.startsWith("Redirecting") ||
        trimmed.startsWith("<!DOCTYPE html") ||
        trimmed.startsWith("<html")
      ) {
        throw new Error(`schema fetch returned non-JSON for ${fixed}`);
      }

      return JSON.parse(text);
    } catch (e) {
      if (e?.name === "AbortError")
        throw new Error(`schema fetch timeout for ${fixed}`);
      throw e;
    } finally {
      clearTimeout(t);
    }
  },
});
addFormats(ajv);

const validatorCache = new Map(); // schemaId -> { validate, fetchedAt }

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

function normalizePemFromTxt(txt) {
  if (!txt || typeof txt !== "string") return null;
  const pem = txt.includes("\\n") ? txt.replace(/\\n/g, "\n") : txt;
  if (!pem.includes("BEGIN PUBLIC KEY") || !pem.includes("END PUBLIC KEY"))
    return null;
  return pem.trim();
}

async function resolveEnsPubkeyPem({ refresh = false } = {}) {
  if (!process.env.ETH_RPC_URL) {
    ensCache.error = "Missing ETH_RPC_URL";
    return { ok: false, source: null, pubkey_pem: null, error: ensCache.error };
  }

  const now = Date.now();
  const expired = now - ensCache.fetched_at > ENS_CACHE_TTL_MS;
  if (!refresh && ensCache.pubkey_pem && !expired) {
    return {
      ok: true,
      source: "ens-cache",
      pubkey_pem: ensCache.pubkey_pem,
      error: null,
    };
  }

  try {
    const { ethers } = await import("ethers");
    const provider = new ethers.JsonRpcProvider(process.env.ETH_RPC_URL);

    const resolver = await provider.getResolver(VERIFIER_ENS_NAME);
    if (!resolver)
      throw new Error(`No resolver for ENS name: ${VERIFIER_ENS_NAME}`);

    const raw = await resolver.getText(ENS_PUBKEY_TEXT_KEY);
    const pem = normalizePemFromTxt(raw);
    if (!pem) throw new Error(`TXT key missing/invalid: ${ENS_PUBKEY_TEXT_KEY}`);

    ensCache.fetched_at = now;
    ensCache.ens_name = VERIFIER_ENS_NAME;
    ensCache.key = ENS_PUBKEY_TEXT_KEY;
    ensCache.pubkey_pem = pem;
    ensCache.error = null;

    return { ok: true, source: "ens", pubkey_pem: pem, error: null };
  } catch (e) {
    ensCache.fetched_at = now;
    ensCache.ens_name = VERIFIER_ENS_NAME;
    ensCache.key = ENS_PUBKEY_TEXT_KEY;
    ensCache.pubkey_pem = null;
    ensCache.error = e?.message || "ENS resolution failed";

    return { ok: false, source: null, pubkey_pem: null, error: ensCache.error };
  }
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

// ---- AJV helpers
function receiptSchemaIdForVerb(verb) {
  // Use www to avoid Vercel redirect chains
  return `https://www.commandlayer.org/schemas/v1.0.0/commons/${verb}/receipts/${verb}.receipt.schema.json`;
}

async function getReceiptValidator(verb) {
  const schemaId = receiptSchemaIdForVerb(verb);
  const now = Date.now();
  const cached = validatorCache.get(schemaId);
  if (cached && now - cached.fetchedAt < SCHEMA_CACHE_TTL_MS) return cached.validate;

  const validate = await ajv.compileAsync({ $ref: schemaId });

  validatorCache.set(schemaId, { validate, fetchedAt: now });
  return validate;
}

function ajvErrorsToStrings(errors) {
  if (!Array.isArray(errors) || !errors.length) return null;
  return errors.slice(0, 50).map((e) => {
    const path = e.instancePath || "(root)";
    const msg = e.message || "schema error";
    const kw = e.keyword ? ` [${e.keyword}]` : "";
    return `${path}: ${msg}${kw}`;
  });
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
    has_rpc: !!process.env.ETH_RPC_URL,
    schema_cache_ttl_ms: SCHEMA_CACHE_TTL_MS,
  });
});

app.get("/debug/enskey", async (req, res) => {
  const refresh = String(req.query.refresh || "") === "1";
  const r = await resolveEnsPubkeyPem({ refresh });

  res.json({
    ok: r.ok,
    pubkey_source: r.ok ? r.source : null,
    ens_name: VERIFIER_ENS_NAME,
    txt_key: ENS_PUBKEY_TEXT_KEY,
    cache: {
      fetched_at: ensCache.fetched_at
        ? new Date(ensCache.fetched_at).toISOString()
        : null,
      ttl_ms: ENS_CACHE_TTL_MS,
    },
    preview: r.pubkey_pem ? r.pubkey_pem.slice(0, 80) + "..." : null,
    error: r.error || null,
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
  });
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
    const lines = content
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
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
    if (op === "normalize_newlines")
      content = content.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
    if (op === "collapse_whitespace") content = content.replace(/[ \t]+/g, " ");
    if (op === "trim") content = content.trim();
    if (op === "remove_empty_lines")
      content = content
        .split("\n")
        .filter((l) => l.trim() !== "")
        .join("\n");
    if (op === "redact_emails") {
      const before = content;
      content = content.replace(
        /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
        "[redacted-email]"
      );
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
    } catch (e) {
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
      if (!Object.keys(parsed).length)
        warnings.push("Could not confidently parse content.");
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
    const picks = sentences
      .slice(0, 3)
      .map((s) => s.replace(/\s+/g, " ").trim());
    summary = picks.join(" ");
  } else {
    summary = sentences.slice(0, 2).join(" ").trim();
  }
  if (!summary) summary = content.slice(0, 400).trim();

  const srcHash = sha256Hex(content);
  const cr = summary.length
    ? Number((content.length / summary.length).toFixed(3))
    : 0;

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
    warnings.push(
      `No deterministic converter for ${src}->${tgt}; echoing content.`
    );
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
  result.summary =
    "Receipts are evidence, not logs: validate schema + hash + signature.";
  result.references = [
    "https://www.commandlayer.org/schemas/v1.0.0/_shared/receipt.base.schema.json",
    "https://www.commandlayer.org/schemas/v1.0.0/_shared/x402.schema.json",
  ];

  return result;
}

// ---- analyze / classify helpers
function clamp01(n) {
  if (Number.isNaN(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

function uniq(arr) {
  return [...new Set(arr)];
}

function topNByCount(counts, n) {
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([k]) => k);
}

// ---- analyze (schema expects body.input string, not body.input.content)
function doAnalyze(body) {
  const inputText = String(body?.input ?? "").trim();
  if (!inputText) throw new Error("analyze.input required (string)");

  const goal = body?.goal ? String(body.goal).trim() : "";
  const hints = Array.isArray(body?.hints)
    ? body.hints.map((s) => String(s).trim()).filter(Boolean)
    : [];

  const len = inputText.length;
  const lines = inputText.split(/\r?\n/);
  const nonEmptyLines = lines.filter((l) => l.trim() !== "");
  const words = inputText.split(/\s+/).filter(Boolean);

  const hasJsonLike = /[{[]/.test(inputText) && /[}\]]/.test(inputText);
  const hasUrl = /\bhttps?:\/\/\S+/i.test(inputText);
  const hasEmail = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(inputText);
  const hasNumbers = /\d/.test(inputText);
  const hasCodeFence = /```/.test(inputText);

  let score = 0;
  score += Math.min(0.25, words.length / 800);
  score += Math.min(0.2, nonEmptyLines.length / 120);
  score += hasJsonLike ? 0.15 : 0;
  score += hasNumbers ? 0.1 : 0;
  score += hasUrl ? 0.05 : 0;
  score += hasEmail ? 0.05 : 0;
  score += hasCodeFence ? 0.1 : 0;
  score = clamp01(score);

  const insights = [];
  insights.push(
    `Input length: ${len} chars; ~${words.length} words; ${nonEmptyLines.length} non-empty lines.`
  );
  if (goal) insights.push(`Goal: ${goal}`);
  if (hints.length) insights.push(`Hints provided: ${hints.length}.`);
  if (hasJsonLike) insights.push("Content appears to include JSON/structured data markers.");
  if (hasCodeFence) insights.push("Content includes code-fence markers (```), likely code/logs.");
  if (hasUrl) insights.push("Content includes URL(s).");
  if (hasEmail) insights.push("Content includes email-like strings.");
  if (hasNumbers) insights.push("Content includes numeric values.");

  const stop = new Set([
    "the","a","an","and","or","to","of","in","for","on","with",
    "is","are","was","were","be","as","it","this","that","by","from"
  ]);
  const counts = {};
  for (const wRaw of words.slice(0, 5000)) {
    const w = wRaw.toLowerCase().replace(/[^a-z0-9._-]/g, "");
    if (!w || w.length < 4) continue;
    if (stop.has(w)) continue;
    counts[w] = (counts[w] || 0) + 1;
  }
  const topTerms = topNByCount(counts, 6);
  if (topTerms.length) insights.push(`Top terms: ${topTerms.join(", ")}`);

  const labels = [];
  if (hasJsonLike) labels.push("structured");
  if (hasCodeFence) labels.push("code_or_logs");
  if (hasUrl) labels.push("contains_urls");
  if (hasEmail) labels.push("contains_emails");
  if (words.length > 300) labels.push("longform");
  if (nonEmptyLines.length > 30) labels.push("multiline");
  if (!labels.length) labels.push("text");

  const summary =
    `Deterministic analysis: ${labels.join(", ")}.` +
    (goal ? ` Goal="${goal}".` : "") +
    ` Score=${score.toFixed(3)}.`;

  return {
    summary,
    insights: insights.slice(0, 128),
    labels: uniq(labels).slice(0, 64),
    score,
  };
}

// ---- classify (schema expects body.input.content + required actor/limits/channel)
function tokenize(s) {
  return String(s)
    .toLowerCase()
    .replace(/[^a-z0-9\s._-]/g, " ")
    .split(/\s+/)
    .filter(Boolean);
}

function countKeywords(tokens, keywords) {
  const set = new Set(tokens);
  let hits = 0;
  for (const k of keywords) if (set.has(k)) hits++;
  return hits;
}

function doClassify(body) {
  const actor = String(body?.actor ?? "").trim();
  if (!actor) throw new Error("classify.actor required");

  const limits = body?.limits;
  if (!limits || typeof limits !== "object") throw new Error("classify.limits required");

  const channel = body?.channel;
  if (!channel || typeof channel !== "object") throw new Error("classify.channel required");

  const content = String(body?.input?.content ?? "").trim();
  if (!content) throw new Error("classify.input.content required");

  const maxLabels = Math.min(128, Math.max(1, Number(limits?.max_labels ?? 5)));

  const providedTaxonomy = Array.isArray(body?.input?.taxonomy)
    ? body.input.taxonomy.map((s) => String(s).trim()).filter(Boolean).slice(0, 128)
    : [];

  const hasJsonLike = /[{[]/.test(content) && /[}\]]/.test(content);
  const hasUrl = /\bhttps?:\/\/\S+/i.test(content);
  const hasEmail = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i.test(content);
  const hasCodeFence = /```/.test(content);
  const hasErrorWords = /\b(error|exception|stack|traceback|failed|timeout)\b/i.test(content);

  const tokens = tokenize(content);

  const candidates = providedTaxonomy.length
    ? providedTaxonomy
    : [
        "security",
        "finance",
        "legal",
        "support",
        "structured",
        "code_or_logs",
        "contains_urls",
        "contains_emails",
        "general",
      ];

  const labelKeywords = {
    security: ["vuln", "exploit", "attack", "malware", "phishing", "token", "wallet", "private", "key", "auth", "signature"],
    finance: ["invoice", "payment", "price", "cost", "usd", "revenue", "billing", "charge", "refund"],
    legal: ["contract", "terms", "policy", "compliance", "law", "agreement", "license"],
    support: ["help", "issue", "bug", "ticket", "support", "troubleshoot", "problem"],
    structured: ["json", "yaml", "schema", "object", "array"],
    code_or_logs: ["error", "exception", "stack", "traceback", "log", "node", "npm", "curl"],
    contains_urls: ["http", "https", "www"],
    contains_emails: ["@mail", "@gmail", "@yahoo"],
    general: [],
  };

  const scored = candidates
    .map((labelRaw) => {
      const label = String(labelRaw).trim();
      if (!label) return null;

      const kws = labelKeywords[label] || [];
      const overlap = kws.length ? countKeywords(tokens, kws) / kws.length : 0;

      let boost = 0;
      if (label === "structured" && hasJsonLike) boost += 0.35;
      if (label === "code_or_logs" && (hasCodeFence || hasErrorWords)) boost += 0.35;
      if (label === "contains_urls" && hasUrl) boost += 0.5;
      if (label === "contains_emails" && hasEmail) boost += 0.5;

      const score = clamp01(overlap * 0.7 + boost);
      return { label, score };
    })
    .filter(Boolean);

  scored.sort((a, b) => (b.score - a.score) || a.label.localeCompare(b.label));

  let picked = scored.slice(0, maxLabels);
  if (!picked.length) picked = [{ label: "general", score: 0.25 }];

  const allZero = picked.every((p) => p.score === 0);
  if (allZero && !picked.some((p) => p.label === "general")) {
    picked[picked.length - 1] = { label: "general", score: 0.25 };
  }

  const labels = uniq(picked.map((p) => p.label)).slice(0, 128);
  const scores = labels.map((l) => {
    const found = picked.find((p) => p.label === l);
    return clamp01(found ? found.score : 0.2);
  });

  const taxonomy = providedTaxonomy.length ? providedTaxonomy : ["root", labels[0] || "general"];

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
  if (!enabled(verb))
    return res.status(404).json(makeError(404, `Verb not enabled: ${verb}`));
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
    const x402 =
      req.body?.x402 || {
        verb,
        version: "1.0.0",
        entry: `x402://${verb}agent.eth/${verb}/v1.0.0`,
      };

    const timeoutMs = Number(
      req.body?.limits?.timeout_ms || req.body?.limits?.max_latency_ms || 0
    );

    const work = Promise.resolve(handlers[verb](req.body));
    const result = timeoutMs
      ? await Promise.race([
          work,
          new Promise((_, rej) =>
            setTimeout(() => rej(new Error("timeout")), timeoutMs)
          ),
        ])
      : await work;

    trace.completed_at = nowIso();
    trace.duration_ms = Date.now() - started;

    const receipt = makeReceipt({ x402, trace, result });
    return res.json(receipt);
  } catch (e) {
    trace.completed_at = nowIso();
    trace.duration_ms = Date.now() - started;

    return res
      .status(500)
      .json(makeError(500, e?.message || "unknown error", { verb, trace }));
  }
}

// Routes: /<verb>/v1.0.0
for (const v of Object.keys(handlers)) {
  app.post(`/${v}/v1.0.0`, (req, res) => handleVerb(v, req, res));
}

// Verify endpoint: validates schema + hash + signature; supports ENS pubkey resolution
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

    // ---- schema validation (AJV) — never hang due to www+timeout in loadSchema
    let schemaValid = false;
    let schemaErrors = null;

    if (!verb || typeof verb !== "string") {
      schemaValid = false;
      schemaErrors = ["(root): missing x402.verb"];
    } else {
      try {
        const validate = await getReceiptValidator(verb);
        schemaValid = !!validate(receipt);
        schemaErrors = schemaValid ? null : ajvErrorsToStrings(validate.errors);
      } catch (e) {
        schemaValid = false;
        schemaErrors = [e?.message || "schema validation failed"];
      }
    }

    // ---- recompute hash from canonical unsigned receipt
    const unsigned = structuredClone(receipt);
    unsigned.metadata.proof.hash_sha256 = "";
    unsigned.metadata.proof.signature_b64 = "";
    const canonical = stableStringify(unsigned);
    const recomputed = sha256Hex(canonical);

    const hashMatches = recomputed === proof.hash_sha256;

    // ---- select pubkey (ENS or env)
    const wantEns = String(req.query.ens || "") === "1";
    const refresh = String(req.query.refresh || "") === "1";
    const allowFallback = String(req.query.fallback || "") === "1";

    let pubPem = null;
    let pubSrc = null;

    if (wantEns) {
      const r = await resolveEnsPubkeyPem({ refresh });
      if (r.ok) {
        pubPem = r.pubkey_pem;
        pubSrc = "ens";
      } else if (allowFallback) {
        pubPem = pemFromB64(PUB_PEM_B64);
        pubSrc = pubPem ? "env-b64" : null;
      } else {
        return res.status(400).json({
          ok: false,
          checks: { schema_valid: schemaValid, hash_matches: hashMatches, signature_valid: false },
          values: {
            verb: verb ?? null,
            signer_id: proof.signer_id ?? null,
            alg: proof.alg ?? null,
            canonical: proof.canonical ?? null,
            claimed_hash: proof.hash_sha256 ?? null,
            recomputed_hash: recomputed,
            pubkey_source: null,
          },
          errors: { schema_errors: schemaErrors, signature_error: r.error || "ENS pubkey resolution failed" },
          error: "ens pubkey resolution failed (use fallback=1 to allow env pubkey)",
        });
      }
    } else {
      pubPem = pemFromB64(PUB_PEM_B64);
      pubSrc = pubPem ? "env-b64" : null;
    }

    // ---- signature verification
    let sigOk = false;
    let sigErr = null;

    if (pubPem) {
      try {
        sigOk = verifyEd25519Base64(
          proof.hash_sha256,
          proof.signature_b64,
          pubPem
        );
      } catch (e) {
        sigOk = false;
        sigErr = e?.message || "signature verify failed";
      }
    } else {
      sigOk = false;
      sigErr = "no pubkey available";
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
        verb: verb ?? null,
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
    return res.status(500).json({ ok: false, error: e?.message || "verify failed" });
  }
});

app.listen(PORT, () => {
  console.log(`runtime listening on :${PORT}`);
});
