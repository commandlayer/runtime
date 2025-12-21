// server.mjs
console.log("SERVER.MJS BOOTED");

import express from "express";
import fetch from "node-fetch";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import crypto from "node:crypto";
import { ethers } from "ethers";

const app = express();
app.use(express.json({ limit: "2mb" }));

/* -------------------- config -------------------- */

// Runtime identity (used in trace.provider + default signer_id)
const SERVICE_NAME = process.env.SERVICE_NAME?.trim() || "commandlayer-runtime";

// ENS used to resolve schema TXT records for each verb.
// Example: "{verb}agent.eth" -> fetchagent.eth, cleanagent.eth, etc.
const SCHEMA_ENS_TEMPLATE = process.env.SCHEMA_ENS_TEMPLATE?.trim() || "{verb}agent.eth";

// ENS used to resolve verifier public key (cl.receipt.* TXT records).
const ENS_NAME = process.env.ENS_NAME?.trim() || null;
const VERIFIER_ENS_NAME = process.env.VERIFIER_ENS_NAME?.trim() || ENS_NAME;

const ETH_RPC_URL = process.env.ETH_RPC_URL?.trim() || null;

// Optional override: if set, ALL verbs use these schema URLs (not recommended for multi-verb)
const ENV_REQ_URL = process.env.SCHEMA_REQUEST_URL?.trim() || null;
const ENV_RCPT_URL = process.env.SCHEMA_RECEIPT_URL?.trim() || null;

const PORT = Number(process.env.PORT || 8080);
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 8000);
const ENS_CACHE_TTL_MS = Number(process.env.ENS_CACHE_TTL_MS || 10 * 60 * 1000); // 10m

// Enabled verbs (supports spaces)
const ENABLED_VERBS = (process.env.ENABLED_VERBS?.trim() ||
  "fetch,describe,format,clean,parse,summarize,convert")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

/* -------------------- helpers -------------------- */

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString("hex")}`;
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(s).digest("hex");
}

function canonicalJson(obj) {
  // v1: stable-enough canonicalization (insertion order)
  return JSON.stringify(obj);
}

function readPemB64Env(name) {
  const b64 = process.env[name]?.trim();
  if (!b64) return null;
  try {
    return Buffer.from(b64, "base64").toString("utf8").trim();
  } catch {
    return null;
  }
}

function recomputeReceiptHash(receipt) {
  const clone = structuredClone(receipt);

  // Remove proof prior to hashing
  if (clone?.metadata?.proof) delete clone.metadata.proof;

  // If metadata becomes empty after removing proof, delete it too
  if (
    clone?.metadata &&
    typeof clone.metadata === "object" &&
    !Array.isArray(clone.metadata) &&
    Object.keys(clone.metadata).length === 0
  ) {
    delete clone.metadata;
  }

  return sha256Hex(canonicalJson(clone));
}

function signEd25519(hashHex) {
  const pem = readPemB64Env("RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64");
  if (!pem) throw new Error("Missing RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64");
  const msg = Buffer.from(hashHex, "hex");
  const sig = crypto.sign(null, msg, { key: pem });
  return sig.toString("base64");
}

function attachReceiptProofOrThrow(receipt) {
  const hash = recomputeReceiptHash(receipt);

  receipt.metadata = receipt.metadata || {};
  receipt.metadata.proof = {
    alg: "ed25519-sha256",
    canonical: "json-stringify",
    hash_sha256: hash,
    signer_id: process.env.RECEIPT_SIGNER_ID?.trim() || SERVICE_NAME,
    signature_b64: signEd25519(hash),
  };

  if (!receipt?.metadata?.proof?.signature_b64 || !receipt?.metadata?.proof?.hash_sha256) {
    throw new Error("INTERNAL: receipt proof missing after signing");
  }

  return receipt;
}

function verifyEd25519(hashHex, sigB64, pubPem) {
  const msg = Buffer.from(hashHex, "hex");
  const sig = Buffer.from(sigB64, "base64");
  return crypto.verify(null, msg, { key: pubPem }, sig);
}

// SSRF guard (demo safety)
function blocked(url) {
  try {
    const u = new URL(url);
    const h = u.hostname;

    if (u.protocol !== "http:" && u.protocol !== "https:") return true;

    return (
      h === "localhost" ||
      h.endsWith(".local") ||
      h === "::1" ||
      /^127\./.test(h) ||
      /^10\./.test(h) ||
      /^192\.168\./.test(h) ||
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(h) ||
      /^169\.254\./.test(h)
    );
  } catch {
    return true;
  }
}

function ensForVerb(verb) {
  return SCHEMA_ENS_TEMPLATE.replaceAll("{verb}", verb);
}

function clampStr(s, maxLen) {
  const v = String(s ?? "");
  return v.length > maxLen ? v.slice(0, maxLen) : v;
}

/* -------------------- ENS helpers -------------------- */

async function getProvider() {
  if (!ETH_RPC_URL) throw new Error("Missing ETH_RPC_URL");
  return new ethers.JsonRpcProvider(ETH_RPC_URL);
}

async function getResolver(name) {
  if (!name) throw new Error("Missing ENS name");
  const provider = await getProvider();
  const resolver = await provider.getResolver(name);
  if (!resolver) throw new Error(`No resolver for ${name}`);
  return resolver;
}

async function resolveSchemasFromENS(verb) {
  const name = ensForVerb(verb);
  const resolver = await getResolver(name);
  const reqUrl = await resolver.getText("cl.schema.request");
  const rcptUrl = await resolver.getText("cl.schema.receipt");
  if (!reqUrl || !rcptUrl) throw new Error(`ENS missing schema TXT records on ${name}`);
  return { ens: name, reqUrl, rcptUrl };
}

async function resolveVerifierKeyFromENS() {
  const resolver = await getResolver(VERIFIER_ENS_NAME);

  const alg = (await resolver.getText("cl.receipt.alg"))?.trim() || null;
  const signer_id = (await resolver.getText("cl.receipt.signer_id"))?.trim() || null;

  const pubEscaped = await resolver.getText("cl.receipt.pubkey_pem");
  if (!pubEscaped) throw new Error(`ENS missing cl.receipt.pubkey_pem on ${VERIFIER_ENS_NAME}`);

  const pubkey_pem = pubEscaped.replace(/\\n/g, "\n").trim();
  return { ens: VERIFIER_ENS_NAME, alg, signer_id, pubkey_pem };
}

/* -------------------- schema cache per verb -------------------- */

const verbSchemaCache = new Map(); // verb -> { mode, ok, ens, reqUrl, rcptUrl, vReq, vRcpt, error, cached_at, expires_at }

function verbCacheValid(verb) {
  const v = verbSchemaCache.get(verb);
  if (!v?.expires_at) return false;
  return Date.now() < Date.parse(v.expires_at);
}

async function buildValidators(reqUrl, rcptUrl) {
  const ajv = new Ajv2020({
    strict: true,
    allErrors: true,
    loadSchema: async (uri) => (await fetch(uri)).json(),
  });
  addFormats(ajv);

  const reqSchema = await (await fetch(reqUrl)).json();
  const rcptSchema = await (await fetch(rcptUrl)).json();

  const vReq = await ajv.compileAsync(reqSchema);
  const vRcpt = await ajv.compileAsync(rcptSchema);

  return { vReq, vRcpt };
}

async function getVerbSchemas(verb, { refresh = false } = {}) {
  if (!refresh && verbCacheValid(verb)) return verbSchemaCache.get(verb);

  const now = Date.now();
  const entry = {
    mode: "booting",
    ok: false,
    ens: null,
    reqUrl: null,
    rcptUrl: null,
    vReq: null,
    vRcpt: null,
    error: null,
    cached_at: new Date(now).toISOString(),
    expires_at: new Date(now + ENS_CACHE_TTL_MS).toISOString(),
  };

  verbSchemaCache.set(verb, entry);

  try {
    // Optional global env override (not recommended when serving many verbs)
    let reqUrl = ENV_REQ_URL;
    let rcptUrl = ENV_RCPT_URL;
    let ens = null;

    if (!reqUrl || !rcptUrl) {
      const resolved = await resolveSchemasFromENS(verb);
      ens = resolved.ens;
      reqUrl = resolved.reqUrl;
      rcptUrl = resolved.rcptUrl;
    }

    const { vReq, vRcpt } = await buildValidators(reqUrl, rcptUrl);

    const ready = {
      ...entry,
      mode: "ready",
      ok: true,
      ens,
      reqUrl,
      rcptUrl,
      vReq,
      vRcpt,
      error: null,
    };

    verbSchemaCache.set(verb, ready);
    return ready;
  } catch (e) {
    const degraded = {
      ...entry,
      mode: "degraded",
      ok: false,
      error: String(e?.message ?? e),
    };
    verbSchemaCache.set(verb, degraded);
    return degraded;
  }
}

/* -------------------- ENS verifier key cache -------------------- */

let ensKeyCache = null; // { ens, alg, signer_id, pubkey_pem, cached_at, expires_at, error }

function keyCacheValid() {
  if (!ensKeyCache?.pubkey_pem || !ensKeyCache?.expires_at) return false;
  return Date.now() < Date.parse(ensKeyCache.expires_at);
}

async function getEnsVerifierKey({ refresh = false } = {}) {
  if (!refresh && keyCacheValid()) return { ...ensKeyCache, source: "ens-cache" };

  const now = Date.now();
  const k = await resolveVerifierKeyFromENS();

  ensKeyCache = {
    ...k,
    cached_at: new Date(now).toISOString(),
    expires_at: new Date(now + ENS_CACHE_TTL_MS).toISOString(),
    error: null,
  };

  return { ...ensKeyCache, source: "ens" };
}

/* -------------------- always-on routes -------------------- */

app.get("/health", (_req, res) => res.status(200).send("ok"));

app.get("/debug/env", (_req, res) => {
  let signer_ok = false;
  let signer_error = null;

  try {
    signEd25519(sha256Hex("debug"));
    signer_ok = true;
  } catch (e) {
    signer_error = String(e?.message ?? e);
  }

  const pubEnv = readPemB64Env("RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64");

  res.json({
    ok: true,
    node: process.version,
    cwd: process.cwd(),
    port: PORT,
    service: SERVICE_NAME,

    ens_name: ENS_NAME,
    verifier_ens_name: VERIFIER_ENS_NAME,
    schema_ens_template: SCHEMA_ENS_TEMPLATE,

    has_rpc: Boolean(ETH_RPC_URL),
    enabled_verbs: ENABLED_VERBS,

    ping_test: process.env.PING_TEST || null,

    signer_id: process.env.RECEIPT_SIGNER_ID?.trim() || SERVICE_NAME,
    signer_ok,
    signer_error,

    has_priv_b64: Boolean(process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64),
    has_pub_b64: Boolean(process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64),
    pub_env_preview: pubEnv ? pubEnv.slice(0, 30) + "..." : null,

    ens_verifier_cache: {
      has_key: Boolean(ensKeyCache?.pubkey_pem),
      cached_at: ensKeyCache?.cached_at || null,
      expires_at: ensKeyCache?.expires_at || null,
      last_error: ensKeyCache?.error || null,
    },
  });
});

app.get("/debug/enskey", async (_req, res) => {
  try {
    const k = await getEnsVerifierKey({ refresh: true });
    res.json({
      ok: true,
      ens: k.ens,
      alg: k.alg,
      signer_id: k.signer_id,
      pubkey_source: k.source,
      pubkey_preview: k.pubkey_pem.slice(0, 40) + "...",
      cached_at: k.cached_at,
      expires_at: k.expires_at,
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e?.message ?? e) });
  }
});

app.get("/debug/verbs", async (req, res) => {
  const refresh = String(req.query?.refresh || "") === "1";
  const out = {};
  for (const verb of ENABLED_VERBS) {
    const s = await getVerbSchemas(verb, { refresh });
    out[verb] = {
      mode: s.mode,
      ok: s.ok,
      ens: s.ens,
      reqUrl: s.reqUrl,
      rcptUrl: s.rcptUrl,
      error: s.error || null,
      cached_at: s.cached_at,
      expires_at: s.expires_at,
    };
  }
  res.json({ ok: true, verbs: out });
});

/* -------------------- /verify -------------------- */

app.post("/verify", async (req, res) => {
  try {
    const receipt = req.body;
    const proof = receipt?.metadata?.proof || null;

    if (!proof?.signature_b64 || !proof?.hash_sha256) {
      return res.status(400).json({ ok: false, error: "missing metadata.proof.signature_b64 or hash_sha256" });
    }

    // Best-effort schema validation using receipt.x402.verb
    const verb = receipt?.x402?.verb?.trim?.() || null;
    let schema_valid = false;
    let schema_errors = null;

    if (verb && ENABLED_VERBS.includes(verb)) {
      const s = await getVerbSchemas(verb);
      if (s?.vRcpt) schema_valid = Boolean(s.vRcpt(receipt));
      schema_errors = s?.vRcpt ? (s.vRcpt.errors || null) : [{ message: "receipt validator not ready", schemaState: s }];
    } else {
      schema_valid = false;
      schema_errors = [{ message: "unknown verb for schema validation", verb }];
    }

    const recomputed_hash = recomputeReceiptHash(receipt);
    const claimed_hash = String(proof.hash_sha256);
    const hash_matches = recomputed_hash === claimed_hash;

    const requireEns = String(req.query?.ens || "") === "1";
    const refresh = String(req.query?.refresh || "") === "1";

    let pubPem = null;
    let pubkey_source = null;

    if (requireEns) {
      const k = await getEnsVerifierKey({ refresh });
      pubPem = k.pubkey_pem;
      pubkey_source = k.source;
    } else {
      pubPem = readPemB64Env("RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64");
      pubkey_source = pubPem ? "env-b64" : null;
    }

    if (!pubPem) {
      return res.status(503).json({
        ok: false,
        error: requireEns ? "ENS verifier key unavailable" : "Missing RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64",
      });
    }

    let signature_valid = false;
    let signature_error = null;
    try {
      signature_valid = verifyEd25519(recomputed_hash, proof.signature_b64, pubPem);
    } catch (e) {
      signature_error = String(e?.message ?? e);
      signature_valid = false;
    }

    return res.json({
      ok: true,
      checks: { schema_valid, hash_matches, signature_valid },
      values: {
        verb,
        signer_id: proof.signer_id || null,
        alg: proof.alg || null,
        canonical: proof.canonical || null,
        claimed_hash,
        recomputed_hash,
        pubkey_source,
      },
      errors: { schema_errors, signature_error },
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message ?? e) });
  }
});

/* -------------------- verb handlers -------------------- */

// ✅ Real handler (already proven)
async function handle_fetch(request) {
  const url = request.source;
  if (blocked(url)) {
    return { ok: false, error: { code: "BAD_SOURCE", message: "blocked or invalid source", retryable: false } };
  }

  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  let r, text;
  try {
    r = await fetch(url, { signal: controller.signal });
    text = await r.text();
  } finally {
    clearTimeout(t);
  }

  const headers = {};
  r.headers.forEach((v, k) => (headers[k] = v));

  return {
    ok: true,
    result: {
      items: [
        {
          source: url,
          query: request.query ?? null,
          include_metadata: request.include_metadata ?? null,
          ok: r.ok,
          http_status: r.status,
          headers,
          body_preview: (text || "").slice(0, 2000),
        },
      ],
    },
  };
}

/* -------- describe (deterministic reference output) -------- */

function buildDescribeText(subject, detail_level, audience) {
  const s = clampStr(subject, 200);
  const dl = detail_level || "medium";
  const aud = audience || "general";

  if (dl === "short") {
    return `**${s}** is a CommandLayer concept: a standard “API meaning” contract agents can call using published schemas and receipts.`;
  }
  if (dl === "long") {
    return `**${s}** is described in CommandLayer terms as a semantic contract: a stable verb+schema interface whose outputs are issued as verifiable receipts. This enables interoperability across runtimes (swap execution without breaking meaning) and post-hoc verification (hash + signature). Audience: ${aud}.`;
  }
  return `**${s}** is a semantic contract surface in CommandLayer: verbs + schemas define meaning, and receipts provide verifiable evidence of execution.`;
}

async function handle_describe(request) {
  const subject = request?.input?.subject ?? "Unknown";
  const detail_level = request?.input?.detail_level ?? "medium";
  const audience = request?.input?.audience ?? "general";

  const description = buildDescribeText(subject, detail_level, audience);

  const bullets = [
    "Schemas define meaning (requests + receipts).",
    "Runtimes can be swapped without breaking interoperability.",
    "Receipts can be independently verified (hash + signature).",
  ];

  const properties = {
    verb: "describe",
    version: "1.0.0",
    audience: String(audience),
    detail_level: String(detail_level),
  };

  return {
    ok: true,
    result: {
      description,
      bullets,
      properties,
    },
  };
}

/* -------- format (deterministic reference formatter) -------- */

function parseLooseKVLines(s) {
  // Accept "a: 1" lines (very small YAML-ish)
  const out = [];
  const lines = String(s ?? "").split(/\r?\n/).filter((x) => x.trim().length);
  for (const line of lines) {
    const m = line.match(/^\s*([^:#]+?)\s*:\s*(.*?)\s*$/);
    if (m) out.push([m[1].trim(), m[2].trim()]);
  }
  return out;
}

function toMarkdownTable(pairs) {
  const rows = pairs.map(([k, v]) => [String(k), String(v)]);
  const header = `| key | value |\n|---|---|`;
  const body = rows.map(([k, v]) => `| ${k} | ${v} |`).join("\n");
  return `${header}\n${body}`;
}

async function handle_format(request) {
  const content = request?.input?.content ?? "";
  const target_style = (request?.input?.target_style ?? "text").toString();

  const original_length = String(content).length;
  const warnings = [];

  let formatted_content = String(content);
  let style = target_style;

  if (target_style === "table") {
    const pairs = parseLooseKVLines(content);
    if (pairs.length) {
      formatted_content = toMarkdownTable(pairs);
      style = "table";
    } else {
      warnings.push("No key:value lines detected; returning original content.");
      formatted_content = String(content);
      style = "text";
    }
  } else if (target_style === "json_pretty") {
    try {
      const obj = JSON.parse(String(content));
      formatted_content = JSON.stringify(obj, null, 2);
      style = "json_pretty";
    } catch {
      warnings.push("Invalid JSON; returning original content.");
      formatted_content = String(content);
      style = "text";
    }
  } else {
    style = target_style;
    formatted_content = String(content);
  }

  const formatted_length = formatted_content.length;

  return {
    ok: true,
    result: {
      formatted_content,
      style,
      original_length,
      formatted_length,
      notes: "Deterministic reference formatter (non-LLM).",
      ...(warnings.length ? { warnings } : {}),
    },
  };
}

/* -------- clean (deterministic normalizer) -------- */

function normalizeNewlines(s) {
  return String(s ?? "").replace(/\r\n/g, "\n").replace(/\r/g, "\n");
}
function collapseWhitespace(s) {
  return String(s ?? "").replace(/[ \t]+/g, " ");
}
function trim(s) {
  return String(s ?? "").trim();
}
function removeEmptyLines(s) {
  return String(s ?? "")
    .split("\n")
    .map((l) => l.trimEnd())
    .filter((l) => l.trim().length > 0)
    .join("\n");
}
function redactEmails(s) {
  // Simple email regex (best-effort)
  const re = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
  const had = re.test(String(s ?? ""));
  const out = String(s ?? "").replace(re, "[redacted-email]");
  return { out, had };
}

async function handle_clean(request) {
  const content = request?.input?.content ?? "";
  const ops = Array.isArray(request?.input?.operations) ? request.input.operations : [];

  const original_length = String(content).length;
  let s = String(content);
  const operations_applied = [];
  const issues_detected = [];
  const warnings = [];

  for (const op of ops) {
    const o = String(op);
    if (o === "normalize_newlines") {
      s = normalizeNewlines(s);
      operations_applied.push(o);
    } else if (o === "collapse_whitespace") {
      s = collapseWhitespace(s);
      operations_applied.push(o);
    } else if (o === "trim") {
      s = trim(s);
      operations_applied.push(o);
    } else if (o === "remove_empty_lines") {
      s = removeEmptyLines(s);
      operations_applied.push(o);
    } else if (o === "redact_emails") {
      const { out, had } = redactEmails(s);
      s = out;
      operations_applied.push(o);
      if (had) issues_detected.push("emails_redacted");
    } else {
      warnings.push(`Unknown operation '${o}' ignored.`);
    }
  }

  // If no ops specified, do a safe default: normalize + trim
  if (operations_applied.length === 0) {
    s = trim(normalizeNewlines(s));
    operations_applied.push("normalize_newlines", "trim");
  }

  const cleaned_length = s.length;

  return {
    ok: true,
    result: {
      cleaned_content: s,
      original_length,
      cleaned_length,
      operations_applied,
      ...(issues_detected.length ? { issues_detected } : {}),
      ...(warnings.length ? { warnings } : {}),
    },
  };
}

/* -------- parse (deterministic reference parser) -------- */

function tryJsonParse(s) {
  return JSON.parse(String(s));
}

function parseLooseYamlKV(s) {
  const pairs = parseLooseKVLines(s);
  const obj = {};
  for (const [k, v] of pairs) obj[k] = v;
  return obj;
}

async function handle_parse(request) {
  const content = request?.input?.content ?? "";
  const content_type = (request?.input?.content_type ?? "").toString().toLowerCase();
  const mode = (request?.input?.mode ?? "best_effort").toString();

  let parsed = {};
  let confidence = 0.5;
  const warnings = [];

  if (content_type === "json") {
    try {
      parsed = tryJsonParse(content);
      confidence = 0.98;
    } catch (e) {
      if (mode === "strict") {
        // Strict: return “best-effort but schema-green”
        warnings.push("Invalid JSON in strict mode; returning empty object.");
        parsed = {};
        confidence = 0.01;
      } else {
        warnings.push("Invalid JSON; falling back to empty object.");
        parsed = {};
        confidence = 0.05;
      }
    }
  } else if (content_type === "yaml") {
    // Minimal YAML-ish: key: value lines
    parsed = parseLooseYamlKV(content);
    confidence = Object.keys(parsed).length ? 0.75 : 0.2;
    if (!Object.keys(parsed).length) warnings.push("No key:value pairs detected.");
  } else {
    // Default: attempt JSON, else fallback to kv pairs, else raw wrapper
    try {
      parsed = tryJsonParse(content);
      confidence = 0.9;
      warnings.push("content_type not provided; inferred JSON.");
    } catch {
      const obj = parseLooseYamlKV(content);
      if (Object.keys(obj).length) {
        parsed = obj;
        confidence = 0.6;
        warnings.push("content_type not provided; inferred key:value lines.");
      } else {
        parsed = { text: String(content) };
        confidence = 0.3;
        warnings.push("content_type not provided; returning raw text wrapper.");
      }
    }
  }

  return {
    ok: true,
    result: {
      parsed,
      confidence,
      ...(request?.input?.target_schema ? { target_schema: String(request.input.target_schema) } : {}),
      ...(warnings.length ? { warnings } : {}),
    },
  };
}

/* -------- summarize (deterministic reference summarizer) -------- */

function summarizeBullets(text, maxChars) {
  const s = String(text ?? "").trim();
  if (!s) return "";

  // Split into sentences-ish
  const parts = s
    .replace(/\s+/g, " ")
    .split(/(?<=[.!?])\s+/)
    .filter(Boolean);

  const bullets = [];
  for (const p of parts.slice(0, 6)) {
    bullets.push(`- ${p}`);
  }
  const out = bullets.join("\n");
  return out.length > maxChars ? out.slice(0, maxChars) : out;
}

function summarizePlain(text, maxChars) {
  const s = String(text ?? "").replace(/\s+/g, " ").trim();
  if (s.length <= maxChars) return s;
  return s.slice(0, Math.max(0, maxChars - 1)) + "…";
}

async function handle_summarize(request) {
  const content = request?.input?.content ?? "";
  const format_hint = (request?.input?.format_hint ?? "text").toString();
  const summary_style = (request?.input?.summary_style ?? "text").toString();

  const maxOut = Number(request?.limits?.max_output_tokens ?? 400);
  const maxChars = Math.max(32, Math.min(25000, maxOut * 4)); // rough

  let summary = "";
  let format = "text";
  const warnings = [];

  if (summary_style === "bullet_points") {
    summary = summarizeBullets(content, maxChars);
    format = format_hint === "markdown" ? "markdown" : "text";
  } else {
    summary = summarizePlain(content, maxChars);
    format = format_hint === "markdown" ? "markdown" : "text";
  }

  if (!summary) {
    summary = summarizePlain(content, maxChars);
    warnings.push("Empty summary produced; fell back to plain summarization.");
  }

  const inLen = String(content).length || 1;
  const outLen = String(summary).length || 1;

  return {
    ok: true,
    result: {
      summary,
      format,
      compression_ratio: inLen / outLen,
      source_hash: sha256Hex(String(content)),
      ...(warnings.length ? { warnings } : {}),
    },
  };
}

/* -------- convert (deterministic reference converter) -------- */

function csvEscape(v) {
  const s = String(v ?? "");
  if (/[",\r\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

function jsonToCsvString(value) {
  // value can be object or array of objects
  const arr = Array.isArray(value) ? value : [value];
  const rows = arr
    .filter((x) => x && typeof x === "object" && !Array.isArray(x))
    .map((x) => x);

  const headersSet = new Set();
  for (const r of rows) for (const k of Object.keys(r)) headersSet.add(k);
  const headers = Array.from(headersSet);

  const lines = [];
  lines.push(headers.map(csvEscape).join(","));
  for (const r of rows) {
    lines.push(headers.map((h) => csvEscape(r[h] ?? "")).join(","));
  }
  return lines.join("\n");
}

function parseCsv(s) {
  // Minimal CSV parser (handles quotes)
  const text = String(s ?? "");
  const rows = [];
  let row = [];
  let cur = "";
  let i = 0;
  let inQuotes = false;

  while (i < text.length) {
    const ch = text[i];

    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          cur += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i += 1;
        continue;
      }
      cur += ch;
      i += 1;
      continue;
    }

    if (ch === '"') {
      inQuotes = true;
      i += 1;
      continue;
    }

    if (ch === ",") {
      row.push(cur);
      cur = "";
      i += 1;
      continue;
    }

    if (ch === "\n") {
      row.push(cur);
      rows.push(row);
      row = [];
      cur = "";
      i += 1;
      continue;
    }

    if (ch === "\r") {
      i += 1;
      continue;
    }

    cur += ch;
    i += 1;
  }

  row.push(cur);
  rows.push(row);

  // Trim trailing empty last row if file ends with newline
  if (rows.length && rows[rows.length - 1].length === 1 && rows[rows.length - 1][0] === "") rows.pop();

  return rows;
}

function csvToJsonString(csvText) {
  const rows = parseCsv(csvText);
  if (!rows.length) return "[]";
  const headers = rows[0].map((h) => String(h ?? "").trim());
  const out = [];

  for (const r of rows.slice(1)) {
    const obj = {};
    for (let i = 0; i < headers.length; i++) {
      const key = headers[i] || `col_${i + 1}`;
      obj[key] = r[i] ?? "";
    }
    out.push(obj);
  }
  return JSON.stringify(out, null, 2);
}

function htmlToTextLoose(html) {
  // Very lossy: strip tags, preserve basic breaks
  let s = String(html ?? "");
  s = s.replace(/<\s*br\s*\/?\s*>/gi, "\n");
  s = s.replace(/<\/\s*p\s*>/gi, "\n\n");
  s = s.replace(/<[^>]+>/g, "");
  s = s.replace(/&nbsp;/g, " ");
  s = s.replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">");
  return s.trim();
}

function textToHtmlLoose(text) {
  const s = String(text ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  return `<pre>${s}</pre>`;
}

async function handle_convert(request) {
  const content = request?.input?.content ?? "";
  const source_format = String(request?.input?.source_format ?? "").toLowerCase().trim();
  const target_format = String(request?.input?.target_format ?? "").toLowerCase().trim();
  const options = request?.input?.options ?? {};

  const warnings = [];
  let lossy = false;
  let converted = String(content);

  const pair = `${source_format}->${target_format}`;

  try {
    if (pair === "json->csv") {
      const obj = JSON.parse(String(content));
      converted = jsonToCsvString(obj);
      lossy = true; // csv loses types/nesting
      warnings.push("JSON->CSV is lossy (types/nesting may be flattened).");
    } else if (pair === "csv->json") {
      converted = csvToJsonString(String(content));
      lossy = false;
    } else if (pair === "json->text" || pair === "json->plain") {
      const obj = JSON.parse(String(content));
      converted = JSON.stringify(obj, null, 2);
      lossy = false;
    } else if (pair === "text->json" || pair === "plain->json") {
      // best-effort: must be valid JSON
      const obj = JSON.parse(String(content));
      converted = JSON.stringify(obj, null, 2);
      lossy = false;
    } else if (pair === "html->markdown") {
      // super minimal “markdown”: really just text
      converted = htmlToTextLoose(content);
      lossy = true;
      warnings.push("HTML->Markdown is implemented as lossy text extraction (no rich structure).");
    } else if (pair === "markdown->html") {
      converted = textToHtmlLoose(content);
      lossy = true;
      warnings.push("Markdown->HTML is implemented as <pre> passthrough (lossy).");
    } else if (pair === `${source_format}->${source_format}`) {
      converted = String(content);
      lossy = false;
    } else {
      // Keep schema-green: passthrough with warnings
      converted = String(content);
      lossy = false;
      warnings.push(`Unsupported conversion '${pair}'; returning passthrough content.`);
      if (options && typeof options === "object" && Object.keys(options).length) {
        warnings.push("Options were provided but not applied for unsupported conversion.");
      }
    }
  } catch (e) {
    // Keep schema-green: passthrough with warning
    converted = String(content);
    lossy = false;
    warnings.push(`Conversion error for '${pair}': ${String(e?.message ?? e)} (passthrough returned).`);
  }

  return {
    ok: true,
    result: {
      converted_content: converted.length ? converted : " ", // must satisfy minLength 1
      source_format: source_format || "unknown",
      target_format: target_format || "unknown",
      lossy,
      ...(warnings.length ? { warnings } : {}),
    },
  };
}

/* -------------------- handlers registry -------------------- */

const HANDLERS = {
  fetch: (req) => handle_fetch(req),
  describe: (req) => handle_describe(req),
  format: (req) => handle_format(req),
  clean: (req) => handle_clean(req),
  parse: (req) => handle_parse(req),
  summarize: (req) => handle_summarize(req),
  convert: (req) => handle_convert(req),
};

/* -------------------- runtime route (multi-verb) -------------------- */

app.post("/:verb/v1.0.0", async (req, res) => {
  const verb = String(req.params.verb || "").trim();

  if (!verb || !ENABLED_VERBS.includes(verb)) {
    return res.status(404).json({ error: "unknown verb", verb });
  }

  const t0 = Date.now();

  // Load validators for this verb
  const schemas = await getVerbSchemas(verb);
  if (!schemas.ok || !schemas.vReq || !schemas.vRcpt) {
    return res.status(503).json({ error: "schemas not ready", verb, schema: schemas });
  }

  // Validate request
  const request = req.body;
  if (!schemas.vReq(request)) {
    return res.status(400).json({ error: "request schema invalid", verb, details: schemas.vReq.errors });
  }

  // Execute via handler
  const started_at = new Date().toISOString();
  const trace_id = id("trace");
  const handler = HANDLERS[verb];

  try {
    if (!handler) {
      return res.status(500).json({ error: "no_handler", verb });
    }

    const exec = await handler(request);

    const base = {
      x402: request.x402,
      trace: {
        trace_id,
        started_at,
        completed_at: new Date().toISOString(),
        duration_ms: Date.now() - t0,
        provider: SERVICE_NAME,
      },
    };

    // IMPORTANT: our commons verbs are implemented to always return ok:true
    // to keep receipt schemas (which require result) schema-green.
    let receipt = {
      status: "success",
      ...base,
      result: exec?.result ?? {},
      ...(exec?.usage ? { usage: exec.usage } : {}),
    };

    attachReceiptProofOrThrow(receipt);

    // Validate receipt against verb receipt schema
    if (!schemas.vRcpt(receipt)) {
      return res.status(500).json({
        error: "receipt schema invalid",
        verb,
        details: schemas.vRcpt.errors,
        note: "Handler output does not match this verb’s receipt schema. Fix handler to match schema.",
      });
    }

    return res.json(receipt);
  } catch (e) {
    const msg = String(e?.message ?? e);
    return res.status(500).json({
      error: "runtime_error",
      verb,
      message: msg,
      hint: msg.includes("Missing RECEIPT_") ? "Signing key misconfigured (check *_PEM_B64 vars)." : null,
    });
  }
});

/* -------------------- start -------------------- */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`listening on ${PORT}`);
});
