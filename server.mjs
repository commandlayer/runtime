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
// Template lets one runtime serve many verbs.
// Example: "{verb}agent.eth" -> fetchagent.eth, cleanagent.eth, etc.
const SCHEMA_ENS_TEMPLATE = process.env.SCHEMA_ENS_TEMPLATE?.trim() || "{verb}agent.eth";

// ENS used to resolve verifier public key (cl.receipt.* TXT records).
// This should be ONE stable ENS name for the whole Commons signer.
// If unset, falls back to ENS_NAME.
const ENS_NAME = process.env.ENS_NAME?.trim() || null;
const VERIFIER_ENS_NAME = process.env.VERIFIER_ENS_NAME?.trim() || ENS_NAME;

const ETH_RPC_URL = process.env.ETH_RPC_URL?.trim() || null;

// Optional override: if set, ALL verbs use these schema URLs (not recommended for multi-verb)
const ENV_REQ_URL = process.env.SCHEMA_REQUEST_URL?.trim() || null;
const ENV_RCPT_URL = process.env.SCHEMA_RECEIPT_URL?.trim() || null;

const PORT = Number(process.env.PORT || 8080);
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 8000);
const ENS_CACHE_TTL_MS = Number(process.env.ENS_CACHE_TTL_MS || 10 * 60 * 1000); // 10m

// Which verbs are enabled on this runtime
const ENABLED_VERBS = (process.env.ENABLED_VERBS?.trim() ||
  "fetch,describe,format,clean,parse,summarize")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

/* -------------------- helpers -------------------- */

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(6).toString("hex")}`;
}

function sha256Hex(s) {
  return crypto.createHash("sha256").update(String(s)).digest("hex");
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
    signature_b64: signEd25519(hash)
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
    loadSchema: async (uri) => (await fetch(uri)).json()
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
    expires_at: new Date(now + ENS_CACHE_TTL_MS).toISOString()
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
      error: null
    };

    verbSchemaCache.set(verb, ready);
    return ready;
  } catch (e) {
    const degraded = {
      ...entry,
      mode: "degraded",
      ok: false,
      error: String(e?.message ?? e)
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
    error: null
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
      last_error: ensKeyCache?.error || null
    }
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
      expires_at: k.expires_at
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
      expires_at: s.expires_at
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

    // Best-effort schema validation:
    // - If receipt.x402.verb exists, validate against that verb’s receipt schema
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
        error: requireEns ? "ENS verifier key unavailable" : "Missing RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64"
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
        pubkey_source
      },
      errors: { schema_errors, signature_error }
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: String(e?.message ?? e) });
  }
});

/* -------------------- verb implementations -------------------- */

// ✅ fetch (real network)
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
          body_preview: (text || "").slice(0, 2000)
        }
      ]
    }
  };
}

// ✅ describe (deterministic reference “explainer”)
function describeTemplate(subject, detailLevel, audience) {
  const s = String(subject || "").trim();
  const dl = (detailLevel || "short").toLowerCase();
  const aud = (audience || "novice").toLowerCase();

  const base =
    `**${s}** is a CommandLayer concept: a standard “API meaning” contract agents can call using published schemas and receipts.`;

  const bullets = [
    "Schemas define meaning (requests + receipts).",
    "Runtimes can be swapped without breaking interoperability.",
    "Receipts can be independently verified (hash + signature)."
  ];

  if (dl === "long" || aud === "expert") {
    bullets.push("ENS TXT records can point to canonical schema URIs + immutable mirrors (IPFS).");
    bullets.push("Receipt proofs bind the semantic envelope to an execution outcome.");
  }

  return { base, bullets };
}

async function handle_describe(request) {
  const subject = request?.input?.subject ?? "";
  const detail_level = request?.input?.detail_level ?? "short";
  const audience = request?.input?.audience ?? "novice";

  const { base, bullets } = describeTemplate(subject, detail_level, audience);

  return {
    ok: true,
    result: {
      description: base,
      bullets,
      properties: {
        verb: "describe",
        version: "1.0.0",
        audience: String(audience),
        detail_level: String(detail_level)
      }
    }
  };
}

// ✅ format (deterministic reference formatter)
function parseKeyValueLines(s) {
  // Accept:
  // a: 1
  // b: 2
  // c: 3
  const out = [];
  const lines = String(s || "").replace(/\r\n/g, "\n").split("\n");
  for (const line of lines) {
    const m = line.match(/^\s*([^:]+?)\s*:\s*(.*?)\s*$/);
    if (!m) continue;
    out.push([m[1].trim(), m[2].trim()]);
  }
  return out;
}

function toMarkdownTable(pairs) {
  const rows = pairs.map(([k, v]) => `| ${k} | ${v} |`);
  return ["| key | value |", "|---|---|", ...rows].join("\n");
}

async function handle_format(request) {
  const content = request?.input?.content ?? "";
  const target = String(request?.input?.target_style ?? "").toLowerCase().trim();

  let formatted = "";
  let style = target || "text";

  if (target === "table") {
    const pairs = parseKeyValueLines(content);
    if (pairs.length) {
      formatted = toMarkdownTable(pairs);
      style = "table";
    } else {
      formatted = String(content).trim();
      style = "text";
    }
  } else if (target === "json-block" || target === "json") {
    // best-effort: try parse JSON then re-stringify
    try {
      const obj = JSON.parse(String(content));
      formatted = JSON.stringify(obj, null, 2);
      style = "json";
    } catch {
      formatted = String(content).trim();
      style = "text";
    }
  } else if (target === "markdown" || target === "bullet-list") {
    // if it looks like CSV-ish / lines, bullet it
    const lines = String(content).replace(/\r\n/g, "\n").split("\n").map((l) => l.trim()).filter(Boolean);
    if (target === "bullet-list") {
      formatted = lines.map((l) => `- ${l.replace(/^\s*[-•]\s*/, "")}`).join("\n");
      style = "bullet-list";
    } else {
      formatted = lines.join("\n");
      style = "markdown";
    }
  } else {
    formatted = String(content).trim();
    style = target || "text";
  }

  return {
    ok: true,
    result: {
      formatted_content: formatted || "(empty)",
      style,
      original_length: String(content || "").length,
      formatted_length: String(formatted || "").length,
      notes: "Deterministic reference formatter (non-LLM)."
    }
  };
}

// ✅ clean (deterministic sanitization pipeline)
function applyCleanOps(input, ops = []) {
  let s = String(input || "");
  const applied = [];
  const issues = [];

  const list = Array.isArray(ops) ? ops.map(String) : [];

  for (const op of list) {
    if (op === "normalize_newlines") {
      s = s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
      applied.push(op);
    } else if (op === "collapse_whitespace") {
      // collapse spaces/tabs, but keep newlines
      s = s.replace(/[ \t]+/g, " ");
      applied.push(op);
    } else if (op === "trim") {
      s = s.trim();
      applied.push(op);
    } else if (op === "remove_empty_lines") {
      s = s
        .split("\n")
        .map((l) => l.trimEnd())
        .filter((l) => l.trim().length > 0)
        .join("\n");
      applied.push(op);
    } else if (op === "redact_emails") {
      const before = s;
      s = s.replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[redacted-email]");
      applied.push(op);
      if (s !== before) issues.push("emails_redacted");
    } else if (op) {
      // Unknown op: ignore (do not break determinism)
    }
  }

  return { cleaned: s, applied, issues };
}

async function handle_clean(request) {
  const content = request?.input?.content ?? "";
  const ops = request?.input?.operations ?? [];

  const original_length = String(content).length;
  const { cleaned, applied, issues } = applyCleanOps(content, ops);

  return {
    ok: true,
    result: {
      cleaned_content: cleaned || "(empty)",
      operations_applied: applied.length ? applied : undefined,
      issues_detected: issues.length ? issues : undefined,
      original_length,
      cleaned_length: String(cleaned).length
    }
  };
}

// ✅ parse (deterministic parsers: json, yaml-ish key: value)
function parseJsonStrict(s) {
  return JSON.parse(String(s));
}

function parseYamlBestEffort(s) {
  // very small subset: key: value per line
  const out = {};
  const lines = String(s || "").replace(/\r\n/g, "\n").split("\n");
  for (const line of lines) {
    const m = line.match(/^\s*([^:#]+?)\s*:\s*(.*?)\s*$/);
    if (!m) continue;
    const k = m[1].trim();
    const v = m[2].trim();
    out[k] = v;
  }
  return out;
}

async function handle_parse(request) {
  const content = request?.input?.content ?? "";
  const content_type = String(request?.input?.content_type ?? "").toLowerCase().trim();
  const mode = String(request?.input?.mode ?? "best_effort").toLowerCase().trim();

  let parsed = null;
  let confidence = 0.5;
  const warnings = [];

  try {
    if (content_type === "json") {
      parsed = parseJsonStrict(content);
      confidence = 0.98;
    } else if (content_type === "yaml") {
      parsed = parseYamlBestEffort(content);
      confidence = mode === "strict" ? 0.85 : 0.75;
      if (mode === "strict") warnings.push("yaml_strict_mode_is_subset_parser");
    } else {
      // best effort: try json then fallback yaml-ish
      try {
        parsed = parseJsonStrict(content);
        confidence = 0.9;
      } catch {
        parsed = parseYamlBestEffort(content);
        confidence = 0.6;
        warnings.push("best_effort_fallback_parser_used");
      }
    }
  } catch (e) {
    if (mode === "strict") {
      return {
        ok: false,
        error: {
          code: "PARSE_FAILED",
          message: String(e?.message ?? e),
          retryable: false
        }
      };
    }
    parsed = parseYamlBestEffort(content);
    confidence = 0.4;
    warnings.push("parse_failed_then_fallback_parser_used");
  }

  const result = { parsed, confidence };
  if (warnings.length) result.warnings = warnings;

  return { ok: true, result };
}

// ✅ summarize (deterministic reference summarizer)
function clampSummaryLen(maxOutputTokens) {
  // Schema says tokens; runtime returns deterministic text.
  // Treat as character budget with sane bounds.
  const n = Number(maxOutputTokens || 0);
  if (!Number.isFinite(n) || n <= 0) return 800;
  return Math.max(80, Math.min(n, 32768));
}

function pickSummaryFormat(req) {
  const hint = (req?.input?.format_hint || "").toLowerCase().trim();
  if (["text", "markdown", "html", "json", "other"].includes(hint)) return hint;

  const outs = req?.channel?.output_modalities || [];
  if (Array.isArray(outs) && outs.map(String).includes("json")) return "json";

  return "text";
}

function normalizeTextForSummarize(s) {
  return String(s || "")
    .replace(/\r\n/g, "\n")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function splitSentences(s) {
  const out = [];
  let buf = "";
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    buf += ch;
    if (ch === "." || ch === "!" || ch === "?") {
      const next = s[i + 1] || "";
      if (next === " " || next === "\n" || next === "\t" || next === "") {
        const t = buf.trim();
        if (t) out.push(t);
        buf = "";
      }
    }
  }
  const tail = buf.trim();
  if (tail) out.push(tail);
  return out;
}

function summarizeDeterministic(content, style, maxChars) {
  const text = normalizeTextForSummarize(content);
  if (!text) return "";

  if (text.length <= maxChars) return text.slice(0, maxChars);

  const sentences = splitSentences(text);
  const wantBullets = String(style || "").toLowerCase().includes("bullet");

  const picked = [];
  let used = 0;

  for (const s of sentences) {
    const nextLen = s.length + (picked.length ? 1 : 0);
    if (used + nextLen > maxChars) break;
    picked.push(s);
    used += nextLen;
    if (picked.length >= 6) break;
  }

  let out;
  if (picked.length === 0) {
    out = text.slice(0, maxChars);
  } else if (wantBullets) {
    out = picked.map((x) => `- ${x.replace(/^\s*[-•]\s*/, "")}`).join("\n");
  } else {
    out = picked.join(" ");
  }

  if (out.length > maxChars) out = out.slice(0, maxChars);
  return out;
}

async function handle_summarize(request) {
  const content = request?.input?.content ?? "";
  const maxChars = clampSummaryLen(request?.limits?.max_output_tokens);
  const format = pickSummaryFormat(request);
  const style = request?.input?.summary_style || "";

  const normalized = normalizeTextForSummarize(content);
  const summary = summarizeDeterministic(normalized, style, maxChars);

  const source_hash = sha256Hex(normalized);
  const inputLen = normalized.length || 0;
  const outputLen = summary.length || 1;
  const compression_ratio = inputLen / outputLen;

  return {
    ok: true,
    result: {
      summary: summary || "(empty summary)",
      format,
      compression_ratio,
      source_hash
    }
  };
}

// Stubs (signed receipts, but schema-green only when implemented)
async function handler_stub(_request, verb) {
  return {
    ok: false,
    error: {
      code: "NOT_IMPLEMENTED",
      message: `Verb '${verb}' is enabled but not implemented yet in this runtime.`,
      retryable: false
    }
  };
}

const HANDLERS = {
  fetch: (req) => handle_fetch(req),
  describe: (req) => handle_describe(req),
  format: (req) => handle_format(req),
  clean: (req) => handle_clean(req),
  parse: (req) => handle_parse(req),
  summarize: (req) => handle_summarize(req)
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
    const exec = handler ? await handler(request) : await handler_stub(request, verb);

    const base = {
      x402: request.x402,
      trace: {
        trace_id,
        started_at,
        completed_at: new Date().toISOString(),
        duration_ms: Date.now() - t0,
        provider: SERVICE_NAME
      }
    };

    let receipt;

    if (exec.ok) {
      receipt = {
        status: "success",
        ...base,
        result: exec.result
      };
    } else {
      receipt = {
        status: "error",
        ...base,
        error: exec.error || { code: "RUNTIME_ERROR", message: "unknown error", retryable: true }
      };
    }

    attachReceiptProofOrThrow(receipt);

    // Validate receipt against verb receipt schema
    if (!schemas.vRcpt(receipt)) {
      return res.status(500).json({
        error: "receipt schema invalid",
        verb,
        details: schemas.vRcpt.errors,
        note: "Handler output does not match this verb’s receipt schema yet. Implement/fix the verb handler."
      });
    }

    return res.json(receipt);
  } catch (e) {
    const msg = String(e?.message ?? e);
    return res.status(500).json({
      error: "runtime_error",
      verb,
      message: msg,
      hint: msg.includes("Missing RECEIPT_") ? "Signing key misconfigured (check *_PEM_B64 vars)." : null
    });
  }
});

/* -------------------- start -------------------- */

app.listen(PORT, "0.0.0.0", () => {
  console.log(`listening on ${PORT}`);
});
