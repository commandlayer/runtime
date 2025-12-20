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

const SERVICE_NAME = process.env.SERVICE_NAME?.trim() || "commandlayer-runtime";

// ENS template for schemas (per-verb)
const SCHEMA_ENS_TEMPLATE = process.env.SCHEMA_ENS_TEMPLATE?.trim() || "{verb}agent.eth";

// ENS name for verifier public key
const ENS_NAME = process.env.ENS_NAME?.trim() || null;
const VERIFIER_ENS_NAME = process.env.VERIFIER_ENS_NAME?.trim() || ENS_NAME;

const ETH_RPC_URL = process.env.ETH_RPC_URL?.trim() || null;

// Optional global override (not recommended for multi-verb)
const ENV_REQ_URL = process.env.SCHEMA_REQUEST_URL?.trim() || null;
const ENV_RCPT_URL = process.env.SCHEMA_RECEIPT_URL?.trim() || null;

const PORT = Number(process.env.PORT || 8080);
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 8000);
const ENS_CACHE_TTL_MS = Number(process.env.ENS_CACHE_TTL_MS || 10 * 60 * 1000); // 10m

// Enable verbs (start with these 3)
const ENABLED_VERBS = (process.env.ENABLED_VERBS?.trim() || "fetch,describe,format")
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

  if (clone?.metadata?.proof) delete clone.metadata.proof;

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

const verbSchemaCache = new Map();
// verb -> { mode, ok, ens, reqUrl, rcptUrl, vReq, vRcpt, error, cached_at, expires_at }

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

    const ready = { ...entry, mode: "ready", ok: true, ens, reqUrl, rcptUrl, vReq, vRcpt, error: null };
    verbSchemaCache.set(verb, ready);
    return ready;
  } catch (e) {
    const degraded = { ...entry, mode: "degraded", ok: false, error: String(e?.message ?? e) };
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

/* -------------------- verb handlers -------------------- */

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

function clampLen(s, max) {
  const x = String(s ?? "");
  return x.length <= max ? x : x.slice(0, max);
}

async function handle_describe(request) {
  const subject = request?.input?.subject ?? "";
  const detail = request?.input?.detail_level ?? "short";
  const audience = request?.input?.audience ?? "general";
  const ctx = request?.input?.context ? ` Context: ${request.input.context}` : "";

  // Simple deterministic-ish output for now (no model).
  // Schema only requires "description" string; bullets/properties are optional.
  let description =
    `**${clampLen(subject, 120)}** is a CommandLayer concept: ` +
    `a standard “API meaning” contract agents can call using published schemas and receipts.` +
    ctx;

  if (detail === "medium") {
    description += " It makes meaning portable across runtimes, and makes outcomes verifiable after the fact.";
  }
  if (detail === "long") {
    description +=
      " It combines canonical verbs, strict JSON Schemas (requests + receipts), and cryptographic receipts (hash + signature) so interoperability survives vendor swaps.";
  }

  return {
    ok: true,
    result: {
      description,
      bullets: [
        "Schemas define meaning (requests + receipts).",
        "Runtimes can be swapped without breaking interoperability.",
        "Receipts can be independently verified (hash + signature)."
      ],
      properties: {
        verb: "describe",
        version: "1.0.0",
        audience,
        detail_level: detail
      }
    }
  };
}

async function handle_format(request) {
  const content = String(request?.input?.content ?? "");
  const target_style = String(request?.input?.target_style ?? "").trim();

  if (!content) {
    return { ok: false, error: { code: "EMPTY_CONTENT", message: "input.content is required", retryable: false } };
  }
  if (!target_style) {
    return { ok: false, error: { code: "EMPTY_TARGET_STYLE", message: "input.target_style is required", retryable: false } };
  }

  const original_length = content.length;

  // Minimal “format” transformations that are deterministic and safe.
  // This is not a model. It’s a schema-green reference implementation.
  let formatted = content;

  const style = target_style.toLowerCase();

  if (style === "bullet-list" || style === "bullets") {
    // Split lines, trim, prefix
    const lines = content
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean)
      .slice(0, 64);

    formatted = lines.map((l) => `- ${l}`).join("\n");
  } else if (style === "markdown") {
    // Wrap in a markdown block if it looks like JSON, else leave as-is but trimmed
    const trimmed = content.trim();
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      formatted = "```json\n" + trimmed + "\n```";
    } else {
      formatted = trimmed;
    }
  } else if (style === "json-block" || style === "json") {
    // Try to parse and pretty print JSON. If it fails, return as a JSON string wrapper.
    try {
      const obj = JSON.parse(content);
      formatted = JSON.stringify(obj, null, 2);
    } catch {
      formatted = JSON.stringify({ content }, null, 2);
    }
  } else if (style === "table") {
    // Extremely simple: turn lines with ":" into a 2-col markdown table
    const rows = content
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean)
      .slice(0, 64)
      .map((l) => {
        const i = l.indexOf(":");
        if (i === -1) return [l, ""];
        return [l.slice(0, i).trim(), l.slice(i + 1).trim()];
      });

    formatted =
      "| key | value |\n|---|---|\n" +
      rows.map(([k, v]) => `| ${k.replaceAll("|", "\\|")} | ${v.replaceAll("|", "\\|")} |`).join("\n");
  } else {
    // Default: normalize whitespace a bit
    formatted = content.replace(/\r\n/g, "\n").trim();
  }

  const formatted_length = formatted.length;

  return {
    ok: true,
    result: {
      formatted_content: formatted,
      style: target_style,
      original_length,
      formatted_length,
      notes: "Deterministic reference formatter (non-LLM)."
    }
  };
}

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
  format: (req) => handle_format(req)
};

/* -------------------- runtime route (multi-verb) -------------------- */

app.post("/:verb/v1.0.0", async (req, res) => {
  const verb = String(req.params.verb || "").trim();

  if (!verb || !ENABLED_VERBS.includes(verb)) {
    return res.status(404).json({ error: "unknown verb", verb });
  }

  const t0 = Date.now();

  const schemas = await getVerbSchemas(verb);
  if (!schemas.ok || !schemas.vReq || !schemas.vRcpt) {
    return res.status(503).json({ error: "schemas not ready", verb, schema: schemas });
  }

  const request = req.body;
  if (!schemas.vReq(request)) {
    return res.status(400).json({ error: "request schema invalid", verb, details: schemas.vReq.errors });
  }

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

    if (!schemas.vRcpt(receipt)) {
      return res.status(500).json({
        error: "receipt schema invalid",
        verb,
        details: schemas.vRcpt.errors,
        note: "Handler output does not match this verb’s receipt schema yet."
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
