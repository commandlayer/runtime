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
// This should be ONE stable ENS name for the whole Commons signer.
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
const ENABLED_VERBS = (process.env.ENABLED_VERBS?.trim() || "fetch,describe,format,clean")
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

// ✅ fetch (real)
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

// ✅ describe (real)
async function handle_describe(request) {
  const subject = String(request?.input?.subject ?? "").trim();
  const detail = String(request?.input?.detail_level ?? "medium");
  const audience = String(request?.input?.audience ?? "general");
  const context = request?.input?.context ? String(request.input.context) : null;

  const base = `**${subject}** is a CommandLayer subject: a standard “API meaning” contract agents can call using published schemas and receipts.`;
  const more =
    detail === "short"
      ? base
      : detail === "long"
        ? `${base}\n\nIt’s designed so meaning (schemas) stays stable while execution (runtimes) can be swapped. Receipts make executions independently verifiable (schema + hash + signature).`
        : base;

  const bullets = [
    "Schemas define meaning (requests + receipts).",
    "Runtimes can be swapped without breaking interoperability.",
    "Receipts can be independently verified (hash + signature).",
  ];

  const properties = {
    verb: "describe",
    version: "1.0.0",
    audience,
    detail_level: detail,
    ...(context ? { context: context.slice(0, 256) } : {}),
  };

  return {
    ok: true,
    result: {
      description: more,
      bullets,
      properties,
    },
  };
}

// ✅ format (real) — deterministic reference formatter (non-LLM)
function toMarkdownTableFromPairs(pairs) {
  const header = "| key | value |\n|---|---|";
  const rows = pairs.map(([k, v]) => `| ${k} | ${v} |`).join("\n");
  return `${header}\n${rows}`;
}

async function handle_format(request) {
  const content = String(request?.input?.content ?? "");
  const target = String(request?.input?.target_style ?? "").trim();

  const original_length = content.length;

  // Minimal deterministic formatter:
  // - if target_style === "table", try parsing "k: v" lines into a markdown table
  // - else return content unchanged with notes
  let formatted_content = content;
  let style = target || "plain";
  let notes = "Deterministic reference formatter (non-LLM).";

  if (target === "table") {
    const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    const pairs = [];
    for (const line of lines) {
      const m = line.match(/^([^:]+):\s*(.*)$/);
      if (m) pairs.push([m[1].trim(), m[2].trim()]);
    }
    if (pairs.length > 0) {
      formatted_content = toMarkdownTableFromPairs(pairs);
      style = "table";
    } else {
      // fallback
      formatted_content = content;
      style = target;
      notes = "No k:v pairs detected; returned content unchanged.";
    }
  }

  const formatted_length = formatted_content.length;

  return {
    ok: true,
    result: {
      formatted_content,
      style,
      original_length,
      formatted_length,
      notes,
    },
  };
}

// ✅ clean (real) — deterministic operations matching your schema
function applyCleanOperations(content, operations = []) {
  let out = String(content ?? "");
  const opsApplied = [];
  const issues = [];

  const addIssue = (s) => {
    if (issues.length >= 128) return;
    issues.push(String(s).slice(0, 256));
  };

  const seen = new Set();
  const ops = Array.isArray(operations) ? operations : [];
  for (const raw of ops) {
    const op = String(raw || "").trim().toLowerCase();
    if (!op) continue;
    if (seen.has(op)) continue;
    seen.add(op);

    switch (op) {
      case "trim": {
        out = out.trim();
        opsApplied.push("trim");
        break;
      }
      case "normalize_newlines": {
        out = out.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
        opsApplied.push("normalize_newlines");
        break;
      }
      case "collapse_whitespace": {
        // collapse runs of spaces/tabs, but keep newlines
        out = out
          .split("\n")
          .map((line) => line.replace(/[ \t]+/g, " ").trimEnd())
          .join("\n");
        opsApplied.push("collapse_whitespace");
        break;
      }
      case "remove_empty_lines": {
        out = out
          .split("\n")
          .map((l) => l.trimEnd())
          .filter((l) => l.trim().length > 0)
          .join("\n");
        opsApplied.push("remove_empty_lines");
        break;
      }
      case "lowercase": {
        out = out.toLowerCase();
        opsApplied.push("lowercase");
        break;
      }
      case "strip_non_ascii": {
        const before = out;
        out = out.replace(/[^\x09\x0A\x0D\x20-\x7E]/g, "");
        if (before !== out) addIssue("non_ascii_stripped");
        opsApplied.push("strip_non_ascii");
        break;
      }
      case "redact_emails": {
        const before = out;
        out = out.replace(
          /([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g,
          "[redacted-email]"
        );
        if (before !== out) addIssue("emails_redacted");
        opsApplied.push("redact_emails");
        break;
      }
      case "redact_phones": {
        const before = out;
        // very rough phone pattern; goal is demo safety, not forensic accuracy
        out = out.replace(
          /(\+?\d{1,3}[\s.-]?)?(\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}/g,
          "[redacted-phone]"
        );
        if (before !== out) addIssue("phones_redacted");
        opsApplied.push("redact_phones");
        break;
      }
      default: {
        // Unknown ops: do not fail; just report
        addIssue(`unknown_operation:${op}`.slice(0, 256));
        break;
      }
    }
  }

  // If no operations provided, still do sane defaults? NO.
  // Your schema allows operations optional; caller chooses.
  return { cleaned: out, opsApplied, issues };
}

async function handle_clean(request) {
  const content = String(request?.input?.content ?? "");
  const operations = request?.input?.operations ?? [];
  const original_length = content.length;

  const { cleaned, opsApplied, issues } = applyCleanOperations(content, operations);

  // Guarantee minLength: 1 in cleaned_content schema
  const cleaned_content = cleaned.length > 0 ? cleaned : " ";

  const cleaned_length = cleaned_content.length;

  const result = {
    cleaned_content,
    original_length,
    cleaned_length,
  };

  if (opsApplied.length > 0) result.operations_applied = opsApplied.slice(0, 32);
  if (issues.length > 0) result.issues_detected = issues.slice(0, 128);

  return { ok: true, result };
}

// 🧱 For verbs you enabled but haven’t built yet
async function handler_stub(_request, verb) {
  return {
    ok: false,
    error: {
      code: "NOT_IMPLEMENTED",
      message: `Verb '${verb}' is enabled but not implemented yet in this runtime.`,
      retryable: false,
    },
  };
}

const HANDLERS = {
  fetch: (req) => handle_fetch(req),
  describe: (req) => handle_describe(req),
  format: (req) => handle_format(req),
  clean: (req) => handle_clean(req),
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
        provider: SERVICE_NAME,
      },
    };

    let receipt;

    if (exec.ok) {
      receipt = {
        status: "success",
        ...base,
        result: exec.result,
      };
    } else {
      receipt = {
        status: "error",
        ...base,
        error: exec.error || { code: "RUNTIME_ERROR", message: "unknown error", retryable: true },
      };
    }

    attachReceiptProofOrThrow(receipt);

    // Validate receipt against verb receipt schema
    if (!schemas.vRcpt(receipt)) {
      return res.status(500).json({
        error: "receipt schema invalid",
        verb,
        details: schemas.vRcpt.errors,
        note: "Handler output does not match this verb’s receipt schema. Fix handler to match the schema.",
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
