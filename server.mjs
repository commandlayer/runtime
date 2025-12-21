// server.mjs
// CommandLayer reference runtime (commons) — deterministic, schema-valid, receipt-verifiable
// Verbs: fetch, describe, format, clean, parse, summarize, convert, explain
//
// ENV (Railway/shared vars):
//   ENABLED_VERBS=fetch,describe,format,clean,parse,summarize,convert,explain
//   ENS_NAME=runtime.commandlayer.eth
//   VERIFIER_ENS_NAME=runtime.commandlayer.eth
//   SCHEMA_ENS_TEMPLATE={verb}agent.eth
//   ETH_RPC_URL=https://mainnet.infura.io/v3/...
//   RECEIPT_SIGNER_ID=runtime.commandlayer.eth
//   RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64=... (base64 PEM)
//   RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64=... (base64 PEM)
//
// ENS TXT required on {verb}agent.eth at minimum:
//   cl.schema.request = https://commandlayer.org/schemas/v1.0.0/commons/<verb>/requests/<verb>.request.schema.json
//   cl.schema.receipt = https://commandlayer.org/schemas/v1.0.0/commons/<verb>/receipts/<verb>.receipt.schema.json
//
// Optional on verifier ENS (VERIFIER_ENS_NAME):
//   cl.verifier.pubkey_pem = -----BEGIN PUBLIC KEY-----...
//   cl.verifier.alg = ed25519-sha256
//
// Notes:
// - This runtime is deterministic (non-LLM). "max_output_tokens" is treated as max characters.
// - Receipt hashing uses stable JSON canonicalization (sorted keys) -> sha256.
// - Signatures use Ed25519 and are embedded in metadata.proof.signature_b64.

import express from "express";
import cors from "cors";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import crypto from "node:crypto";
import { setTimeout as sleep } from "node:timers/promises";

import { createPublicClient, http, isAddress } from "viem";
import { mainnet } from "viem/chains";
import { normalize } from "viem/ens";

// -------------------------
// env + config
// -------------------------
const PORT = Number(process.env.PORT || 8080);

const ENABLED_VERBS = (process.env.ENABLED_VERBS || "fetch")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const ENS_NAME = (process.env.ENS_NAME || "").trim() || null;
const VERIFIER_ENS_NAME = (process.env.VERIFIER_ENS_NAME || "").trim() || null;
const SCHEMA_ENS_TEMPLATE = (process.env.SCHEMA_ENS_TEMPLATE || "{verb}agent.eth").trim();

const ETH_RPC_URL = (process.env.ETH_RPC_URL || "").trim() || null;

const RECEIPT_SIGNER_ID = (process.env.RECEIPT_SIGNER_ID || "").trim() || (ENS_NAME || "runtime");
const PRIV_PEM_B64 = (process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64 || "").trim() || null;
const PUB_PEM_B64 = (process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "").trim() || null;

// cache TTLs
const VERB_CACHE_TTL_MS = 10 * 60 * 1000; // 10m
const ENSKEY_CACHE_TTL_MS = 10 * 60 * 1000; // 10m

// -------------------------
// utilities
// -------------------------
function nowIso() {
  return new Date().toISOString();
}

function rndId(prefix = "trace") {
  return `${prefix}_${crypto.randomBytes(6).toString("hex")}`;
}

function b64ToUtf8(b64) {
  return Buffer.from(b64, "base64").toString("utf8");
}

function clampText(s, maxChars) {
  if (!maxChars || !Number.isFinite(Number(maxChars))) return s;
  const n = Math.max(1, Number(maxChars));
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}

// stable JSON stringify (sorted keys) — avoids provider-specific ordering issues
function stableStringify(value) {
  const seen = new WeakSet();

  const sorter = (k, v) => {
    if (v && typeof v === "object") {
      if (seen.has(v)) return "[Circular]";
      seen.add(v);
      if (Array.isArray(v)) return v.map((x) => x);
      // sort object keys
      const out = {};
      for (const key of Object.keys(v).sort()) out[key] = v[key];
      return out;
    }
    return v;
  };

  return JSON.stringify(value, sorter);
}

function sha256Hex(str) {
  return crypto.createHash("sha256").update(str, "utf8").digest("hex");
}

function sha256Bytes(str) {
  return crypto.createHash("sha256").update(str, "utf8").digest();
}

function signEd25519(privateKeyPem, messageBytes) {
  // messageBytes should be a Buffer
  const sig = crypto.sign(null, messageBytes, privateKeyPem);
  return sig.toString("base64");
}

function verifyEd25519(publicKeyPem, messageBytes, sigB64) {
  const sig = Buffer.from(sigB64, "base64");
  return crypto.verify(null, messageBytes, publicKeyPem, sig);
}

function envPreviewPem(pem) {
  if (!pem) return null;
  const s = pem.replace(/\r/g, "");
  const firstLine = s.split("\n").slice(0, 2).join("\n");
  return firstLine + "\n…";
}

// -------------------------
// ENS read (viem)
// -------------------------
const hasRpc = !!ETH_RPC_URL;
const publicClient = hasRpc
  ? createPublicClient({
      chain: mainnet,
      transport: http(ETH_RPC_URL, { timeout: 15_000 }),
    })
  : null;

async function ensGetText(name, key) {
  if (!publicClient) throw new Error("ETH_RPC_URL not set");
  const n = normalize(name);
  return await publicClient.getEnsText({ name: n, key });
}

async function ensResolveAddress(name) {
  if (!publicClient) throw new Error("ETH_RPC_URL not set");
  const n = normalize(name);
  return await publicClient.getEnsAddress({ name: n });
}

// -------------------------
// AJV setup
// -------------------------
const ajv = new Ajv2020({
  strict: true,
  allErrors: true,
  allowUnionTypes: true,
  // We're fetching remote schemas ourselves and adding them into AJV.
  loadSchema: async (uri) => {
    const res = await fetch(uri, { headers: { "accept": "application/json" } });
    if (!res.ok) throw new Error(`Failed to load schema: ${uri} (${res.status})`);
    return await res.json();
  },
});
addFormats(ajv);

// -------------------------
// schema + verb cache
// -------------------------
const verbCache = new Map(); // verb -> {mode, ok, ens, reqUrl, rcptUrl, vReq, vRcpt, error, cached_at, expires_at}
const verifierKeyCache = {
  has_key: false,
  cached_at: null,
  expires_at: null,
  last_error: null,
  alg: null,
  signer_id: null,
  pubkey_pem: null,
  pubkey_source: null,
};

function verbEnsName(verb) {
  return SCHEMA_ENS_TEMPLATE.replace("{verb}", verb);
}

async function fetchJson(url) {
  const res = await fetch(url, { headers: { "accept": "application/json" } });
  if (!res.ok) throw new Error(`HTTP ${res.status} for ${url}`);
  return await res.json();
}

async function ensureVerbSchemas(verb, { refresh = false } = {}) {
  const cached = verbCache.get(verb);
  const now = Date.now();
  if (!refresh && cached && cached.expires_at && new Date(cached.expires_at).getTime() > now) {
    return cached;
  }

  const cached_at = nowIso();
  const expires_at = new Date(now + VERB_CACHE_TTL_MS).toISOString();

  // If no ENS, we still allow schemas to be provided by request.x402? not in this reference runtime.
  // This runtime expects ENS TXT records to point at schema URLs.
  const ens = verbEnsName(verb);

  let reqUrl = null;
  let rcptUrl = null;

  try {
    reqUrl = await ensGetText(ens, "cl.schema.request");
    rcptUrl = await ensGetText(ens, "cl.schema.receipt");

    if (!reqUrl || !rcptUrl) {
      const error = `ENS missing schema TXT records on ${ens}`;
      const degraded = {
        mode: "degraded",
        ok: false,
        ens: null,
        reqUrl: null,
        rcptUrl: null,
        vReq: null,
        vRcpt: null,
        error,
        cached_at,
        expires_at,
      };
      verbCache.set(verb, degraded);
      return degraded;
    }

    // Load + compile
    const reqSchema = await fetchJson(reqUrl);
    const rcptSchema = await fetchJson(rcptUrl);

    // Add into AJV with IDs so refs resolve
    ajv.removeSchema(reqUrl);
    ajv.removeSchema(rcptUrl);
    ajv.addSchema(reqSchema, reqUrl);
    ajv.addSchema(rcptSchema, rcptUrl);

    const vReq = await ajv.compileAsync(reqSchema);
    const vRcpt = await ajv.compileAsync(rcptSchema);

    const ready = {
      mode: "ready",
      ok: true,
      ens,
      reqUrl,
      rcptUrl,
      vReq,
      vRcpt,
      error: null,
      cached_at,
      expires_at,
    };
    verbCache.set(verb, ready);
    return ready;
  } catch (e) {
    const degraded = {
      mode: "degraded",
      ok: false,
      ens: null,
      reqUrl: null,
      rcptUrl: null,
      vReq: null,
      vRcpt: null,
      error: String(e?.message || e),
      cached_at,
      expires_at,
    };
    verbCache.set(verb, degraded);
    return degraded;
  }
}

async function ensureVerifierEnsKey({ refresh = false } = {}) {
  const now = Date.now();
  if (!refresh && verifierKeyCache.expires_at && new Date(verifierKeyCache.expires_at).getTime() > now) {
    return verifierKeyCache;
  }

  verifierKeyCache.cached_at = nowIso();
  verifierKeyCache.expires_at = new Date(now + ENSKEY_CACHE_TTL_MS).toISOString();
  verifierKeyCache.last_error = null;
  verifierKeyCache.has_key = false;
  verifierKeyCache.alg = "ed25519-sha256";
  verifierKeyCache.signer_id = VERIFIER_ENS_NAME || null;
  verifierKeyCache.pubkey_pem = null;
  verifierKeyCache.pubkey_source = null;

  if (!VERIFIER_ENS_NAME) {
    verifierKeyCache.last_error = "VERIFIER_ENS_NAME not set";
    return verifierKeyCache;
  }
  if (!publicClient) {
    verifierKeyCache.last_error = "ETH_RPC_URL not set";
    return verifierKeyCache;
  }

  try {
    // First ensure ENS has a resolver
    const addr = await ensResolveAddress(VERIFIER_ENS_NAME);
    // Even if address is null, resolver might exist — but this is a cheap check. We'll still try text records.
    // If addr is null and text read fails, we report resolver issue from text read.
    void addr;

    // Prefer standard key; you can change this later.
    const pub = await ensGetText(VERIFIER_ENS_NAME, "cl.verifier.pubkey_pem");
    const alg = (await ensGetText(VERIFIER_ENS_NAME, "cl.verifier.alg")) || "ed25519-sha256";

    if (!pub) {
      verifierKeyCache.last_error = `Missing cl.verifier.pubkey_pem on ${VERIFIER_ENS_NAME}`;
      return verifierKeyCache;
    }

    verifierKeyCache.has_key = true;
    verifierKeyCache.alg = alg;
    verifierKeyCache.pubkey_pem = pub;
    verifierKeyCache.pubkey_source = "ens";
    return verifierKeyCache;
  } catch (e) {
    // Common failure: no resolver / text read fails
    verifierKeyCache.last_error = String(e?.message || e);
    return verifierKeyCache;
  }
}

// -------------------------
// receipt build + verify
// -------------------------
function getEnvSignerKeys() {
  // sign with env keys
  const privPem = PRIV_PEM_B64 ? b64ToUtf8(PRIV_PEM_B64) : null;
  const pubPem = PUB_PEM_B64 ? b64ToUtf8(PUB_PEM_B64) : null;
  return { privPem, pubPem };
}

function buildReceipt({ verb, version, entry, trace, result, request }) {
  const { privPem } = getEnvSignerKeys();
  if (!privPem) throw new Error("Missing RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64");

  const base = {
    status: "success",
    x402: { entry, verb, version },
    trace,
    result,
    // metadata will be added below
  };

  const canonical = "json-stringify";

  // IMPORTANT: hash should bind the full receipt payload minus the signature itself.
  // We put proof.hash_sha256 + signature_b64 in metadata.proof.
  // To avoid recursion, we compute hash over a copy WITHOUT signature_b64 and WITHOUT hash_sha256.
  const unsigned = structuredClone(base);
  unsigned.metadata = {
    proof: {
      alg: "ed25519-sha256",
      canonical,
      signer_id: RECEIPT_SIGNER_ID,
      // hash_sha256 + signature_b64 filled after hashing/signing
    },
    // optional: echo some safe request hints
    request: {
      actor: request?.actor ?? null,
    },
  };

  // Compute hash over unsigned receipt with empty proof fields removed
  const hashInputObj = structuredClone(unsigned);
  delete hashInputObj.metadata.proof.hash_sha256;
  delete hashInputObj.metadata.proof.signature_b64;

  const canonicalStr = stableStringify(hashInputObj);
  const hashHex = sha256Hex(canonicalStr);
  const sigB64 = signEd25519(privPem, sha256Bytes(canonicalStr));

  // Final receipt
  unsigned.metadata.proof.hash_sha256 = hashHex;
  unsigned.metadata.proof.signature_b64 = sigB64;

  return unsigned;
}

async function verifyReceipt(receipt, { ens = false, refresh = false } = {}) {
  const out = {
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
    errors: { schema_errors: null, signature_error: null },
  };

  try {
    if (!receipt || typeof receipt !== "object") throw new Error("receipt must be JSON object");

    const verb = receipt?.x402?.verb;
    out.values.verb = verb || null;

    const proof = receipt?.metadata?.proof;
    if (!proof?.signature_b64 || !proof?.hash_sha256) {
      throw new Error("missing metadata.proof.signature_b64 or hash_sha256");
    }

    out.values.signer_id = proof.signer_id || null;
    out.values.alg = proof.alg || null;
    out.values.canonical = proof.canonical || null;
    out.values.claimed_hash = proof.hash_sha256 || null;

    // 1) schema validation
    if (!verb || typeof verb !== "string") throw new Error("missing x402.verb");

    const v = await ensureVerbSchemas(verb, { refresh });
    if (!v.ok) throw new Error(`schemas not ready: ${v.error}`);

    const valid = v.vRcpt(receipt);
    if (!valid) {
      out.errors.schema_errors = v.vRcpt.errors || null;
      out.checks.schema_valid = false;
      // still attempt hash/signature to help debug, but keep schema false
    } else {
      out.checks.schema_valid = true;
    }

    // 2) hash recompute
    const unsigned = structuredClone(receipt);
    // remove signature/hash from proof before recomputing
    if (unsigned?.metadata?.proof) {
      delete unsigned.metadata.proof.signature_b64;
      delete unsigned.metadata.proof.hash_sha256;
    }

    const canonicalStr = stableStringify(unsigned);
    const recomputed = sha256Hex(canonicalStr);
    out.values.recomputed_hash = recomputed;
    out.checks.hash_matches = recomputed === proof.hash_sha256;

    // 3) signature verify — choose pubkey from ENS (if ens=1) else env-b64
    let pubPem = null;
    let pubkey_source = null;

    if (ens) {
      const k = await ensureVerifierEnsKey({ refresh });
      if (!k.has_key) throw new Error(k.last_error || "ENS key not available");
      pubPem = k.pubkey_pem;
      pubkey_source = "ens";
    } else {
      const env = getEnvSignerKeys();
      if (!env.pubPem) throw new Error("Missing RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64");
      pubPem = env.pubPem;
      pubkey_source = "env-b64";
    }

    out.values.pubkey_source = pubkey_source;

    const okSig = verifyEd25519(pubPem, sha256Bytes(canonicalStr), proof.signature_b64);
    out.checks.signature_valid = okSig;

    out.ok = out.checks.schema_valid && out.checks.hash_matches && out.checks.signature_valid;
    return out;
  } catch (e) {
    out.ok = false;
    out.errors.signature_error = null;
    return { ...out, error: String(e?.message || e) };
  }
}

// -------------------------
// verb handlers (deterministic)
// -------------------------
async function handle_fetch(req) {
  const input = req?.input || req || {};
  const source = input.source || input.url || input?.input?.source;
  const query = input.query ?? null;
  const include_metadata = input.include_metadata ?? null;

  if (!source || typeof source !== "string") {
    return { ok: false, error: "input.source is required" };
  }

  const res = await fetch(source, { redirect: "follow" });
  const text = await res.text();
  const preview = clampText(text, 1800);

  return {
    ok: true,
    result: {
      items: [
        {
          source,
          query,
          include_metadata,
          ok: res.ok,
          http_status: res.status,
          headers: Object.fromEntries(res.headers.entries()),
          body_preview: preview,
        },
      ],
    },
  };
}

async function handle_describe(req) {
  const input = req?.input || {};
  const subject = String(input.subject || "").trim();
  const audience = input.audience ? String(input.audience).trim() : "general";
  const detail = input.detail_level || "medium";
  const maxOut = req?.limits?.max_output_tokens;

  let description = "";
  if (detail === "short") {
    description = `**${subject}**: a named subject described deterministically for **${audience}**.`;
  } else if (detail === "long") {
    description =
      `**${subject}**: a deterministic reference description produced by a CommandLayer runtime (non-LLM).\n\n` +
      `It returns schema-valid output and a receipt you can verify (schema + hash + signature).`;
  } else {
    description = `**${subject}** described for **${audience}** with stable, deterministic formatting.`;
  }

  const bullets = [
    "Schemas define meaning (requests + receipts).",
    "Runtimes can be swapped without breaking interoperability.",
    "Receipts can be independently verified (hash + signature).",
  ];

  return {
    ok: true,
    result: {
      description: clampText(description, maxOut),
      bullets,
      properties: {
        verb: "describe",
        version: "1.0.0",
        audience,
        detail_level: detail,
      },
    },
  };
}

async function handle_format(req) {
  const input = req?.input || {};
  const content = String(input.content ?? "").toString();
  const target = (input.target_style || "text").toString().toLowerCase();
  const maxOut = req?.limits?.max_output_tokens;

  let formatted = content;
  let style = target;

  if (target === "table") {
    // naive key/value table: parse lines "k: v"
    const lines = content.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    const rows = [];
    for (const l of lines) {
      const m = l.match(/^([^:]+):\s*(.*)$/);
      if (m) rows.push([m[1].trim(), m[2].trim()]);
    }
    formatted = `| key | value |\n|---|---|\n` + rows.map(([k, v]) => `| ${k} | ${v} |`).join("\n");
    style = "table";
  } else if (target === "json_pretty") {
    try {
      const obj = JSON.parse(content);
      formatted = JSON.stringify(obj, null, 2);
      style = "json_pretty";
    } catch {
      formatted = content;
      style = "text";
    }
  } else if (target === "trim") {
    formatted = content.trim();
    style = "trim";
  }

  formatted = clampText(formatted, maxOut);

  return {
    ok: true,
    result: {
      formatted_content: formatted,
      style,
      original_length: content.length,
      formatted_length: formatted.length,
      notes: "Deterministic reference formatter (non-LLM).",
    },
  };
}

async function handle_clean(req) {
  const input = req?.input || {};
  let content = String(input.content ?? "");
  const ops = Array.isArray(input.operations) ? input.operations : [];
  const maxOut = req?.limits?.max_output_tokens;

  const issues = [];

  const normalize_newlines = () => { content = content.replace(/\r\n/g, "\n").replace(/\r/g, "\n"); };
  const collapse_whitespace = () => { content = content.replace(/[ \t]+/g, " "); };
  const trim = () => { content = content.trim(); };
  const remove_empty_lines = () => {
    content = content
      .split("\n")
      .map((l) => l.trimEnd())
      .filter((l) => l.trim().length > 0)
      .join("\n");
  };
  const redact_emails = () => {
    const before = content;
    content = content.replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[redacted-email]");
    if (content !== before) issues.push("emails_redacted");
  };

  const map = {
    normalize_newlines,
    collapse_whitespace,
    trim,
    remove_empty_lines,
    redact_emails,
  };

  const original = content;
  const applied = [];
  for (const op of ops) {
    if (map[op]) {
      map[op]();
      applied.push(op);
    }
  }

  content = clampText(content, maxOut);

  return {
    ok: true,
    result: {
      cleaned_content: content,
      original_length: original.length,
      cleaned_length: content.length,
      operations_applied: applied,
      issues_detected: issues,
    },
  };
}

async function handle_parse(req) {
  const input = req?.input || {};
  const raw = String(input.content ?? "");
  const type = (input.content_type || "").toString().toLowerCase();
  const mode = (input.mode || "best_effort").toString();
  const maxOut = req?.limits?.max_output_tokens;

  let parsed = null;
  let confidence = 0.6;
  const warnings = [];

  const tryJson = () => {
    parsed = JSON.parse(raw);
    confidence = 0.98;
  };

  const tryYamlKV = () => {
    // very naive "k: v" YAML-ish parser
    const obj = {};
    for (const line of raw.split(/\r?\n/)) {
      const l = line.trim();
      if (!l || l.startsWith("#")) continue;
      const m = l.match(/^([^:]+):\s*(.*)$/);
      if (m) obj[m[1].trim()] = m[2].trim();
    }
    parsed = obj;
    confidence = 0.75;
  };

  try {
    if (type === "json") {
      tryJson();
    } else if (type === "yaml") {
      tryYamlKV();
    } else if (type === "csv") {
      // naive CSV -> array of objects (headers first row)
      const rows = raw.split(/\r?\n/).filter(Boolean).map((r) => r.split(","));
      const headers = rows.shift() || [];
      parsed = rows.map((r) => Object.fromEntries(headers.map((h, i) => [h, r[i] ?? ""])));
      confidence = 0.7;
    } else {
      // best-effort
      if (mode === "strict") {
        warnings.push("unknown content_type for strict mode");
        parsed = { raw };
        confidence = 0.4;
      } else {
        try {
          tryJson();
        } catch {
          tryYamlKV();
        }
      }
    }
  } catch (e) {
    if (mode === "strict") throw e;
    parsed = { raw };
    confidence = 0.2;
    warnings.push("parse_failed_best_effort");
  }

  // clamp output size by stringifying and trimming (so receipts stay small)
  const parsedStr = stableStringify(parsed);
  const clampedParsedStr = clampText(parsedStr, maxOut);
  let finalParsed = parsed;
  if (clampedParsedStr !== parsedStr) {
    finalParsed = { _truncated: true, raw: clampedParsedStr };
    warnings.push("parsed_truncated_to_limits");
    confidence = Math.min(confidence, 0.5);
  }

  return {
    ok: true,
    result: {
      parsed: finalParsed,
      confidence,
      ...(warnings.length ? { warnings } : {}),
      ...(input.target_schema ? { target_schema: String(input.target_schema) } : {}),
    },
  };
}

async function handle_summarize(req) {
  const input = req?.input || {};
  const content = String(input.content ?? "");
  const style = (input.summary_style || "text").toString().toLowerCase();
  const format = (input.format_hint || "text").toString().toLowerCase();
  const maxOut = req?.limits?.max_output_tokens;

  // Deterministic "summary": either first N chars or bullet split by sentences
  let summary = "";
  if (style.includes("bullet")) {
    const sentences = content
      .replace(/\s+/g, " ")
      .split(/(?<=[.!?])\s+/)
      .filter(Boolean)
      .slice(0, 6);
    summary = sentences.map((s) => `- ${s}`).join("\n");
  } else {
    summary = content.replace(/\s+/g, " ").trim();
  }

  summary = clampText(summary, maxOut);

  const srcHash = sha256Hex(content);
  const compression_ratio = content.length > 0 ? Math.max(0, content.length / Math.max(1, summary.length)) : 0;

  return {
    ok: true,
    result: {
      summary,
      format: format === "markdown" ? "markdown" : "text",
      compression_ratio: Number.isFinite(compression_ratio) ? compression_ratio : 0,
      source_hash: srcHash,
    },
  };
}

async function handle_convert(req) {
  const input = req?.input || {};
  const content = String(input.content ?? "");
  const source = (input.source_format || "").toString().toLowerCase();
  const target = (input.target_format || "").toString().toLowerCase();
  const maxOut = req?.limits?.max_output_tokens;

  let converted = "";
  const warnings = [];
  let lossy = false;

  // Minimal deterministic conversions:
  if (source === "json" && target === "csv") {
    lossy = true;
    warnings.push("JSON->CSV is lossy (types/nesting may be flattened).");
    try {
      const obj = JSON.parse(content);
      if (Array.isArray(obj)) {
        // array of objects -> csv
        const keys = Array.from(new Set(obj.flatMap((o) => (o && typeof o === "object" ? Object.keys(o) : []))));
        const rows = [keys.join(",")].concat(
          obj.map((o) => keys.map((k) => (o && o[k] != null ? String(o[k]) : "")).join(","))
        );
        converted = rows.join("\n");
      } else if (obj && typeof obj === "object") {
        // object -> key,value csv
        const rows = ["key,value"].concat(Object.entries(obj).map(([k, v]) => `${k},${String(v)}`));
        converted = rows.join("\n");
      } else {
        converted = "value\n" + String(obj);
      }
    } catch {
      converted = content;
      lossy = true;
      warnings.push("invalid_json_input");
    }
  } else if (source === "markdown" && target === "text") {
    lossy = true;
    warnings.push("markdown->text strips formatting.");
    converted = content.replace(/[#*_`>\[\]()!-]/g, "").replace(/\s+/g, " ").trim();
  } else if (source === "html" && target === "text") {
    lossy = true;
    warnings.push("html->text strips tags.");
    converted = content.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
  } else {
    // identity fallback
    converted = content;
    warnings.push("no_conversion_rule_applied; returned input as-is");
  }

  converted = clampText(converted, maxOut);

  return {
    ok: true,
    result: {
      converted_content: converted,
      source_format: source || "unknown",
      target_format: target || "unknown",
      lossy,
      ...(warnings.length ? { warnings } : {}),
    },
  };
}

async function handle_explain(req) {
  const input = req?.input || {};
  const subject = String(input.subject || "").trim();
  const context = input.context ? String(input.context).trim() : "";
  const audience = input.audience ? String(input.audience).trim() : "general";
  const detail = input.detail_level || "medium";
  const style = input.style ? String(input.style).trim().toLowerCase() : "";
  const maxOut = req?.limits?.max_output_tokens;

  let explanation = "";
  if (detail === "short") {
    explanation =
      `**${subject}** explained for **${audience}**: ` +
      `This runtime returns a deterministic explanation based on the request fields and known protocol semantics.`;
  } else if (detail === "long") {
    explanation =
      `**${subject}** explained for **${audience}**:\n\n` +
      `This is a deterministic reference explanation produced by a CommandLayer runtime (non-LLM). ` +
      `It is designed to be schema-valid and receipt-verifiable, not to simulate deep reasoning.\n\n` +
      `What it does:\n` +
      `- Reads your subject (and optional context)\n` +
      `- Applies audience/style/detail hints\n` +
      `- Returns a verifiable receipt (schema + hash + signature)\n\n` +
      `Why that matters:\n` +
      `- Interoperability: meaning is stable across runtimes\n` +
      `- Auditability: receipts are evidence, not logs\n` +
      `- Replaceability: execution can change without breaking semantics`;
  } else {
    explanation =
      `**${subject}** explained for **${audience}**: ` +
      `This runtime produces a structured explanation using your request hints ` +
      `and returns it as a verifiable receipt.`;
  }

  if (context) explanation += `\n\nContext provided:\n${clampText(context, 800)}`;

  const wantsSteps =
    style.includes("step") ||
    style.includes("steps") ||
    style.includes("walk") ||
    detail === "long";

  const steps = wantsSteps
    ? [
        `Identify the subject: "${subject}".`,
        `Apply audience hint: "${audience}".`,
        `Apply style hint: "${style || "none"}" and detail level: "${detail}".`,
        `Generate a deterministic explanation (non-LLM).`,
        `Emit a receipt with hash + signature for independent verification.`,
      ]
    : null;

  const summary = detail !== "short"
    ? `Deterministic explanation for "${subject}" (audience: ${audience}, detail: ${detail}).`
    : null;

  const references = [
    req?.x402?.entry ? String(req.x402.entry) : null,
    "https://commandlayer.org/schemas/v1.0.0/commons/explain/requests/explain.request.schema.json",
    "https://commandlayer.org/schemas/v1.0.0/commons/explain/receipts/explain.receipt.schema.json",
  ].filter(Boolean);

  return {
    ok: true,
    result: {
      explanation: clampText(explanation, maxOut),
      ...(steps ? { steps } : {}),
      ...(summary ? { summary: clampText(summary, Math.min(Number(maxOut || 300), 300)) } : {}),
      ...(references.length ? { references } : {}),
    },
  };
}

// -------------------------
// handler registry
// -------------------------
const HANDLERS = {
  fetch: handle_fetch,
  describe: handle_describe,
  format: handle_format,
  clean: handle_clean,
  parse: handle_parse,
  summarize: handle_summarize,
  convert: handle_convert,
  explain: handle_explain,
};

// -------------------------
// express app
// -------------------------
const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

app.get("/health", (_req, res) => res.status(200).send("ok"));

app.get("/debug/env", async (_req, res) => {
  const { privPem, pubPem } = getEnvSignerKeys();
  res.json({
    ok: true,
    node: process.version,
    cwd: process.cwd(),
    port: PORT,
    service: process.env.RAILWAY_SERVICE_NAME || process.env.SERVICE_NAME || "commandlayer-runtime",
    ens_name: ENS_NAME,
    verifier_ens_name: VERIFIER_ENS_NAME,
    schema_ens_template: SCHEMA_ENS_TEMPLATE,
    has_rpc: !!publicClient,
    enabled_verbs: ENABLED_VERBS,
    signer_id: RECEIPT_SIGNER_ID,
    signer_ok: !!privPem && !!(pubPem || PUB_PEM_B64),
    signer_error: !privPem ? "missing RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64" : (!PUB_PEM_B64 ? "missing RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64" : null),
    has_priv_b64: !!PRIV_PEM_B64,
    has_pub_b64: !!PUB_PEM_B64,
    pub_env_preview: pubPem ? envPreviewPem(pubPem) : null,
    ens_verifier_cache: {
      has_key: verifierKeyCache.has_key,
      cached_at: verifierKeyCache.cached_at,
      expires_at: verifierKeyCache.expires_at,
      last_error: verifierKeyCache.last_error,
    },
  });
});

app.get("/debug/enskey", async (req, res) => {
  const refresh = String(req.query.refresh || "") === "1";
  const k = await ensureVerifierEnsKey({ refresh });
  if (!k.has_key) {
    return res.json({ ok: false, error: k.last_error || "No ENS verifier key" });
  }
  res.json({
    ok: true,
    ens: VERIFIER_ENS_NAME,
    alg: k.alg,
    signer_id: k.signer_id,
    pubkey_source: k.pubkey_source,
    pubkey_preview: envPreviewPem(k.pubkey_pem),
    cached_at: k.cached_at,
    expires_at: k.expires_at,
  });
});

app.get("/debug/verbs", async (req, res) => {
  const refresh = String(req.query.refresh || "") === "1";
  const verbs = {};
  for (const v of ENABLED_VERBS) {
    verbs[v] = await ensureVerbSchemas(v, { refresh });
    // don't leak compiled validators in debug output
    if (verbs[v]?.vReq) verbs[v].vReq = undefined;
    if (verbs[v]?.vRcpt) verbs[v].vRcpt = undefined;
  }
  res.json({ ok: true, verbs });
});

// POST /verify (receipt in body) ; /verify?ens=1 uses VERIFIER_ENS_NAME key
app.post("/verify", async (req, res) => {
  const ens = String(req.query.ens || "") === "1";
  const refresh = String(req.query.refresh || "") === "1";
  const result = await verifyReceipt(req.body, { ens, refresh });
  res.json(result);
});

// generic verb route: POST /<verb>/v1.0.0
app.post("/:verb/v:version", async (req, res) => {
  const verb = String(req.params.verb || "").toLowerCase();
  const version = String(req.params.version || "");

  if (!ENABLED_VERBS.includes(verb)) {
    return res.status(404).json({ error: "verb not enabled", verb });
  }

  // ensure schemas (from ENS) are ready
  const schemas = await ensureVerbSchemas(verb, { refresh: String(req.query.refresh || "") === "1" });
  if (!schemas.ok) {
    return res.status(503).json({
      error: "schemas not ready",
      verb,
      schema: {
        mode: schemas.mode,
        ok: schemas.ok,
        ens: schemas.ens,
        reqUrl: schemas.reqUrl,
        rcptUrl: schemas.rcptUrl,
        error: schemas.error,
        cached_at: schemas.cached_at,
        expires_at: schemas.expires_at,
      },
    });
  }

  // validate request schema
  const body = req.body;
  const okReq = schemas.vReq(body);
  if (!okReq) {
    return res.status(400).json({
      error: "request schema invalid",
      verb,
      details: schemas.vReq.errors || null,
    });
  }

  // basic route/version guard (schema should already enforce, but keep it explicit)
  if (body?.x402?.verb !== verb || body?.x402?.version !== version) {
    return res.status(400).json({
      error: "x402 mismatch",
      expected: { verb, version },
      got: { verb: body?.x402?.verb, version: body?.x402?.version },
    });
  }

  const started = Date.now();
  const trace = {
    trace_id: rndId("trace"),
    started_at: nowIso(),
    completed_at: null,
    duration_ms: null,
    provider: process.env.RAILWAY_SERVICE_NAME || "commandlayer-runtime",
  };

  try {
    const handler = HANDLERS[verb];
    if (!handler) return res.status(500).json({ error: "handler missing", verb });

    // timeouts: best-effort — if timeout_ms exists, we race the handler
    const timeoutMs = Number(body?.limits?.timeout_ms || body?.limits?.max_latency_ms || 0) || 0;

    let handled;
    if (timeoutMs > 0) {
      handled = await Promise.race([
        handler(body),
        (async () => {
          await sleep(timeoutMs);
          return { ok: false, error: "timeout" };
        })(),
      ]);
      if (!handled?.ok) throw new Error(handled?.error || "timeout");
    } else {
      handled = await handler(body);
      if (!handled?.ok) throw new Error(handled?.error || "handler error");
    }

    trace.completed_at = nowIso();
    trace.duration_ms = Date.now() - started;

    const entry = body?.x402?.entry || `x402://${verbEnsName(verb)}/${verb}/v${version}`;
    const receipt = buildReceipt({
      verb,
      version,
      entry,
      trace,
      result: handled.result,
      request: body,
    });

    // validate receipt schema before returning (hard guarantee)
    const okRcpt = schemas.vRcpt(receipt);
    if (!okRcpt) {
      return res.status(500).json({
        error: "internal: generated receipt failed schema",
        verb,
        details: schemas.vRcpt.errors || null,
      });
    }

    return res.json(receipt);
  } catch (e) {
    trace.completed_at = nowIso();
    trace.duration_ms = Date.now() - started;
    return res.status(500).json({
      error: String(e?.message || e),
      verb,
      trace,
    });
  }
});

app.listen(PORT, () => {
  console.log(`[runtime] listening on :${PORT}`);
});
