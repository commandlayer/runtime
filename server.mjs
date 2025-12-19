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
const SCHEMA_ENS_TEMPLATE = process.env.SCHEMA_ENS_TEMPLATE?.trim() || "{verb}agent.eth";

const ENS_NAME = process.env.ENS_NAME?.trim() || null;
const VERIFIER_ENS_NAME = process.env.VERIFIER_ENS_NAME?.trim() || ENS_NAME;
const ETH_RPC_URL = process.env.ETH_RPC_URL?.trim() || null;

const ENV_REQ_URL = process.env.SCHEMA_REQUEST_URL?.trim() || null;
const ENV_RCPT_URL = process.env.SCHEMA_RECEIPT_URL?.trim() || null;

const PORT = Number(process.env.PORT || 8080);
const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 8000);
const ENS_CACHE_TTL_MS = Number(process.env.ENS_CACHE_TTL_MS || 10 * 60 * 1000);

const ENABLED_VERBS = (process.env.ENABLED_VERBS?.trim() || "fetch,clean")
  .split(",")
  .map(v => v.trim())
  .filter(Boolean);

/* -------------------- helpers -------------------- */

const id = (p) => `${p}_${crypto.randomBytes(6).toString("hex")}`;
const sha256Hex = (s) => crypto.createHash("sha256").update(s).digest("hex");
const canonicalJson = (o) => JSON.stringify(o);

function readPemB64Env(name) {
  const b64 = process.env[name]?.trim();
  if (!b64) return null;
  return Buffer.from(b64, "base64").toString("utf8").trim();
}

function recomputeReceiptHash(receipt) {
  const clone = structuredClone(receipt);
  if (clone?.metadata?.proof) delete clone.metadata.proof;
  if (clone?.metadata && Object.keys(clone.metadata).length === 0) delete clone.metadata;
  return sha256Hex(canonicalJson(clone));
}

function signEd25519(hashHex) {
  const pem = readPemB64Env("RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64");
  if (!pem) throw new Error("Missing RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64");
  return crypto.sign(null, Buffer.from(hashHex, "hex"), { key: pem }).toString("base64");
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
  return receipt;
}

const verifyEd25519 = (h, s, p) =>
  crypto.verify(null, Buffer.from(h, "hex"), { key: p }, Buffer.from(s, "base64"));

const blocked = (url) => {
  try {
    const u = new URL(url);
    return !["http:", "https:"].includes(u.protocol) ||
      /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|169\.254\.|.*\.local$)/.test(u.hostname);
  } catch { return true; }
};

const ensForVerb = (v) => SCHEMA_ENS_TEMPLATE.replaceAll("{verb}", v);

/* -------------------- ENS helpers -------------------- */

const getProvider = async () => new ethers.JsonRpcProvider(ETH_RPC_URL);

async function getResolver(name) {
  const r = await (await getProvider()).getResolver(name);
  if (!r) throw new Error(`No resolver for ${name}`);
  return r;
}

async function resolveSchemasFromENS(verb) {
  const r = await getResolver(ensForVerb(verb));
  return {
    reqUrl: await r.getText("cl.schema.request"),
    rcptUrl: await r.getText("cl.schema.receipt")
  };
}

async function resolveVerifierKeyFromENS() {
  const r = await getResolver(VERIFIER_ENS_NAME);
  const pub = await r.getText("cl.receipt.pubkey_pem");
  if (!pub) throw new Error("Missing cl.receipt.pubkey_pem");
  return { pubkey_pem: pub.replace(/\\n/g, "\n").trim() };
}

/* -------------------- schema cache -------------------- */

const verbSchemas = new Map();

async function loadVerbSchemas(verb) {
  if (verbSchemas.has(verb)) return verbSchemas.get(verb);

  const { reqUrl, rcptUrl } = ENV_REQ_URL && ENV_RCPT_URL
    ? { reqUrl: ENV_REQ_URL, rcptUrl: ENV_RCPT_URL }
    : await resolveSchemasFromENS(verb);

  const ajv = new Ajv2020({ strict: true, loadSchema: u => fetch(u).then(r => r.json()) });
  addFormats(ajv);

  const vReq = await ajv.compileAsync(await (await fetch(reqUrl)).json());
  const vRcpt = await ajv.compileAsync(await (await fetch(rcptUrl)).json());

  const out = { vReq, vRcpt };
  verbSchemas.set(verb, out);
  return out;
}

/* -------------------- CLEAN handler -------------------- */

function applyCleanOps(content, ops = []) {
  let out = content;
  const applied = [];
  const issues = [];

  for (const op of ops || []) {
    switch (op) {
      case "trim": out = out.trim(); applied.push(op); break;
      case "normalize_whitespace": out = out.replace(/\s+/g, " "); applied.push(op); break;
      case "collapse_newlines": out = out.replace(/\n{3,}/g, "\n\n"); applied.push(op); break;
      case "strip_html": out = out.replace(/<[^>]*>/g, ""); applied.push(op); break;
      default: issues.push(`UNKNOWN:${op}`);
    }
  }

  if (!out) out = content || " ";
  return { out, applied, issues };
}

async function handle_clean(req) {
  const c = req.input?.content;
  if (!c) {
    return {
      ok: false,
      error: { code: "BAD_INPUT", message: "content required", retryable: false },
      result: { cleaned_content: " " }
    };
  }

  const { out, applied, issues } = applyCleanOps(c, req.input?.operations);
  return {
    ok: true,
    result: {
      cleaned_content: out,
      operations_applied: applied,
      issues_detected: issues.length ? issues : undefined,
      original_length: c.length,
      cleaned_length: out.length
    }
  };
}

/* -------------------- handlers -------------------- */

async function handle_fetch(req) {
  const url = req.source;
  if (blocked(url)) {
    return { ok: false, error: { code: "BAD_SOURCE", message: "blocked", retryable: false } };
  }
  const r = await fetch(url);
  return { ok: true, result: { items: [{ source: url, ok: r.ok, body_preview: (await r.text()).slice(0, 2000) }] } };
}

const HANDLERS = {
  fetch: handle_fetch,
  clean: handle_clean
};

/* -------------------- runtime route -------------------- */

app.post("/:verb/v1.0.0", async (req, res) => {
  const verb = req.params.verb;
  if (!ENABLED_VERBS.includes(verb)) return res.status(404).json({ error: "unknown verb" });

  const { vReq, vRcpt } = await loadVerbSchemas(verb);
  if (!vReq(req.body)) return res.status(400).json({ error: "bad request", details: vReq.errors });

  const exec = await HANDLERS[verb](req.body);
  const receipt = {
    status: exec.ok ? "success" : "error",
    x402: req.body.x402,
    trace: { trace_id: id("trace"), started_at: new Date().toISOString(), provider: SERVICE_NAME },
    ...(exec.result ? { result: exec.result } : {}),
    ...(exec.error ? { error: exec.error } : {})
  };

  attachReceiptProofOrThrow(receipt);

  if (!vRcpt(receipt)) {
    return res.status(500).json({ error: "receipt schema invalid", details: vRcpt.errors });
  }

  res.json(receipt);
});

/* -------------------- verify -------------------- */

app.post("/verify", async (req, res) => {
  const r = req.body;
  const hash = recomputeReceiptHash(r);
  const k = await resolveVerifierKeyFromENS();
  res.json({
    ok: true,
    checks: {
      hash_matches: hash === r.metadata.proof.hash_sha256,
      signature_valid: verifyEd25519(hash, r.metadata.proof.signature_b64, k.pubkey_pem)
    }
  });
});

/* -------------------- start -------------------- */

app.listen(PORT, "0.0.0.0", () => console.log(`listening on ${PORT}`));
