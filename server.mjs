// server.mjs
import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { JsonRpcProvider } from "ethers";

const app = express();
app.use(express.json({ limit: "2mb" }));

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

// IMPORTANT: keep www to avoid 307 issues
const SCHEMA_HOST = process.env.SCHEMA_HOST || "https://www.commandlayer.org";

const ENS_CACHE_TTL_MS = Number(process.env.ENS_CACHE_TTL_MS || 600_000);
const SCHEMA_CACHE_TTL_MS = Number(process.env.SCHEMA_CACHE_TTL_MS || 600_000);

const SCHEMA_FETCH_TIMEOUT_MS = Number(
  process.env.SCHEMA_FETCH_TIMEOUT_MS || 8000
);

// Hard cap for *entire* schema validation phase so /verify never 502s
const SCHEMA_VALIDATE_BUDGET_MS = Number(
  process.env.SCHEMA_VALIDATE_BUDGET_MS || 3500
);

function nowIso() {
  return new Date().toISOString();
}

function randId(prefix = "trace_") {
  return prefix + crypto.randomBytes(6).toString("hex");
}

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

function normalizePem(maybePem) {
  if (!maybePem) return null;
  let s = String(maybePem).trim();
  s = s.replace(/\\n/g, "\n");
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
  const sig = crypto.sign(null, Buffer.from(messageUtf8, "utf8"), key);
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

function withTimeoutPromise(p, ms, label = "timeout") {
  return Promise.race([
    p,
    new Promise((_, rej) => setTimeout(() => rej(new Error(label)), ms)),
  ]);
}

async function fetchJsonWithTimeout(url) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), SCHEMA_FETCH_TIMEOUT_MS);
  try {
    const r = await fetch(url, { method: "GET", signal: controller.signal });
    if (!r.ok) throw new Error(`schema fetch failed ${r.status} for ${url}`);
    return await r.json();
  } finally {
    clearTimeout(t);
  }
}

// ---------------- ENS

const ensCache = {
  fetched_at: null,
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

// ------------- AJV (SAFE MODE)

const schemaCache = new Map(); // url -> { fetched_at, json }
const validatorCache = new Map(); // verb -> validateFn
const inflight = new Map(); // verb -> Promise

const ajv = new Ajv({
  strict: false,
  allErrors: true,
});
addFormats(ajv);

function receiptSchemaUrlForVerb(verb) {
  return `${SCHEMA_HOST}/schemas/v1.0.0/commons/${verb}/receipts/${verb}.receipt.schema.json`;
}

async function getSchemaJson(url) {
  const now = Date.now();
  const cached = schemaCache.get(url);
  if (cached && now - cached.fetched_at < SCHEMA_CACHE_TTL_MS) return cached.json;

  const json = await fetchJsonWithTimeout(url);
  schemaCache.set(url, { fetched_at: now, json });
  return json;
}

/**
 * SAFE validator compilation:
 * - fetch the verb receipt schema JSON
 * - compile it synchronously (no compileAsync)
 * NOTE: This assumes your published receipt schemas use absolute $ref URLs
 * that Ajv can resolve from its in-memory schema pool OR not at all.
 * If $refs exist, we still avoid hangs by time-budgets (we fail fast).
 */
async function getReceiptValidatorForVerbSafe(verb) {
  if (validatorCache.has(verb)) return validatorCache.get(verb);
  if (inflight.has(verb)) return inflight.get(verb);

  const p = (async () => {
    const url = receiptSchemaUrlForVerb(verb);

    // fetch within budget
    const schema = await getSchemaJson(url);

    // Add the root schema under its $id so $ref can match if needed
    if (schema?.$id) {
      try { ajv.addSchema(schema, schema.$id); } catch {}
    }

    // compile synchronously — cannot hang
    const validate = ajv.compile(schema);

    validatorCache.set(verb, validate);
    inflight.delete(verb);
    return validate;
  })().catch((e) => {
    inflight.delete(verb);
    throw e;
  });

  inflight.set(verb, p);
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
    schema_validate_budget_ms: SCHEMA_VALIDATE_BUDGET_MS,
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
    cache: {
      fetched_at: out.fetched_at ? new Date(out.fetched_at).toISOString() : null,
      ttl_ms: ENS_CACHE_TTL_MS,
    },
    preview,
    error: out.error || null,
  });
});

app.get("/debug/validators", (req, res) => {
  res.json({
    ok: true,
    cached: Array.from(validatorCache.keys()).map((verb) => ({ verb })),
  });
});

app.get("/debug/schemafetch", async (req, res) => {
  const verb = String(req.query.verb || "").trim();
  if (!verb) return res.status(400).json(makeError(400, "missing ?verb="));
  const url = receiptSchemaUrlForVerb(verb);
  try {
    const schema = await getSchemaJson(url);
    res.json({ ok: true, url, id: schema?.$id || null, hasRefs: !!schema?.allOf || !!schema?.$ref });
  } catch (e) {
    res.status(500).json({ ok: false, url, error: e?.message || "fetch failed" });
  }
});

// ---- verbs (same as before, trimmed here to keep focus)
// IMPORTANT: Keep your existing verb handlers as-is in your repo.
// If you want, I’ll re-expand them, but you already have them working.

const handlers = {}; // placeholder so file parses if you paste only this block
// --- YOU ALREADY HAVE WORKING handlers in your current file ---
// Don't delete them. Keep your current verb implementations.
// The only section that matters for this fix is /verify schema=1 safe mode.

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

// ---- VERIFY

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

    const unsigned = structuredClone(receipt);
    unsigned.metadata.proof.hash_sha256 = "";
    unsigned.metadata.proof.signature_b64 = "";
    const canonical = stableStringify(unsigned);
    const recomputed = sha256Hex(canonical);
    const hashMatches = recomputed === proof.hash_sha256;

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

    const wantSchema = String(req.query.schema || "") === "1";
    let schemaValid = true;
    let schemaErrors = null;

    if (wantSchema) {
      // HARD BUDGET so this NEVER causes 502
      try {
        await withTimeoutPromise(
          (async () => {
            const verb = String(receipt?.x402?.verb || "").trim();
            if (!verb) throw new Error("missing x402.verb");

            const validate = await getReceiptValidatorForVerbSafe(verb);
            const ok = validate(receipt);

            schemaValid = !!ok;
            schemaErrors = ok
              ? null
              : (validate.errors || []).map((e) => ({
                  instancePath: e.instancePath,
                  schemaPath: e.schemaPath,
                  keyword: e.keyword,
                  message: e.message,
                  params: e.params,
                }));
          })(),
          SCHEMA_VALIDATE_BUDGET_MS,
          `schema_validation_budget_exceeded ${SCHEMA_VALIDATE_BUDGET_MS}ms`
        );
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
