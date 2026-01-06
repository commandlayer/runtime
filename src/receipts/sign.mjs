import crypto from "crypto";
import { stableStringify } from "../util/stable-json.mjs";
import { fetchEnsPubkeyPem } from "./ens.mjs";
import { getValidatorForVerb, hasValidatorCached, queueWarm, startWarmWorker, ajvErrorsToSimple } from "./schema.mjs";

function pemFromB64(b64) {
  if (!b64) return null;
  const pem = Buffer.from(b64, "base64").toString("utf8");
  return pem.includes("BEGIN") ? pem : null;
}

function signEd25519Base64(messageUtf8) {
  const pem = pemFromB64(process.env.RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64 || "");
  if (!pem) throw new Error("Missing RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64");
  const key = crypto.createPrivateKey(pem);
  const sig = crypto.sign(null, Buffer.from(messageUtf8, "utf8"), key);
  return sig.toString("base64");
}

function verifyEd25519Base64(messageUtf8, signatureB64, pubPem) {
  const key = crypto.createPublicKey(pubPem);
  return crypto.verify(null, Buffer.from(messageUtf8, "utf8"), key, Buffer.from(signatureB64, "base64"));
}

function sha256Hex(str) {
  return crypto.createHash("sha256").update(str).digest("hex");
}

function normalizePem(text) {
  if (!text) return null;
  const pem = String(text).replace(/\\n/g, "\n").trim();
  return pem.includes("BEGIN") ? pem : null;
}

export function makeReceipt({ signer_id, x402, trace, status = "success", result = null, error = null, actor = null, metadata_patch = null }) {
  const receipt = {
    status,
    x402,
    trace,
    ...(error ? { error } : {}),
    ...(status === "success" ? { result } : {}),
    metadata: {
      ...(actor ? { actor } : {}),
      ...(metadata_patch ? metadata_patch : {}),
      proof: {
        alg: "ed25519-sha256",
        canonical: "json-stringify",
        signer_id,
        hash_sha256: null,
        signature_b64: null
      },
      receipt_id: ""
    }
  };

  const unsigned = structuredClone(receipt);
  unsigned.metadata.proof.hash_sha256 = "";
  unsigned.metadata.proof.signature_b64 = "";
  unsigned.metadata.receipt_id = "";

  const canonical = stableStringify(unsigned);
  const hash = sha256Hex(canonical);
  const sigB64 = signEd25519Base64(hash);

  receipt.metadata.proof.hash_sha256 = hash;
  receipt.metadata.proof.signature_b64 = sigB64;
  receipt.metadata.receipt_id = hash;

  return receipt;
}

makeReceipt.verify = async function verifyReceipt({ receipt, wantEns, refresh, wantSchema, schemaHost }) {
  const proof = receipt?.metadata?.proof;
  if (!proof?.signature_b64 || !proof?.hash_sha256) {
    return { ok: false, http_status: 400, error: "missing metadata.proof.signature_b64 or hash_sha256" };
  }

  // recompute hash from unsigned receipt
  const unsigned = structuredClone(receipt);
  unsigned.metadata.proof.hash_sha256 = "";
  unsigned.metadata.proof.signature_b64 = "";
  if (unsigned?.metadata) unsigned.metadata.receipt_id = "";
  const canonical = stableStringify(unsigned);
  const recomputed = sha256Hex(canonical);
  const hashMatches = recomputed === proof.hash_sha256;

  // pick pubkey: env or ENS
  let pubPem = pemFromB64(process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "");
  let pubSrc = pubPem ? "env-b64" : null;

  if (wantEns) {
    const ensOut = await fetchEnsPubkeyPem({ refresh });
    if (ensOut.ok && ensOut.pem) {
      pubPem = ensOut.pem;
      pubSrc = "ens";
    }
  }

  let sigOk = false;
  let sigErr = null;
  if (pubPem) {
    try {
      sigOk = verifyEd25519Base64(proof.hash_sha256, proof.signature_b64, pubPem);
    } catch (e) {
      sigOk = false;
      sigErr = e?.message || "signature verify failed";
    }
  } else {
    sigErr = "no public key available (set RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 or pass ens=1)";
  }

  // schema validation (optional; edge-safe behavior belongs in schema.mjs)
  let schemaOk = true;
  let schemaErrors = null;

  if (wantSchema) {
    schemaOk = false;
    const verb = String(receipt?.x402?.verb || "").trim();
    if (!verb) {
      schemaErrors = [{ message: "missing receipt.x402.verb" }];
    } else if (getValidatorForVerb.cachedOnly() && !hasValidatorCached(verb)) {
      queueWarm(verb);
      startWarmWorker();
      return {
        ok: false,
        http_status: 202,
        retry_after_ms: 1000,
        checks: { schema_valid: false, hash_matches: hashMatches, signature_valid: sigOk },
        errors: { schema_errors: [{ message: "validator_not_warmed_yet" }], signature_error: sigErr },
        values: { verb, claimed_hash: proof.hash_sha256, recomputed_hash: recomputed, pubkey_source: pubSrc }
      };
    } else {
      try {
        const validate = getValidatorForVerb.cachedOnly() ? getValidatorForVerb.peek(verb) : await getValidatorForVerb(verb, schemaHost);
        if (!validate) {
          schemaErrors = [{ message: "validator_missing" }];
        } else {
          const ok = validate(receipt);
          schemaOk = !!ok;
          if (!ok) schemaErrors = ajvErrorsToSimple(validate.errors) || [{ message: "schema validation failed" }];
        }
      } catch (e) {
        schemaErrors = [{ message: e?.message || "schema validation error" }];
      }
    }
  }

  return {
    ok: hashMatches && sigOk && schemaOk,
    checks: { schema_valid: schemaOk, hash_matches: hashMatches, signature_valid: sigOk },
    values: {
      verb: receipt?.x402?.verb ?? null,
      signer_id: proof.signer_id ?? null,
      alg: proof.alg ?? null,
      canonical: proof.canonical ?? null,
      claimed_hash: proof.hash_sha256 ?? null,
      recomputed_hash: recomputed,
      pubkey_source: pubSrc
    },
    errors: { schema_errors: schemaErrors, signature_error: sigErr }
  };
};
