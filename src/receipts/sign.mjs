import crypto from "crypto";

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

export function makeReceipt({ signer_id, x402, trace, result, status = "success", error = null, actor = null, metadata_patch = null } = {}) {
  const receipt = {
    status,
    x402,
    trace,
    ...(error ? { error } : {}),
    ...(status === "success" ? { result } : {}),
    metadata: {
      ...(actor ? { actor } : {}),
      ...(metadata_patch && typeof metadata_patch === "object" ? metadata_patch : {}),
      proof: {
        alg: "ed25519-sha256",
        canonical: "json-stringify",
        signer_id: signer_id || "runtime",
        hash_sha256: null,
        signature_b64: null,
      },
      receipt_id: "",
    },
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

makeReceipt.verify = async function verify({ receipt, wantEns = false, refresh = false } = {}) {
  const proof = receipt?.metadata?.proof;
  if (!proof?.signature_b64 || !proof?.hash_sha256) {
    return { ok: false, http_status: 400, error: "missing metadata.proof.signature_b64 or hash_sha256" };
  }

  const unsigned = structuredClone(receipt);
  unsigned.metadata.proof.hash_sha256 = "";
  unsigned.metadata.proof.signature_b64 = "";
  if (unsigned?.metadata) unsigned.metadata.receipt_id = "";
  const canonical = stableStringify(unsigned);
  const recomputed = sha256Hex(canonical);
  const hashMatches = recomputed === proof.hash_sha256;

  let pubPem = pemFromB64(process.env.RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 || "");
  let pubSrc = pubPem ? "env-b64" : null;

  if (wantEns) {
    const { fetchEnsPubkeyPem } = await import("./ens.mjs");
    const ensOut = await fetchEnsPubkeyPem({ refresh });
    if (ensOut.ok && ensOut.pem) {
      pubPem = ensOut.pem;
      pubSrc = "ens";
    }
  }

  if (!pubPem) {
    return {
      ok: false,
      http_status: 400,
      checks: { hash_matches: hashMatches, signature_valid: false },
      values: { recomputed_hash: recomputed, pubkey_source: pubSrc },
      error: "no public key available (set RECEIPT_SIGNING_PUBLIC_KEY_PEM_B64 or use ens=1)",
    };
  }

  let sigOk = false;
  let sigErr = null;
  try {
    sigOk = verifyEd25519Base64(proof.hash_sha256, proof.signature_b64, pubPem);
  } catch (e) {
    sigOk = false;
    sigErr = e?.message || "signature verify failed";
  }

  return {
    ok: hashMatches && sigOk,
    http_status: hashMatches && sigOk ? 200 : 400,
    checks: { hash_matches: hashMatches, signature_valid: sigOk },
    values: { recomputed_hash: recomputed, pubkey_source: pubSrc },
    errors: { signature_error: sigErr },
  };
};
