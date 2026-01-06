import { ethers } from "ethers";

const ETH_RPC_URL = process.env.ETH_RPC_URL || "";
const VERIFIER_ENS_NAME =
  process.env.VERIFIER_ENS_NAME ||
  process.env.ENS_NAME ||
  process.env.RECEIPT_SIGNER_ID ||
  "";

const ENS_PUBKEY_TEXT_KEY = process.env.ENS_PUBKEY_TEXT_KEY || "cl.receipt.pubkey.pem";

let ensCache = {
  fetched_at: 0,
  ttl_ms: 10 * 60 * 1000,
  pem: null,
  error: null,
  source: null,
};

function normalizePem(text) {
  if (!text) return null;
  const pem = String(text).replace(/\\n/g, "\n").trim();
  return pem.includes("BEGIN") ? pem : null;
}

async function withTimeout(promise, ms, label = "timeout") {
  if (!ms || ms <= 0) return await promise;
  return await Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(label)), ms)),
  ]);
}

export function hasRpc() {
  return !!ETH_RPC_URL;
}

export async function fetchEnsPubkeyPem({ refresh = false } = {}) {
  const now = Date.now();

  if (!refresh && ensCache.pem && now - ensCache.fetched_at < ensCache.ttl_ms) {
    return {
      ok: true,
      pem: ensCache.pem,
      source: ensCache.source,
      ens_name: VERIFIER_ENS_NAME || null,
      txt_key: ENS_PUBKEY_TEXT_KEY,
      cache: { ...ensCache },
    };
  }

  if (!VERIFIER_ENS_NAME) {
    ensCache = { ...ensCache, fetched_at: now, pem: null, error: "Missing VERIFIER_ENS_NAME", source: null };
    return { ok: false, pem: null, source: null, ens_name: null, txt_key: ENS_PUBKEY_TEXT_KEY, error: ensCache.error, cache: { ...ensCache } };
  }

  if (!ETH_RPC_URL) {
    ensCache = { ...ensCache, fetched_at: now, pem: null, error: "Missing ETH_RPC_URL", source: null };
    return { ok: false, pem: null, source: null, ens_name: VERIFIER_ENS_NAME, txt_key: ENS_PUBKEY_TEXT_KEY, error: ensCache.error, cache: { ...ensCache } };
  }

  try {
    const provider = new ethers.JsonRpcProvider(ETH_RPC_URL);
    const resolver = await withTimeout(provider.getResolver(VERIFIER_ENS_NAME), 6000, "ens_resolver_timeout");
    if (!resolver) throw new Error("No resolver for ENS name");

    const txt = await withTimeout(resolver.getText(ENS_PUBKEY_TEXT_KEY), 6000, "ens_text_timeout");
    const pem = normalizePem(txt);
    if (!pem) throw new Error(`ENS text ${ENS_PUBKEY_TEXT_KEY} missing/invalid PEM`);

    ensCache = { ...ensCache, fetched_at: now, pem, error: null, source: "ens" };
    return { ok: true, pem, source: "ens", ens_name: VERIFIER_ENS_NAME, txt_key: ENS_PUBKEY_TEXT_KEY, cache: { ...ensCache } };
  } catch (e) {
    ensCache = { ...ensCache, fetched_at: now, pem: null, error: e?.message || "ens fetch failed", source: null };
    return { ok: false, pem: null, source: null, ens_name: VERIFIER_ENS_NAME, txt_key: ENS_PUBKEY_TEXT_KEY, error: ensCache.error, cache: { ...ensCache } };
  }
}
