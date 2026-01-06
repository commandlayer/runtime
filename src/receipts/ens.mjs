import { ethers } from "ethers";
import { normalizePem } from "./sign.mjs";

let ensCache = {
  fetched_at: 0,
  ttl_ms: 10 * 60 * 1000,
  pem: null,
  error: null,
  source: null,
};

async function withTimeout(promise, ms, label = "timeout") {
  if (!ms || ms <= 0) return await promise;
  return await Promise.race([promise, new Promise((_, rej) => setTimeout(() => rej(new Error(label)), ms))]);
}

export async function fetchEnsPubkeyPem({
  ETH_RPC_URL,
  VERIFIER_ENS_NAME,
  ENS_PUBKEY_TEXT_KEY,
  refresh = false,
}) {
  const now = Date.now();
  if (!refresh && ensCache.pem && now - ensCache.fetched_at < ensCache.ttl_ms) {
    return { ok: true, pem: ensCache.pem, source: ensCache.source, cache: { ...ensCache } };
  }
  if (!VERIFIER_ENS_NAME) {
    ensCache = { ...ensCache, fetched_at: now, pem: null, error: "Missing VERIFIER_ENS_NAME", source: null };
    return { ok: false, pem: null, source: null, error: ensCache.error, cache: { ...ensCache } };
  }
  if (!ETH_RPC_URL) {
    ensCache = { ...ensCache, fetched_at: now, pem: null, error: "Missing ETH_RPC_URL", source: null };
    return { ok: false, pem: null, source: null, error: ensCache.error, cache: { ...ensCache } };
  }

  try {
    const provider = new ethers.JsonRpcProvider(ETH_RPC_URL);
    const resolver = await withTimeout(provider.getResolver(VERIFIER_ENS_NAME), 6000, "ens_resolver_timeout");
    if (!resolver) throw new Error("No resolver for ENS name");
    const txt = await withTimeout(resolver.getText(ENS_PUBKEY_TEXT_KEY), 6000, "ens_text_timeout");
    const pem = normalizePem(txt);
    if (!pem) throw new Error(`ENS text ${ENS_PUBKEY_TEXT_KEY} missing/invalid PEM`);
    ensCache = { ...ensCache, fetched_at: now, pem, error: null, source: "ens" };
    return { ok: true, pem, source: "ens", cache: { ...ensCache } };
  } catch (e) {
    ensCache = { ...ensCache, fetched_at: now, pem: null, error: e?.message || "ens fetch failed", source: null };
    return { ok: false, pem: null, source: null, error: ensCache.error, cache: { ...ensCache } };
  }
}
