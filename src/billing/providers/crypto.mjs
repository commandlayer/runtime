/**
 * Crypto billing provider (stub)
 * - Intended for USDC/ETH capture flows later
 * - For now: throws NOT_CONFIGURED so runtime can boot without crypto enabled.
 */

function notConfigured(op) {
  const e = new Error(`CRYPTO_PROVIDER_NOT_CONFIGURED: ${op}`);
  e.code = "CRYPTO_PROVIDER_NOT_CONFIGURED";
  e.http_status = 501;
  return e;
}

export async function preauth({ actor, amount, currency, metadata } = {}) {
  throw notConfigured("preauth");
}

export async function charge({ actor, amount, currency, metadata } = {}) {
  throw notConfigured("charge");
}

export async function refund({ actor, ref, amount, currency, metadata } = {}) {
  throw notConfigured("refund");
}

export default { preauth, charge, refund };
