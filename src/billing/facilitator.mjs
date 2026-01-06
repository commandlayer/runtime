import fs from "fs";
import path from "path";

const PRICING_PATH = process.env.PRICING_PATH || "src/billing/pricing.json";

export function loadPricing() {
  try {
    const p = path.resolve(process.cwd(), PRICING_PATH);
    const raw = fs.readFileSync(p, "utf8");
    const obj = JSON.parse(raw);
    return obj && typeof obj === "object" ? obj : { currency: "USD", free_tier: { calls_per_day: 0, burst_rps: 0 }, verbs: {} };
  } catch {
    return { currency: "USD", free_tier: { calls_per_day: 0, burst_rps: 0 }, verbs: {} };
  }
}

/**
 * Placeholder: later you’ll move real billing logic here:
 * - choose free vs paid
 * - preauth/charge/refund via provider adapter
 * - persist usage counters (redis)
 */
export async function meterAndBill({ verb, actor, pricing, paid = false } = {}) {
  const unit = 1;
  const currency = pricing?.currency || "USD";
  const price = Number(pricing?.verbs?.[verb]?.unit_price || 0);
  const amount = Number((price * unit).toFixed(6));

  return {
    paid: !!paid,
    billing: paid
      ? { provider: process.env.BILLING_PROVIDER || "none", amount: String(amount), currency }
      : null,
    usage: { verb, units: unit },
  };
}
