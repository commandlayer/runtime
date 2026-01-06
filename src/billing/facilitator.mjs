import fs from "fs";
import path from "path";

function nowIso() {
  return new Date().toISOString();
}

function readPricing() {
  const p = path.join(process.cwd(), "src", "billing", "pricing.json");
  const raw = fs.readFileSync(p, "utf8");
  return JSON.parse(raw);
}

// Minimal in-mem usage store: actor+verb -> { dayKey, count }
const usage = new Map();

function dayKeyUTC() {
  const d = new Date();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

export function getPricing() {
  return readPricing();
}

export function meterAndDecide({ actorKey, verb }) {
  const pricing = readPricing();
  const freeCalls = Number(process.env.DEFAULT_DAILY_FREE_CALLS || pricing?.free_tier?.calls_per_day || 0);
  const unitPrice = Number(pricing?.verbs?.[verb]?.unit_price || 0);
  const currency = String(pricing?.currency || "USD");

  const key = `${actorKey || "anon"}::${verb}`;
  const dk = dayKeyUTC();

  const row = usage.get(key) || { dayKey: dk, count: 0 };
  if (row.dayKey !== dk) {
    row.dayKey = dk;
    row.count = 0;
  }
  row.count += 1;
  usage.set(key, row);

  const freeRemaining = Math.max(0, freeCalls - row.count);
  const isFree = row.count <= freeCalls;

  return {
    pricing: { unit_price: unitPrice, currency },
    usage: { day: dk, count_today: row.count, free_remaining: freeRemaining },
    decision: { is_free: isFree, pay_required: !isFree && unitPrice > 0 }
  };
}

// Provider hooks: stubbed now; later Stripe/crypto adapters.
export async function chargeIfNeeded({ decision, verb, pricing, actorKey }) {
  if (!decision?.pay_required) return null;

  // v1 stub: return a fake billing reference
  return {
    provider: process.env.BILLING_PROVIDER || "stub",
    charge_id: `stub_${verb}_${Date.now()}`,
    amount: String(pricing?.unit_price ?? "0"),
    currency: pricing?.currency || "USD",
    ts: nowIso(),
    actor: actorKey || "anon"
  };
}
