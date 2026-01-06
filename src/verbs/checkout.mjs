import { crockford26 } from "../util/crockford-id.mjs";

export default async function checkout({ body } = {}) {
  const input = body?.input || {};
  return {
    checkout_id: crockford26(),
    status: "created",
    amount: input.amount || { value: "0.00", currency: "USD" },
    settlement: input.settlement || { method: "card", network: "unknown" },
    items: Array.isArray(input.items) && input.items.length ? input.items : [{ sku: "sku_placeholder", quantity: 1, unit_price: { value: "0.00", currency: "USD" } }],
    pricing: input.pricing || undefined,
    expires_at: input.expires_at || new Date(Date.now() + 30 * 60 * 1000).toISOString(),
    next_action: "authorize",
    metadata: input.metadata || {},
  };
}
