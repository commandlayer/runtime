export default async function checkout({ body, ids }) {
  const input = body?.input || {};
  const amount = input.amount;
  const settlement = input.settlement;
  const items = input.items;

  if (!amount || !settlement || !Array.isArray(items) || items.length < 1) {
    const e = new Error("checkout.input requires amount, settlement, items[]");
    e.code = "BAD_REQUEST";
    throw e;
  }

  return {
    checkout_id: ids.ulid26(),
    status: "created",
    amount,
    settlement,
    items,
    pricing: input.pricing || undefined,
    expires_at: input.expires_at || undefined,
    next_action: "authorize",
    metadata: input.metadata || undefined,
  };
}
