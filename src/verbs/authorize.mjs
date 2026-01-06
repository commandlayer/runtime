export default async function authorize({ body, ids }) {
  const input = body?.input || {};
  const checkout_id = input.checkout_id;

  // Minimal demo logic: if missing checkout_id, decline.
  if (!checkout_id) {
    return {
      authorization_id: ids.ulid26(),
      status: "declined",
      reason: "missing_checkout_id",
      metadata: input.metadata || undefined,
    };
  }

  // If provided, treat as authorized and require amount+settlement
  const amount = input.amount;
  const settlement = input.settlement;
  if (!amount || !settlement) {
    return {
      authorization_id: ids.ulid26(),
      checkout_id,
      status: "declined",
      reason: "missing_amount_or_settlement",
      metadata: input.metadata || undefined,
    };
  }

  return {
    authorization_id: ids.ulid26(),
    checkout_id,
    status: "authorized",
    amount,
    settlement,
    expires_at: input.expires_at || undefined,
    evidence: input.evidence || undefined,
    metadata: input.metadata || undefined,
  };
}
