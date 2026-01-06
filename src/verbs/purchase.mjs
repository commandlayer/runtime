export default async function purchase({ body, ids }) {
  const input = body?.input || {};

  const amount = input.amount;
  const settlement = input.settlement;

  // For schema: success/pending require amount+settlement.
  if (!amount || !settlement) {
    return {
      purchase_id: ids.ulid26(),
      status: "failed",
      reason: "missing_amount_or_settlement",
      metadata: input.metadata || undefined,
    };
  }

  return {
    purchase_id: ids.ulid26(),
    status: "success",
    amount,
    settlement,
    evidence: input.evidence || undefined,
    metadata: input.metadata || undefined,
  };
}
