import { crockford26 } from "../util/crockford-id.mjs";

export default async function purchase({ body } = {}) {
  const input = body?.input || {};
  return {
    purchase_id: crockford26(),
    status: "success",
    amount: input.amount || { value: "0.00", currency: "USD" },
    settlement: input.settlement || { method: "card", network: "unknown" },
    evidence: input.evidence || { provider_ref: "stub" },
    metadata: input.metadata || {},
  };
}
