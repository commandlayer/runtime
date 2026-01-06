import { crockford26 } from "../util/crockford-id.mjs";

export default async function authorize({ body } = {}) {
  const input = body?.input || {};
  const status = "authorized";
  return {
    authorization_id: crockford26(),
    checkout_id: input.checkout_id || crockford26(),
    status,
    amount: input.amount || { value: "0.00", currency: "USD" },
    settlement: input.settlement || { method: "card", network: "unknown" },
    expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString(),
    metadata: input.metadata || {},
  };
}
