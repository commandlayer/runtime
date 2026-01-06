export default async function verify({ body }) {
  const input = body?.input || {};
  const target = String(input.target || "");
  if (!target) {
    return { target: "missing", verified: false, status: "not_found", reason: "missing_target" };
  }

  // deterministic demo: if target contains "ok" => verified
  const verified = target.toLowerCase().includes("ok");
  return {
    target,
    verified,
    status: verified ? "success" : "failed",
    amount: input.amount || undefined,
    settlement: input.settlement || undefined,
    evidence: input.evidence || undefined,
    reason: verified ? undefined : (input.reason || "not_verified"),
    metadata: input.metadata || undefined,
  };
}
