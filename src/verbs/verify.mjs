export default async function verifyVerb({ body } = {}) {
  const input = body?.input || {};
  const target = String(input.target || body?.target || "unknown");
  return {
    target,
    verified: false,
    status: "not_found",
    reason: "stub_verifier",
    metadata: input.metadata || {},
  };
}
