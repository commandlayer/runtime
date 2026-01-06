export function resolveActor(req) {
  const body = req?.body || {};
  const actorId = body?.actor ? String(body.actor) : null;
  const tenantId = body?.x402?.tenant ? String(body.x402.tenant) : null;

  if (actorId) return { id: actorId, role: "user" };
  if (tenantId) return { id: tenantId, role: "tenant" };
  return null;
}
