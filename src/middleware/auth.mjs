export function resolveActor(req) {
  const bodyActor = req?.body?.actor;
  if (bodyActor && typeof bodyActor === "string") return { id: bodyActor, role: "user" };

  const tenant = req?.body?.x402?.tenant;
  if (tenant && typeof tenant === "string") return { id: tenant, role: "tenant" };

  return { id: "anonymous", role: "anonymous" };
}
