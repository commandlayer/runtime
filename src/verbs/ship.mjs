export default async function ship({ body } = {}) {
  const input = body?.input || {};
  return {
    shipment_id: input.shipment_id || "ship_" + String(Date.now()),
    shipment_group_id: input.shipment_group_id || undefined,
    order_id: input.order_id || "order_" + String(Date.now()),
    status: "label_created",
    carrier: input.carrier || "stub_carrier",
    tracking_number: input.tracking_number || "Z999999-TEST",
    tracking_url: input.tracking_url || undefined,
    eta: input.eta || undefined,
    delivered_at: input.delivered_at || undefined,
    metadata: input.metadata || {},
  };
}
