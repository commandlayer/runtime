export default async function ship({ body }) {
  const input = body?.input || {};
  const order_id = input.order_id;

  if (!order_id) {
    return {
      shipment_id: String(input.shipment_id || "ship_missing_order"),
      order_id: "missing",
      status: "failed",
      metadata: input.metadata || undefined,
    };
  }

  const carrier = input.carrier || "carrier";
  const tracking_number = input.tracking_number || "TRK12345";

  return {
    shipment_id: String(input.shipment_id || `ship_${Date.now()}`),
    shipment_group_id: input.shipment_group_id || undefined,
    order_id,
    status: input.status || "label_created",
    carrier,
    tracking_number,
    tracking_url: input.tracking_url || undefined,
    eta: input.eta || undefined,
    delivered_at: input.delivered_at || undefined,
    metadata: input.metadata || undefined,
  };
}
