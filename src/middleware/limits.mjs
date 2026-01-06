const DEFAULT_DAILY_FREE_CALLS = Number(process.env.DEFAULT_DAILY_FREE_CALLS || 100);
const DEFAULT_RATE_RPS = Number(process.env.DEFAULT_RATE_RPS || 3);

// ultra-simple in-memory counters (fine for local dev)
const daily = new Map(); // key -> { day, count }
const rps = new Map();   // key -> { tsSec, count }

function dayKey() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth()+1).padStart(2,"0")}-${String(d.getUTCDate()).padStart(2,"0")}`;
}

function keyFor(actor, verb) {
  const a = actor?.id || "anonymous";
  return `${a}::${verb}`;
}

export async function applyLimits({ req, verb, pricing, actor } = {}) {
  const key = keyFor(actor, verb);

  const burst = Number(pricing?.free_tier?.burst_rps || DEFAULT_RATE_RPS);
  const freePerDay = Number(pricing?.free_tier?.calls_per_day || DEFAULT_DAILY_FREE_CALLS);

  // RPS
  const sec = Math.floor(Date.now() / 1000);
  const cur = rps.get(key) || { tsSec: sec, count: 0 };
  if (cur.tsSec !== sec) { cur.tsSec = sec; cur.count = 0; }
  cur.count += 1;
  rps.set(key, cur);

  if (burst > 0 && cur.count > burst) {
    const e = new Error("RATE_LIMIT");
    e.code = "RATE_LIMIT";
    e.http_status = 429;
    e.retry_after_ms = 1000;
    throw e;
  }

  // daily free tier
  const day = dayKey();
  const d = daily.get(key) || { day, count: 0 };
  if (d.day !== day) { d.day = day; d.count = 0; }
  d.count += 1;
  daily.set(key, d);

  const paid = freePerDay > 0 ? d.count > freePerDay : true;

  return {
    paid,
    billing: paid ? { provider: process.env.BILLING_PROVIDER || "none", path: "paid" } : null,
    limits: { calls_today: d.count, free_calls_per_day: freePerDay, burst_rps: burst },
  };
}
