const state = {
  day: new Map(),   // key -> { date, count }
  rps: new Map(),   // key -> { ts, tokens }
};

function dayKey(actor, verb) {
  return `${actor?.id || "anon"}:${verb}`;
}

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

export async function applyLimits({ req, verb, pricing, actor }) {
  const ft = pricing?.free_tier || { calls_per_day: 0, burst_rps: 0 };
  const key = dayKey(actor, verb);

  // daily counter
  const today = todayStr();
  const cur = state.day.get(key) || { date: today, count: 0 };
  if (cur.date !== today) {
    cur.date = today;
    cur.count = 0;
  }
  cur.count += 1;
  state.day.set(key, cur);

  const freeCalls = Number(ft.calls_per_day || 0);
  const paid = freeCalls > 0 ? cur.count > freeCalls : true;

  // naive RPS (token bucket-ish per second)
  const burst = Number(ft.burst_rps || 0);
  if (burst > 0) {
    const now = Date.now();
    const sec = Math.floor(now / 1000);
    const r = state.rps.get(key) || { sec, count: 0 };
    if (r.sec !== sec) {
      r.sec = sec;
      r.count = 0;
    }
    r.count += 1;
    state.rps.set(key, r);

    if (r.count > burst) {
      const e = new Error("RATE_LIMIT");
      e.code = "RATE_LIMIT";
      e.http_status = 429;
      e.retry_after_ms = 1000;
      throw e;
    }
  }

  const unitPrice = Number(pricing?.verbs?.[verb]?.unit_price || 0);
  const currency = String(pricing?.currency || "USD");

  return {
    paid,
    limits: { calls_per_day: freeCalls, burst_rps: burst, used_today: cur.count },
    billing: paid ? { provider: "none", amount: String(unitPrice), currency } : null,
  };
}
