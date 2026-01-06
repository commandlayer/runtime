import express from "express";
import crypto from "crypto";

import { makeReceipt } from "./receipts/sign.mjs";
import { loadPricing } from "./billing/facilitator.mjs";
import { applyLimits } from "./middleware/limits.mjs";
import { resolveActor } from "./middleware/auth.mjs";

import authorize from "./verbs/authorize.mjs";
import checkout from "./verbs/checkout.mjs";
import purchase from "./verbs/purchase.mjs";
import ship from "./verbs/ship.mjs";
import verifyVerb from "./verbs/verify.mjs";

const handlers = { authorize, checkout, purchase, ship, verify: verifyVerb };

function nowIso() { return new Date().toISOString(); }
function randId(prefix = "trace_") { return prefix + crypto.randomBytes(6).toString("hex"); }

export function buildApp() {
  const app = express();
  app.use(express.json({ limit: "2mb" }));

  app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
    if (req.method === "OPTIONS") return res.status(204).end();
    next();
  });

  const PORT = Number(process.env.PORT || 8080);
  const SERVICE_NAME = process.env.SERVICE_NAME || "commandlayer-commercial-runtime";
  const SERVICE_VERSION = process.env.SERVICE_VERSION || "1.0.0";
  const API_VERSION = process.env.API_VERSION || "1.0.0";
  const CANONICAL_BASE = (process.env.CANONICAL_BASE_URL || `http://localhost:${PORT}`).replace(/\/+$/, "");

  const ENABLED_VERBS = (process.env.ENABLED_VERBS || "authorize,checkout,purchase,ship,verify")
    .split(",").map((s) => s.trim()).filter(Boolean);

  const SIGNER_ID = process.env.RECEIPT_SIGNER_ID || process.env.ENS_NAME || "commercial-runtime";
  const pricing = loadPricing();

  const enabled = (verb) => ENABLED_VERBS.includes(verb);
  const requireBody = (req, res) => {
    if (!req.body || typeof req.body !== "object") {
      res.status(400).json({ status: "error", code: 400, message: "Invalid JSON body" });
      return false;
    }
    return true;
  };

  async function handleVerb(verb, req, res) {
    if (!enabled(verb)) return res.status(404).json({ status: "error", code: 404, message: `Verb not enabled: ${verb}` });
    if (!handlers[verb]) return res.status(404).json({ status: "error", code: 404, message: `Verb not supported: ${verb}` });
    if (!requireBody(req, res)) return;

    const started = Date.now();
    const trace = {
      trace_id: randId("trace_"),
      started_at: nowIso(),
      completed_at: null,
      duration_ms: null,
      provider: process.env.RAILWAY_SERVICE_NAME || "commercial-runtime",
    };
    const x402 = req.body?.x402 || { verb, version: "1.0.0", entry: `x402://${verb}agent.eth/${verb}/v1.0.0` };

    try {
      const actor = resolveActor(req);
      const limitsDecision = await applyLimits({ req, verb, pricing, actor });

      const result = await handlers[verb]({ body: req.body, actor });

      trace.completed_at = nowIso();
      trace.duration_ms = Date.now() - started;

      const receipt = makeReceipt({
        signer_id: SIGNER_ID,
        x402,
        trace,
        status: "success",
        result,
        actor,
        metadata_patch: {
          usage: { verb, units: 1, duration_ms: trace.duration_ms, ts: nowIso(), path: limitsDecision?.paid ? "paid" : "free" },
          billing: limitsDecision?.billing || null,
          limits: limitsDecision?.limits || null,
        },
      });

      return res.json(receipt);
    } catch (e) {
      trace.completed_at = nowIso();
      trace.duration_ms = Date.now() - started;

      const actor = resolveActor(req);

      const err = {
        code: String(e?.code || "INTERNAL_ERROR"),
        message: String(e?.message || "unknown error").slice(0, 2048),
        retryable: false,
        details: { verb },
      };

      const receipt = makeReceipt({
        signer_id: SIGNER_ID,
        x402,
        trace,
        status: "error",
        error: err,
        actor,
        metadata_patch: { usage: { verb, units: 1, duration_ms: trace.duration_ms, ts: nowIso(), path: "error" } },
      });

      const http = Number(e?.http_status || 500);
      return res.status(http).json(receipt);
    }
  }

  app.get("/", (req, res) => {
    res.json({
      ok: true,
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      api_version: API_VERSION,
      base: CANONICAL_BASE,
      health: "/health",
      pricing: "/.well-known/pricing.json",
      verify: "/verify",
      debug_validators: "/debug/validators",
      verbs: (ENABLED_VERBS || []).map((v) => `/${v}/v${API_VERSION}`),
      time: nowIso(),
    });
  });

  app.get("/health", (req, res) => {
    res.json({
      ok: true,
      service: SERVICE_NAME,
      version: SERVICE_VERSION,
      api_version: API_VERSION,
      port: PORT,
      enabled_verbs: ENABLED_VERBS,
      signer_id: SIGNER_ID,
      time: nowIso(),
    });
  });

  app.get("/.well-known/pricing.json", (req, res) => res.json(pricing));

  app.get("/debug/validators", async (req, res) => {
    try {
      const { debugState } = await import("./receipts/schema.mjs");
      res.json({ ok: true, ...debugState() });
    } catch (e) {
      res.status(500).json({ ok: false, error: e?.message || "debug failed" });
    }
  });

  for (const v of Object.keys(handlers)) {
    app.post(`/${v}/v1.0.0`, (req, res) => handleVerb(v, req, res));
  }

  app.post("/verify", async (req, res) => {
    try {
      const wantEns = String(req.query.ens || "0") === "1";
      const refresh = String(req.query.refresh || "0") === "1";
      const wantSchema = String(req.query.schema || "0") === "1";
      const receipt = req.body;

      const sigOut = await makeReceipt.verify({ receipt, wantEns, refresh });

      let schemaOk = true;
      let schemaErrors = null;

      if (wantSchema) {
        schemaOk = false;
        const { getValidatorForVerb, ajvErrorsToSimple } = await import("./receipts/schema.mjs");
        const verb = String(receipt?.x402?.verb || "").trim();
        if (!verb) {
          schemaErrors = [{ message: "missing receipt.x402.verb" }];
        } else {
          try {
            const validate = await getValidatorForVerb(verb);
            const ok = validate(receipt);
            schemaOk = !!ok;
            if (!ok) schemaErrors = ajvErrorsToSimple(validate.errors) || [{ message: "schema validation failed" }];
          } catch (e) {
            schemaOk = false;
            schemaErrors = [{ message: e?.message || "schema validation error" }];
          }
        }
      }

      const ok = !!sigOut.ok && !!schemaOk;
      return res.status(ok ? 200 : 400).json({
        ok,
        checks: {
          hash_matches: sigOut?.checks?.hash_matches ?? false,
          signature_valid: sigOut?.checks?.signature_valid ?? false,
          schema_valid: schemaOk,
        },
        values: {
          verb: receipt?.x402?.verb ?? null,
          signer_id: receipt?.metadata?.proof?.signer_id ?? null,
          claimed_hash: receipt?.metadata?.proof?.hash_sha256 ?? null,
          recomputed_hash: sigOut?.values?.recomputed_hash ?? null,
          pubkey_source: sigOut?.values?.pubkey_source ?? null,
        },
        errors: {
          signature_error: sigOut?.errors?.signature_error ?? null,
          schema_errors: schemaErrors,
        },
      });
    } catch (e) {
      return res.status(500).json({ ok: false, error: e?.message || "verify failed" });
    }
  });

  return { app, PORT };
}

export function start() {
  const { app, PORT } = buildApp();
  const server = app.listen(PORT, "127.0.0.1", () => {
    console.log(`commercial runtime listening on http://127.0.0.1:${PORT}`);
  });
  server.on("error", (e) => console.error("listen_error:", e?.message || e));
  return server;
}

// If this module is executed directly (node src/server.mjs), start.
if (import.meta.url === new URL(process.argv[1], "file:").href) {
  start();
}
