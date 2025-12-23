*** server.mjs (patch) ***

@@
 import express from "express";
 import crypto from "crypto";
 import Ajv from "ajv";
 import addFormats from "ajv-formats";
 import { ethers } from "ethers";
+import net from "net";

 const app = express();
 app.use(express.json({ limit: "2mb" }));

@@
 const SCHEMA_HOST = (process.env.SCHEMA_HOST || "https://www.commandlayer.org").replace(/\/+$/, "");
 const SCHEMA_FETCH_TIMEOUT_MS = Number(process.env.SCHEMA_FETCH_TIMEOUT_MS || 8000);
 const SCHEMA_VALIDATE_BUDGET_MS = Number(process.env.SCHEMA_VALIDATE_BUDGET_MS || 3500);
+
+// ---- scaling + safety knobs (server-side caps)
+const MAX_JSON_CACHE_ENTRIES = Number(process.env.MAX_JSON_CACHE_ENTRIES || 256);
+const JSON_CACHE_TTL_MS = Number(process.env.JSON_CACHE_TTL_MS || 10 * 60 * 1000);
+const MAX_VALIDATOR_CACHE_ENTRIES = Number(process.env.MAX_VALIDATOR_CACHE_ENTRIES || 128);
+const VALIDATOR_CACHE_TTL_MS = Number(process.env.VALIDATOR_CACHE_TTL_MS || 30 * 60 * 1000);
+const SERVER_MAX_HANDLER_MS = Number(process.env.SERVER_MAX_HANDLER_MS || 12000); // hard cap even if caller doesn't set limits
+const FETCH_TIMEOUT_MS = Number(process.env.FETCH_TIMEOUT_MS || 8000);
+const FETCH_MAX_BYTES = Number(process.env.FETCH_MAX_BYTES || 256 * 1024); // cap preview + protect memory
+const ENABLE_SSRF_GUARD = String(process.env.ENABLE_SSRF_GUARD || "1") === "1";
+const ALLOW_FETCH_HOSTS = (process.env.ALLOW_FETCH_HOSTS || "")
+  .split(",")
+  .map((s) => s.trim().toLowerCase())
+  .filter(Boolean);

 function nowIso() {
   return new Date().toISOString();
 }

@@
 function sha256Hex(str) {
   return crypto.createHash("sha256").update(str).digest("hex");
 }
 
+function sha256HexBytes(buf) {
+  return crypto.createHash("sha256").update(buf).digest("hex");
+}
+
+function isPrivateIp(ip) {
+  // ipv4 only guard (good enough to kill the common SSRF abuse paths)
+  if (!net.isIP(ip)) return false;
+  if (net.isIP(ip) === 6) return true; // treat ipv6 as blocked unless you add explicit handling
+  const parts = ip.split(".").map((n) => Number(n));
+  const [a, b] = parts;
+  if (a === 10) return true;
+  if (a === 127) return true;
+  if (a === 169 && b === 254) return true;
+  if (a === 172 && b >= 16 && b <= 31) return true;
+  if (a === 192 && b === 168) return true;
+  if (a === 0) return true;
+  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
+  return false;
+}
+
+async function resolveARecords(hostname) {
+  // Avoid extra deps; use global DNS via node's built-in resolver
+  const dns = await import("dns/promises");
+  try {
+    const addrs = await dns.resolve4(hostname);
+    return Array.isArray(addrs) ? addrs : [];
+  } catch {
+    return [];
+  }
+}
+
+async function ssrfGuardOrThrow(urlStr) {
+  if (!ENABLE_SSRF_GUARD) return;
+  let u;
+  try {
+    u = new URL(urlStr);
+  } catch {
+    throw new Error("fetch requires a valid absolute URL");
+  }
+  if (!/^https?:$/.test(u.protocol)) throw new Error("fetch only allows http(s)");
+  const host = (u.hostname || "").toLowerCase();
+
+  // Optional allowlist (strongest)
+  if (ALLOW_FETCH_HOSTS.length) {
+    const ok = ALLOW_FETCH_HOSTS.some((h) => host === h || host.endsWith("." + h));
+    if (!ok) throw new Error("fetch host not allowed");
+  }
+
+  // Block obvious metadata targets
+  if (host === "localhost" || host.endsWith(".localhost")) throw new Error("fetch host blocked");
+  if (host === "169.254.169.254") throw new Error("fetch host blocked");
+
+  // Block direct IPs in private ranges
+  if (net.isIP(host) && isPrivateIp(host)) throw new Error("fetch to private IP blocked");
+
+  // Block DNS that resolves to private IPs
+  const addrs = await resolveARecords(host);
+  if (addrs.some(isPrivateIp)) throw new Error("fetch DNS resolves to private IP (blocked)");
+}
+
 function pemFromB64(b64) {
   if (!b64) return null;
   const pem = Buffer.from(b64, "base64").toString("utf8");
   return pem.includes("BEGIN") ? pem : null;
 }
@@
 function signEd25519Base64(messageUtf8) {
   const pem = pemFromB64(PRIV_PEM_B64);
   if (!pem) throw new Error("Missing RECEIPT_SIGNING_PRIVATE_KEY_PEM_B64");
   const key = crypto.createPrivateKey(pem);
   // For Ed25519: algorithm is null
   const sig = crypto.sign(null, Buffer.from(messageUtf8, "utf8"), key);
   return sig.toString("base64");
 }
@@
-function makeReceipt({ x402, trace, result }) {
+function makeReceipt({ x402, trace, result, status = "success", error = null, delegation_result = null, actor = null }) {
   const receipt = {
-    status: "success",
+    status,
     x402,
     trace,
-    result,
+    ...(delegation_result ? { delegation_result } : {}),
+    ...(error ? { error } : {}),
+    ...(status === "success" ? { result } : {}),
     metadata: {
       proof: {
         alg: "ed25519-sha256",
         canonical: "json-stringify",
         signer_id: SIGNER_ID,
         hash_sha256: null,
         signature_b64: null,
       },
     },
   };
 
+  // Optional: stable receipt_id + actor semantics without touching v1.0.0 schemas
+  // - receipt_id is derived from the canonical unsigned receipt (same canonical bytes used for hash)
+  // - actor is stored in metadata.actor (identity schema compatible) or metadata.actor_id string
+  if (actor) receipt.metadata.actor = actor;
+
   // hash/sign after building receipt but BEFORE inserting signature/hash
   const unsigned = structuredClone(receipt);
   unsigned.metadata.proof.hash_sha256 = "";
   unsigned.metadata.proof.signature_b64 = "";
 
   const canonical = stableStringify(unsigned);
   const hash = sha256Hex(canonical);
   const sigB64 = signEd25519Base64(hash);
 
   receipt.metadata.proof.hash_sha256 = hash;
   receipt.metadata.proof.signature_b64 = sigB64;
+
+  // Deterministic receipt identifier (do NOT add top-level field in v1.0.0)
+  // Store in metadata so it stays schema-legal under receipt.base.
+  receipt.metadata.receipt_id = hash;
 
   return receipt;
 }
 
 function makeError(code, message, extra = {}) {
   return { status: "error", code, message, ...extra };
 }
@@
 const schemaJsonCache = new Map(); // url -> { fetchedAt, schema }
 const validatorCache = new Map();  // verb -> { compiledAt, validate }
 const inflightValidator = new Map(); // verb -> Promise<validate>
+
+function cachePrune(map, { ttlMs, maxEntries, tsField = "fetchedAt" } = {}) {
+  const now = Date.now();
+  if (ttlMs && ttlMs > 0) {
+    for (const [k, v] of map.entries()) {
+      const t = v?.[tsField] || 0;
+      if (now - t > ttlMs) map.delete(k);
+    }
+  }
+  if (maxEntries && maxEntries > 0 && map.size > maxEntries) {
+    // delete oldest
+    const entries = Array.from(map.entries()).sort((a, b) => {
+      const ta = a[1]?.[tsField] || 0;
+      const tb = b[1]?.[tsField] || 0;
+      return ta - tb;
+    });
+    const toDelete = entries.slice(0, map.size - maxEntries);
+    for (const [k] of toDelete) map.delete(k);
+  }
+}

@@
 async function fetchJsonWithTimeout(url, timeoutMs) {
   const u = normalizeSchemaFetchUrl(url);
-  const cached = schemaJsonCache.get(u);
-  if (cached) return cached.schema;
+  cachePrune(schemaJsonCache, { ttlMs: JSON_CACHE_TTL_MS, maxEntries: MAX_JSON_CACHE_ENTRIES, tsField: "fetchedAt" });
+  const cached = schemaJsonCache.get(u);
+  if (cached) return cached.schema;
@@
     const schema = await resp.json();
     schemaJsonCache.set(u, { fetchedAt: Date.now(), schema });
     return schema;
   } finally {
     clearTimeout(t);
   }
 }
@@
 async function getValidatorForVerb(verb) {
+  cachePrune(validatorCache, { ttlMs: VALIDATOR_CACHE_TTL_MS, maxEntries: MAX_VALIDATOR_CACHE_ENTRIES, tsField: "compiledAt" });
   // cache hit
   const hit = validatorCache.get(verb);
   if (hit?.validate) return hit.validate;
@@
 async function doFetch(body) {
   const url = body?.source || body?.input?.source || body?.input?.url;
   if (!url || typeof url !== "string") throw new Error("fetch requires source (url)");
-  const resp = await fetch(url, { method: "GET" });
-  const text = await resp.text();
-  const preview = text.slice(0, 2000);
+  await ssrfGuardOrThrow(url);
+
+  const ac = new AbortController();
+  const t = setTimeout(() => ac.abort(), FETCH_TIMEOUT_MS);
+  let resp;
+  try {
+    resp = await fetch(url, { method: "GET", signal: ac.signal });
+  } finally {
+    clearTimeout(t);
+  }
+
+  // stream and cap bytes (prevents OOM + huge responses)
+  const reader = resp.body?.getReader?.();
+  let received = 0;
+  const chunks = [];
+  if (reader) {
+    while (true) {
+      const { value, done } = await reader.read();
+      if (done) break;
+      received += value.byteLength;
+      if (received > FETCH_MAX_BYTES) break;
+      chunks.push(value);
+    }
+  }
+  const buf = chunks.length ? Buffer.concat(chunks.map((u) => Buffer.from(u))) : Buffer.from(await resp.text());
+  const text = buf.toString("utf8");
+  const preview = text.slice(0, 2000);
   return {
     items: [
       {
         source: url,
         query: body?.query ?? null,
         include_metadata: body?.include_metadata ?? null,
         ok: resp.ok,
         http_status: resp.status,
         headers: Object.fromEntries(resp.headers.entries()),
         body_preview: preview,
+        bytes_read: Math.min(received || buf.length, FETCH_MAX_BYTES),
+        truncated: (received || buf.length) > FETCH_MAX_BYTES,
       },
     ],
   };
 }
@@
 async function handleVerb(verb, req, res) {
   if (!enabled(verb)) return res.status(404).json(makeError(404, `Verb not enabled: ${verb}`));
   if (!requireBody(req, res)) return;
 
   const started = Date.now();
   const trace = {
     trace_id: randId("trace_"),
+    parent_trace_id: req.body?.trace?.parent_trace_id || req.body?.x402?.extras?.parent_trace_id || null,
     started_at: nowIso(),
     completed_at: null,
     duration_ms: null,
     provider: process.env.RAILWAY_SERVICE_NAME || "commandlayer-runtime",
   };
 
   try {
     const x402 = req.body?.x402 || { verb, version: "1.0.0", entry: `x402://${verb}agent.eth/${verb}/v1.0.0` };
 
-    const timeoutMs = Number(req.body?.limits?.timeout_ms || req.body?.limits?.max_latency_ms || 0);
+    const callerTimeout = Number(req.body?.limits?.timeout_ms || req.body?.limits?.max_latency_ms || 0);
+    const timeoutMs = Math.min(
+      SERVER_MAX_HANDLER_MS,
+      callerTimeout && callerTimeout > 0 ? callerTimeout : SERVER_MAX_HANDLER_MS
+    );
     const work = Promise.resolve(handlers[verb](req.body));
     const result = timeoutMs
       ? await Promise.race([
           work,
           new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), timeoutMs)),
         ])
       : await work;
 
     trace.completed_at = nowIso();
     trace.duration_ms = Date.now() - started;
 
-    const receipt = makeReceipt({ x402, trace, result });
+    const actor =
+      req.body?.actor
+        ? { id: String(req.body.actor), role: "user" }
+        : (req.body?.x402?.tenant ? { id: String(req.body.x402.tenant), role: "tenant" } : null);
+
+    const receipt = makeReceipt({ x402, trace, result, status: "success", actor });
     return res.json(receipt);
   } catch (e) {
     trace.completed_at = nowIso();
     trace.duration_ms = Date.now() - started;
-    return res.status(500).json(makeError(500, e?.message || "unknown error", { verb, trace }));
+
+    // BIG FIX: schema-legal error receipt (receipt.base compatible)
+    const x402 = req.body?.x402 || { verb, version: "1.0.0", entry: `x402://${verb}agent.eth/${verb}/v1.0.0` };
+    const actor =
+      req.body?.actor
+        ? { id: String(req.body.actor), role: "user" }
+        : (req.body?.x402?.tenant ? { id: String(req.body.x402.tenant), role: "tenant" } : null);
+
+    const err = {
+      code: String(e?.code || "INTERNAL_ERROR"),
+      message: String(e?.message || "unknown error").slice(0, 2048),
+      retryable: String(e?.message || "").includes("timeout"),
+      details: {
+        verb,
+      },
+    };
+
+    const receipt = makeReceipt({ x402, trace, status: "error", error: err, actor });
+    return res.status(500).json(receipt);
   }
 }
@@
 app.get("/debug/validators", (req, res) => {
   res.json({
     ok: true,
     cached: Array.from(validatorCache.keys()),
+    cache_sizes: { schemaJsonCache: schemaJsonCache.size, validatorCache: validatorCache.size },
   });
 });
 
@@
 app.listen(PORT, () => {
   console.log(`runtime listening on :${PORT}`);
 });
