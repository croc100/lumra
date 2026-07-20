/**
 * Lumra Cloud — measurement ingest + query API (P2 slice 1).
 *
 * Reporters (the `lumra` CLI) push signed measurement bundles here; the dashboard
 * reads them back. Trust is cryptographic, not infrastructural: every ingested
 * bundle carries an Ed25519 signature over its canonical measurement bytes, and
 * this Worker verifies that signature before storing anything. We never trust the
 * transport — only the signature.
 *
 * Wire format (v1). To keep signature verification reproducible without
 * re-deriving Go's struct-ordered JSON canonicalization in JS, the reporter sends
 * `measurement` as the VERBATIM canonical bytes it signed, as a JSON string:
 *
 *   {
 *     "measurement": "<canonical JSON string exactly as signed>",
 *     "digest": "sha256:<hex>",
 *     "signature": { "alg": "ed25519", "public_key": "<b64>", "key_id": "SHA256:..", "value": "<b64>" },
 *     "asn": "AS3786",      // optional network context
 *     "country": "KR"        // optional
 *   }
 *
 * The signature is verified over utf8(measurement); the digest is checked over the
 * same bytes; then the string is parsed to lift verdict fields into columns.
 */

export interface Env {
  DB: D1Database;
}

interface Signature {
  alg: string;
  public_key: string;
  key_id: string;
  value: string;
}

interface IngestBody {
  measurement: string;
  digest: string;
  signature: Signature;
  asn?: string;
  country?: string;
}

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "content-type",
};

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...CORS },
  });
}

function b64ToBytes(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function keyIdOf(pub: Uint8Array): Promise<string> {
  return "SHA256:" + (await sha256Hex(pub)).slice(0, 16);
}

/** Verify the Ed25519 signature over the canonical measurement bytes. */
async function verifyBundle(body: IngestBody): Promise<{ ok: true } | { ok: false; error: string }> {
  const sig = body.signature;
  if (!sig || sig.alg !== "ed25519") return { ok: false, error: "unsupported or missing signature alg" };

  let pub: Uint8Array, sigBytes: Uint8Array;
  try {
    pub = b64ToBytes(sig.public_key);
    sigBytes = b64ToBytes(sig.value);
  } catch {
    return { ok: false, error: "invalid base64 in signature" };
  }
  if (pub.length !== 32) return { ok: false, error: "invalid public key length" };
  if (sigBytes.length !== 64) return { ok: false, error: "invalid signature length" };

  if ((await keyIdOf(pub)) !== sig.key_id) return { ok: false, error: "key_id does not match public key" };

  const canonical = new TextEncoder().encode(body.measurement);
  if ("sha256:" + (await sha256Hex(canonical)) !== body.digest) {
    return { ok: false, error: "digest mismatch — measurement was altered" };
  }

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("raw", pub as BufferSource, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    return { ok: false, error: "runtime lacks Ed25519 support" };
  }
  const valid = await crypto.subtle.verify({ name: "Ed25519" }, key, sigBytes as BufferSource, canonical as BufferSource);
  if (!valid) return { ok: false, error: "signature does not verify" };
  return { ok: true };
}

async function handleIngest(req: Request, env: Env): Promise<Response> {
  let body: IngestBody;
  try {
    body = (await req.json()) as IngestBody;
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  if (typeof body.measurement !== "string" || typeof body.digest !== "string") {
    return json({ error: "missing measurement or digest" }, 400);
  }

  const verified = await verifyBundle(body);
  if (!verified.ok) return json({ error: verified.error }, 422);

  // Lift verdict fields from the (now-trusted) measurement.
  let m: any;
  try {
    m = JSON.parse(body.measurement);
  } catch {
    return json({ error: "measurement is not valid JSON" }, 400);
  }
  const v = m.verdict ?? {};
  const asn = typeof body.asn === "string" ? body.asn.slice(0, 32) : null;
  const country = typeof body.country === "string" ? body.country.slice(0, 2).toUpperCase() : null;

  const bundle = JSON.stringify({ measurement: body.measurement, digest: body.digest, signature: body.signature });

  const res = await env.DB.prepare(
    `INSERT OR IGNORE INTO measurements
       (id, key_id, public_key, tool, tool_version, target, type, nature,
        confidence, attribution, authority, cause, asn, country,
        measured_at, received_at, evidence, bundle)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      body.digest,
      body.signature.key_id,
      body.signature.public_key,
      m.tool ?? "lumra",
      m.tool_version ?? null,
      m.target ?? v.target ?? "",
      v.type ?? "INCONCLUSIVE",
      v.nature ?? "unknown",
      v.confidence ?? null,
      v.attribution ?? null,
      v.authority ?? null,
      v.cause ?? null,
      asn,
      country,
      m.measured_at ?? new Date().toISOString(),
      new Date().toISOString(),
      v.evidence ? JSON.stringify(v.evidence) : null,
      bundle,
    )
    .run();

  const deduped = res.meta.changes === 0;
  return json({ id: body.digest, stored: !deduped, deduped }, deduped ? 200 : 201);
}

const COLUMNS =
  "id, key_id, target, type, nature, confidence, attribution, authority, cause, asn, country, measured_at, received_at";

async function handleEvents(url: URL, env: Env): Promise<Response> {
  const target = url.searchParams.get("target");
  const type = url.searchParams.get("type");
  const keyId = url.searchParams.get("key_id");
  const since = url.searchParams.get("since"); // RFC3339
  const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") ?? "100", 10) || 100, 1), 500);

  const where: string[] = [];
  const binds: unknown[] = [];
  if (target) { where.push("target = ?"); binds.push(target); }
  if (type) { where.push("type = ?"); binds.push(type); }
  if (keyId) { where.push("key_id = ?"); binds.push(keyId); }
  if (since) { where.push("measured_at >= ?"); binds.push(since); }
  const clause = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const { results } = await env.DB.prepare(
    `SELECT ${COLUMNS} FROM measurements ${clause} ORDER BY measured_at DESC LIMIT ?`,
  )
    .bind(...binds, limit)
    .all();
  return json({ events: results, count: results.length });
}

/** Per-target rollup for the dashboard: latest verdict + interference counts. */
async function handleTargets(env: Env): Promise<Response> {
  const { results } = await env.DB.prepare(
    `SELECT
       target,
       COUNT(*)                                          AS total,
       SUM(CASE WHEN type != 'OK' THEN 1 ELSE 0 END)     AS interference,
       MAX(measured_at)                                   AS last_seen
     FROM measurements
     GROUP BY target
     ORDER BY last_seen DESC
     LIMIT 500`,
  ).all();
  return json({ targets: results });
}

async function handleBundle(id: string, env: Env): Promise<Response> {
  const row = await env.DB.prepare("SELECT bundle FROM measurements WHERE id = ?").bind(id).first<{ bundle: string }>();
  if (!row) return json({ error: "not found" }, 404);
  return new Response(row.bundle, { headers: { "content-type": "application/json", ...CORS } });
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

    const url = new URL(req.url);
    const path = url.pathname;

    if (path === "/health") return json({ ok: true, service: "lumra-cloud" });
    if (path === "/v1/ingest" && req.method === "POST") return handleIngest(req, env);
    if (path === "/v1/events" && req.method === "GET") return handleEvents(url, env);
    if (path === "/v1/targets" && req.method === "GET") return handleTargets(env);
    if (path.startsWith("/v1/bundle/") && req.method === "GET") {
      return handleBundle(decodeURIComponent(path.slice("/v1/bundle/".length)), env);
    }
    return json({ error: "not found" }, 404);
  },
} satisfies ExportedHandler<Env>;
