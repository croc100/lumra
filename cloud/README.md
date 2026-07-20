# Lumra Cloud (P2)

Hosted ingest + query API for Lumra measurements. Cloudflare Workers + D1 — free
tier, serverless, global edge. Trust is cryptographic: every measurement is an
Ed25519-signed bundle, verified at ingest before storage. No IPs, no packet
content — a measurement is attributed only to the signing key the reporter chose.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/v1/ingest` | Submit a signed measurement bundle (see wire format below) |
| `GET`  | `/v1/events?target=&type=&key_id=&since=&limit=` | List measurement events |
| `GET`  | `/v1/targets` | Per-target rollup: total, interference count, last seen |
| `GET`  | `/v1/bundle/:id` | The verbatim signed bundle for a measurement (id = digest) |
| `GET`  | `/health` | Liveness |

### Ingest wire format (v1)

`measurement` is the **verbatim canonical bytes the reporter signed**, as a JSON
string — so the Worker verifies the Ed25519 signature over exactly those bytes
without re-deriving Go's struct-ordered JSON canonicalization in JS.

```json
{
  "measurement": "{\"bundle_version\":\"1\",\"tool\":\"lumra\",...}",
  "digest": "sha256:<hex>",
  "signature": { "alg": "ed25519", "public_key": "<b64>", "key_id": "SHA256:..", "value": "<b64>" },
  "asn": "AS3786",
  "country": "KR"
}
```

The `lumra` CLI push path (next slice) produces this directly from a `--bundle`.

## Local development

```sh
cd cloud
npm install
wrangler d1 create lumra            # copy database_id into wrangler.jsonc
npm run migrate:local
npm run dev                          # http://localhost:8787
```

## Deploy

```sh
npm run migrate:remote
npm run deploy                       # publishes the Worker
```

## Idempotency

The bundle digest is the primary key, so re-submitting the same measurement is a
no-op (`INSERT OR IGNORE`); the response reports `deduped: true`.
