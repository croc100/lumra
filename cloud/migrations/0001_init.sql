-- Lumra Cloud — measurement ingest schema (P2 slice 1).
--
-- One row per signed measurement bundle. The bundle digest is the primary key,
-- so replays of the same measurement are idempotent (INSERT OR IGNORE). We keep
-- the full signed bundle verbatim for tamper-evident re-verification, and lift
-- the verdict fields into columns for cheap querying by the dashboard.
--
-- No-log stance: we never store the reporter's IP or any packet content. A
-- measurement is attributed only to the signing key (key_id) the reporter chose
-- to present. Coarse network context (asn/country) is optional and reporter-set.

CREATE TABLE IF NOT EXISTS measurements (
  id            TEXT PRIMARY KEY,   -- bundle digest "sha256:<hex>" (idempotency key)
  key_id        TEXT NOT NULL,      -- SHA256:... fingerprint of the signing public key
  public_key    TEXT NOT NULL,      -- base64 raw Ed25519 public key
  tool          TEXT NOT NULL,
  tool_version  TEXT,
  target        TEXT NOT NULL,
  type          TEXT NOT NULL,      -- verdict type, e.g. SNI_FILTERING
  nature        TEXT NOT NULL,      -- control|surveillance|degradation|fault|none|unknown
  confidence    TEXT,
  attribution   TEXT,
  authority     TEXT,               -- e.g. KCSC, when self-identified
  cause         TEXT,
  asn           TEXT,               -- optional, reporter-supplied network context
  country       TEXT,               -- optional, 2-letter, reporter-supplied
  measured_at   TEXT NOT NULL,      -- RFC3339 UTC, from the signed measurement
  received_at   TEXT NOT NULL,      -- RFC3339 UTC, server receive time
  evidence      TEXT,               -- JSON array of {probe,outcome,detail}
  bundle        TEXT NOT NULL       -- full signed bundle JSON, verbatim
);

CREATE INDEX IF NOT EXISTS idx_measurements_target_time ON measurements (target, measured_at DESC);
CREATE INDEX IF NOT EXISTS idx_measurements_key_time    ON measurements (key_id, measured_at DESC);
CREATE INDEX IF NOT EXISTS idx_measurements_type_time   ON measurements (type, measured_at DESC);
CREATE INDEX IF NOT EXISTS idx_measurements_received    ON measurements (received_at DESC);
