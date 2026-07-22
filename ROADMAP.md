# Lumra Roadmap

**"I control my own internet."** — diagnose the cause and type of internet
censorship and interference.

This is Lumra's public roadmap. **v0.2.0 is shipped** — the measurement engine,
CLI, and a live passive cockpit are all out (`brew install croc100/tap/lumra`).
P2/P3 below are directional.

Status legend: ✅ done · 🚧 in progress · ⬜ planned

---

## Milestones at a Glance

| Phase | Theme | Status |
|-------|-------|--------|
| **P0 — Engine** | Local measurement + classification core | ✅ shipped in v0.1.0 |
| **P1 — CLI** | `lumra diagnose <target>` one-shot analysis | ✅ shipped in v0.1.0 |
| **P1.5 — Live & Deep Probes** | Passive cockpit, modern-protocol coverage, evidence bundles, mobile shells | ✅ shipped in v0.2.0 |
| **P2 — SaaS** | Hosted dashboard + historical trends | 🚧 in progress |
| **P3 — Network effect** | Aggregate, opt-in vantage data | ⬜ planned |

---

## P0 — Measurement & Classification Engine

The core: run probes and classify *what kind* of interference is present.

- ✅ DNS analysis — tampering vs. NXDOMAIN injection vs. duplicate-response
  injection; cross-resolver comparison against DoH ground truth, public
  divergence held as info to avoid CDN false positives
- ✅ TLS/SNI probe — SNI-based filtering, RST injection, cert substitution
  (MITM via chain verification against system roots)
- ✅ Connectivity / attribution — TCP reachability, IP-level blocking, and real
  raw-socket RST/TTL hop attribution (in-network vs. destination)
- ✅ Throttling detection — deliberate rate-limiting vs. congestion via relative
  throughput against a capable control path
- ✅ Classification layer — folds raw signals into a labeled verdict +
  confidence + attribution, with a pinned precedence order

**Delivered:** `engine.Diagnose(target)` returns
`{type, cause, confidence, attribution, evidence[]}`.

---

## P1 — CLI

Put the engine in users' hands as a single command.

- ✅ `lumra diagnose <domain|ip>` — one-shot, human-readable verdict
- ✅ Evidence output (why we concluded this) + machine-readable `--json`
- ✅ Shareable self-contained HTML evidence report (`--report`)
- ✅ Browser extension + native-messaging host bridge
- ✅ Multi-resolver / multi-path probing from the user's own vantage point

**Delivered:** cross-platform CLI (`brew install croc100/tap/lumra`), no account
required. Deep RST/TTL attribution needs a raw socket (run elevated).

---

## P1.5 — Live Cockpit & Deep Probes (shipped in v0.2.0)

Past point-in-time diagnosis: continuous, passive, and hard-to-fool sensing.

- ✅ `lumra live` — passive cockpit of every domain your machine touches; TLS
  metadata tracker + SNI parser, ClientHello reassembly across TCP segments,
  IPv6, macOS (BPF) / Linux / Windows (raw) tap backends. Pure-passive by
  default; `--active` opts into confirmation probes.
- ✅ `lumra watch` — continuous monitoring with a blocked-at timeline and
  auto-escalation/drill-down.
- ✅ `lumra serve` — local web cockpit: a serverless, account-free dashboard on
  `127.0.0.1` that drives the same engine from the browser. Diagnose targets,
  one-click evidence export (HTML report, signed bundle, OONI), continuous
  monitoring with a live blocked-at timeline, and the live traffic board — all
  local, no cloud. Built for individual and lab use.
- ✅ Modern-protocol coverage — **QUIC/HTTP-3** block detection (Version
  Negotiation), **ECH** block detection (reset of Encrypted ClientHello),
  **TLS 1.3 downgrade** detection (surveillance signal), and **DoH-blocking**
  resilience (multi-provider pool fallback + block detection).
- ✅ Passive interference detection — DNS-redirect and TLS-MITM caught on the
  wire via handshake reassembly + cert-chain check, with attribution/authority
  and site-down disambiguation.
- ✅ Un-foolable detection arc — provenance-precise RST detection (kernel truth,
  not text matching), repeated-trial robustness (catches probabilistic blocking,
  kills false positives), and un-fingerprintable rotating control SNI.
- ✅ Signed evidence — Ed25519-signed, tamper-evident measurement bundles
  (`--bundle`) + OONI export (`--ooni`) and `lumra verify`.
- ✅ Mobile — standalone iOS/Android monitoring app shells + a gomobile-bindable
  Cockpit facade (observe-only; circumvention stays in [Warren](https://github.com/croc100/warren)).

**Delivered:** verdict taxonomy now spans OK, DNS_TAMPERING, SNI_FILTERING,
RST_INJECTION, IP_BLOCKING, TLS_MITM, TLS_DOWNGRADE, ECH_BLOCKING, DOH_BLOCKING,
QUIC_BLOCKING, BLOCK_PAGE, THROTTLING, LOCAL_ISSUE, GENUINE_OUTAGE, INCONCLUSIVE —
each folded to a control / surveillance / degradation / fault nature.

---

## P2 — Hosted SaaS

Turn point-in-time diagnosis into ongoing visibility.

- ⬜ Hosted dashboard — interference events over time, per network/ISP
- ⬜ Scheduled monitoring of user-selected targets
- ⬜ Alerts when a target's reachability/interference profile changes
- ⬜ Accounts, org spaces, retention tiers

**Deliverable:** `lumra.crode.net` hosted product.

---

## P3 — Aggregate Vantage Network (opt-in)

- ⬜ Opt-in sharing of anonymized interference measurements
- ⬜ Cross-vantage confirmation — distinguish "blocked for me" from
  "blocked country-wide"
- ⬜ Public country/ISP interference view (privacy-preserving aggregates)

Aligns with [Warren](https://github.com/croc100/warren)'s Independence Logger —
Lumra consumes and complements Warren's aggregate, opt-in censorship statistics.

---

## Non-Goals

- Not a VPN or a circumvention tool (that's Warren). Lumra *diagnoses*; it does
  not route around blocks.
- No packet-content logging. Analysis is metadata- and behavior-based, in line
  with CRODE's no-log stance.
