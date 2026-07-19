# Lumra Roadmap

**"I control my own internet."** — diagnose the cause and type of internet
censorship and interference.

This is Lumra's public roadmap. **v0.1.0 is shipped** — the measurement engine
and CLI are live (`brew install croc100/tap/lumra`). P2/P3 below are directional.

Status legend: ✅ done · 🚧 in progress · ⬜ planned

---

## Milestones at a Glance

| Phase | Theme | Status |
|-------|-------|--------|
| **P0 — Engine** | Local measurement + classification core | ✅ shipped in v0.1.0 |
| **P1 — CLI** | `lumra diagnose <target>` one-shot analysis | ✅ shipped in v0.1.0 |
| **P2 — SaaS** | Hosted dashboard + historical trends | ⬜ planned |
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
