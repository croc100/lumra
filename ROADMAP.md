# Lumra Roadmap

**"I control my own internet."** — diagnose the cause and type of internet
censorship and interference.

This is Lumra's public roadmap. The product concept is confirmed; specifics
below are directional and will tighten as the measurement engine lands.

Status legend: ✅ done · 🚧 in progress · ⬜ planned

---

## Milestones at a Glance

| Phase | Theme | Gate to next phase |
|-------|-------|--------------------|
| **P0 — Engine** | Local measurement + classification core | Reliably distinguishes block-type on known cases |
| **P1 — CLI** | `lumra diagnose <target>` one-shot analysis | Actionable verdict with evidence, no false "it's blocked" |
| **P2 — SaaS** | Hosted dashboard + historical trends | Users can see interference over time per network |
| **P3 — Network effect** | Aggregate, opt-in vantage data | Cross-vantage confirmation of country-level events |

---

## P0 — Measurement & Classification Engine

The core: run probes and classify *what kind* of interference is present.

- ⬜ DNS analysis — poisoning / tampering vs. NXDOMAIN vs. misconfig
  (compare resolvers, DoH/DoT ground truth, TTL/answer anomalies)
- ⬜ TLS/SNI probe — SNI-based filtering, RST injection, cert substitution (MITM)
- ⬜ Connectivity probe — TCP reachability, packet loss, RST timing signatures
- ⬜ Throttling detection — deliberate rate-limiting vs. congestion
- ⬜ Classification layer — turn raw signals into a labeled verdict + confidence

**Deliverable:** a library that takes a target and returns
`{interference_type, cause, confidence, evidence[]}`.

---

## P1 — CLI

Put the engine in users' hands as a single command.

- ⬜ `lumra diagnose <domain|ip>` — one-shot, human-readable verdict
- ⬜ Evidence output (why we concluded this) + machine-readable `--json`
- ⬜ Multi-resolver / multi-path probing from the user's own vantage point

**Deliverable:** cross-platform CLI, no account required.

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
