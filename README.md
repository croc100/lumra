# Lumra

**Take back control of your internet.** Lumra analyzes *why* your connection is
being blocked, throttled, or tampered with — not just *that* it is.

Lumra is CRODE's internet censorship & interference analysis SaaS. When a site
won't load, a service is degraded, or DNS returns the wrong answer, Lumra
diagnoses the **cause and type** of the interference: government-level blocking,
DNS manipulation, TLS/SNI-based filtering, throttling, or ordinary outage.

---

## Why Lumra

Most tools tell you a site is "down." Lumra tells you *how* and *by whom* it's
being interfered with, with evidence:

| Symptom | What Lumra distinguishes |
|---------|--------------------------|
| Site won't load | Real outage vs. state-level block vs. local network issue |
| Wrong / no DNS answer | DNS poisoning / tampering vs. misconfiguration |
| TLS handshake fails | SNI-based filtering vs. cert error vs. MITM |
| Slow connection | Deliberate throttling vs. congestion |

Lumra is the **analysis and visibility** counterpart to
[Warren](https://github.com/croc100/warren) (censorship-resistant P2P network).
It sits in CRODE's no-log, internet-freedom product line alongside Crovi and
Litescope.

---

## Install

```sh
brew install croc100/tap/lumra          # macOS / Linux
go install github.com/croc100/lumra/cmd/lumra@latest
```

Then:

```sh
lumra diagnose example.com              # human-readable verdict
lumra diagnose example.com --json       # machine-readable
lumra diagnose example.com --report report.html   # shareable evidence page
```

Deep RST/TTL attribution needs a raw socket — run elevated (`sudo` /
`cap_net_raw`) on Linux. Every other signal works unprivileged.

## Status

**v0.1.0 shipped.** The measurement engine and CLI are live: DNS
(tampering / NXDOMAIN / duplicate-response injection), TLS/SNI filtering,
TLS MITM, IP blocking, RST/TTL attribution, throttling, and self-identifying
block pages — plus a browser extension. See [ROADMAP.md](ROADMAP.md) for the
path to hosted monitoring (P2) and the opt-in vantage network (P3).

---

## License

TBD (CRODE no-log line).
