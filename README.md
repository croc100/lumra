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

## Run it — no install

Lumra is a **single self-contained binary** with the web UI baked in (no
runtime, no dependencies). You don't have to install anything: download the
binary for your platform from [Releases](https://github.com/croc100/lumra/releases),
and **just run it** —

```sh
./lumra              # (double-click on Windows/macOS)
```

— which launches the local cockpit and opens `http://127.0.0.1:7777` in your
browser. That's the whole thing: one file, run it, dashboard.

### Or install it on your PATH

If you'd rather have `lumra` as a command everywhere:

```sh
brew install croc100/tap/lumra          # macOS / Linux
scoop install lumra                      # Windows (via the croc100 bucket)
irm https://raw.githubusercontent.com/croc100/lumra/main/install.ps1 | iex   # Windows, no package manager
go install github.com/croc100/lumra/cmd/lumra@latest
```

Then use the subcommands:

```sh
lumra diagnose example.com              # human-readable verdict
lumra diagnose example.com --json       # machine-readable
lumra diagnose example.com --report report.html   # shareable evidence page
lumra diagnose example.com --bundle b.json --ooni  # signed evidence + OONI export

lumra live                              # passive cockpit of every domain you touch
lumra watch example.com                 # continuous monitoring + blocked-at timeline
lumra verify b.json                     # check a signed measurement bundle

lumra serve                             # local web cockpit in your browser (no account, no server)
```

### Local web cockpit

`lumra serve` runs a self-hosted dashboard on `http://127.0.0.1:7777` that
drives the same engine as the CLI — no account, no cloud, the page talks only to
this process. It's the convenient way to use Lumra on a personal machine or in a
lab:

- **Diagnose** any target from the browser, with the full evidence breakdown.
- **Export evidence** in one click — shareable HTML report, Ed25519-signed
  bundle, or OONI measurement — generated from exactly the verdict on screen.
- **Continuous monitoring** — watch a target and build a live blocked-at
  timeline; add or stop targets from the UI.
- **Live board** of every domain this machine touches (needs elevation for the
  passive tap; diagnosis and monitoring work unprivileged).

```sh
lumra serve --addr 127.0.0.1:8080       # custom bind address
lumra serve --active                    # add background confirmation probes
```

Deep RST/TTL attribution needs a raw socket — run elevated (`sudo` /
`cap_net_raw`) on Linux. Every other signal works unprivileged.

## Status

**v0.2.0 shipped.** The measurement engine, CLI, and a live passive cockpit are
out. Detection spans DNS (tampering / NXDOMAIN / duplicate-response injection),
TLS/SNI filtering, TLS MITM, TLS 1.3 downgrade, IP blocking, RST/TTL
attribution, throttling, self-identifying block pages, and modern protocols —
QUIC/HTTP-3, ECH, and DoH blocking. Plus continuous monitoring (`lumra watch`),
a passive cockpit (`lumra live`), a local web cockpit (`lumra serve`) with
one-click evidence export and continuous monitoring, signed/OONI-exportable
evidence bundles, a browser extension, and iOS/Android app shells. See
[ROADMAP.md](ROADMAP.md) for
the path to hosted monitoring (P2) and the opt-in vantage network (P3).

---

## License

TBD (CRODE no-log line).
