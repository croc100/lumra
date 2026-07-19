# Lumra — Program Overview

**Take back control of your internet.** Lumra measures *why* a connection is
being interfered with — and where the interference originates — from direct,
active probing. It does not fetch or trust third-party block lists; the evidence
identifies itself.

Status: **v0.1.0 shipped** — the engine, CLI, and browser extension are live
(`brew install croc100/tap/lumra`). This document remains the design spec; see
[ROADMAP.md](../ROADMAP.md) for phasing and what's next (P2 hosted, P3 vantage).

---

## 1. Form Factor

Lumra ships as **no-install, run-and-go tools** plus **browser extensions** that
share one measurement core.

| Surface | Form | Notes |
|---------|------|-------|
| **Native (Win)** | single `lumra.exe`, no installer | run-and-go; requests UAC elevation for RST/TTL probes, degrades gracefully without |
| **Native (macOS)** | signed+notarized binary / `.dmg` | reuses Litescope GUI signing pipeline; `sudo`/raw-socket for deep probes |
| **Native (Linux)** | single binary | `cap_net_raw` for deep probes |
| **Chrome/Edge** | extension (MV3) | lightweight; calls native core via Native Messaging when present |
| **Firefox** | extension (WebExtension) | same model |

**Design stance:** a diagnostic tool must have zero install friction —
download → run → verdict. GUI, when added, wraps the same single binary
(Wails/Tauri) so distribution stays as one file per platform.

### Native ↔ Extension split

The browser cannot inspect raw packets, so capabilities are tiered, not
duplicated:

- **Native core** = full engine: DNS, TCP/RST, TLS/SNI, and **TTL-based
  attribution** (raw sockets).
- **Extension standalone** = browser-visible signals only: block-page /
  redirect detection (e.g. `warning.or.kr`), TLS handshake failures as seen by
  the browser, DNS-over-`fetch` comparison. Confidence is capped without the
  core.
- **Extension + native (Native Messaging)** = the extension detects a failing
  page in-browser, hands the target to the local core, and renders the core's
  full verdict incl. attribution. This is the flagship experience.

---

## 2. What Lumra Outputs

Every run returns:

```
verdict = { type, cause, confidence, attribution, evidence[] }
```

### Interference types
`OK` · **`DNS_TAMPERING`** · **`SNI_FILTERING`** · **`RST_INJECTION`** ·
`IP_BLOCKING` · `TLS_MITM` · `BLOCK_PAGE` · `THROTTLING` · `LOCAL_ISSUE` ·
`GENUINE_OUTAGE`   *(bold = MVP)*

### Attribution axis (the differentiator)

Lumra does not claim "the government blocked this." It reports, from
measurement, **where** the interference sits and **whether the machinery
self-identifies**:

- `in_network` — interference originates inside the domestic network path,
  before international transit (destination is otherwise reachable)
- `destination` — the target server itself is failing (→ likely `GENUINE_OUTAGE`)
- `local` — the user's own network (→ `LOCAL_ISSUE`)
- `self_identified: <authority>` — a block page/redirect points to an operator's
  own server (e.g. KCSC `warning.or.kr`)

---

## 3. Detection Engine — how each signal is measured

All detectors compare the target against a known-good **control** target run in
parallel, so a local outage is never misreported as censorship.

**(A) DNS analysis**
- Query target via ① system resolver ② plaintext public (8.8.8.8 / 1.1.1.1)
  ③ **DoH/DoT ground truth** (Cloudflare / Google)
- Plaintext answer diverges from DoH ground truth AND resolves to
  unreachable / block-page / bogon IP → `DNS_TAMPERING`
- Injection signatures: response arriving before the real one, TTL anomalies,
  duplicate answers; NXDOMAIN consistency check separates real-absent from
  tampered

**(B) TCP reachability + RST injection**
- TCP connect to resolved IP:443
- RST after SYN or after ClientHello whose **packet TTL disagrees with the true
  server TTL** → injected by a middlebox → `RST_INJECTION`
- Distinguish blackhole (timeout) vs RST vs success

**(C) TLS / SNI filtering** — highest-signal probe
- Handshake to the same IP with **SNI = target** vs **SNI = benign/empty**
- Fails only with target SNI → `SNI_FILTERING` (near-certain)
- Presented cert chain vs DoH-fetched expected / CT logs → mismatch = `TLS_MITM`

**(D) Attribution via TTL hop triangulation**
- From the injected packet's TTL, compute how many hops away the injecting
  middlebox is; compare to the destination's hop distance
- Injector before the international gateway (inside domestic backbone) while the
  destination is farther → `attribution = in_network`
- This is physics (hop count), not a list lookup

**(E) Self-identification**
- If a blocked request is redirected/injected toward a known operator block
  server (e.g. `warning.or.kr` → KCSC), record `self_identified` — the
  censoring infrastructure is naming itself; no third-party list involved

**(F) Cross-vantage consistency** *(P2, requires hosted backend)*
- Same target reproduced across ISPs/vantages → identical mechanism everywhere
  ⇒ national mandate vs single-ISP action; clean out-of-country vantage
  confirms `GENUINE_OUTAGE` vs `IP_BLOCKING`

---

## 4. Explicit stance on sources

- **No trusted block lists.** Lumra never reports "blocked" because KISA / a
  third party said so. Such lists are, at most, corroboration — never evidence.
- **Evidence must be self-produced or self-identifying.** A verdict cites
  packets Lumra observed (TTL, RST timing, SNI-conditional resets) or
  infrastructure that named itself (operator block page).
- **No claim beyond measurement.** Lumra states *where* and *how*, and lets the
  self-identifying block page speak for *who*. It does not assert legal intent.

---

## 5. Example output

```
$ lumra diagnose example.com

Target:      example.com
Verdict:     SNI_FILTERING            (confidence: high)
Attribution: in_network / self_identified: KCSC

Cause: TLS connections carrying SNI=example.com are reset by a middlebox
       inside the domestic network path; the same IP completes a handshake
       with a benign SNI, and the blocked request is redirected to the
       operator's own block server.

Evidence:
  ✓ DNS   consistent across resolvers (no tampering)
  ✓ TCP   93.184.216.34:443 reachable
  ✗ TLS   SNI=example.com  → RST after ClientHello (pkt TTL 250, server TTL 54)
  ✓ TLS   SNI=cloudflare.com → handshake OK on same IP
  ⓘ HOP   RST injected ~6 hops away; destination ~14 hops → in-network
  ⓘ PAGE  blocked request redirected to warning.or.kr (KCSC block server)
  ✓ CTRL  control (wikipedia.org): OK → not a local network issue
```

---

## 6. Tech Stack

- **Go** — single static binary, cross-compile, low-level socket/TLS control;
  unifies with Warren
- DNS/DoH: `miekg/dns`
- Raw packet / TTL inspection: `gopacket` (degrades to heuristic when no raw
  socket privilege)
- Browser extensions: MV3 (Chrome/Edge) + WebExtension (Firefox), Native
  Messaging host bundled with the native binary
- Hosted backend (P2): reuse the Litescope Cloud stack (CF Workers + D1)

---

## 7. Build Order (MVP → SaaS)

1. ✅ **Core engine** — DNS + TCP/RST + TLS/SNI + MITM + IP-block + control +
   throttling + real TTL attribution
2. ✅ **CLI** — `lumra diagnose <target>`, `--json`, `--report`
3. ✅ **Native Messaging host** + **browser extension** (standalone signals →
   full verdict when core present)
4. ⬜ **Hosted SaaS** — dashboard, scheduled monitoring, alerts (Litescope Cloud
   stack)
5. ⬜ **Cross-vantage network** — opt-in, privacy-preserving aggregates

*(1–3 shipped in v0.1.0.)*

Non-goals unchanged: Lumra diagnoses, it does not circumvent (that is Warren),
and it does not log packet contents.
