# mleak — Per-Mail OSINT for Thunderbird

*Languages: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md)*

**Source:** <https://github.com/c0decave/mleak/>

**Brief description.** mleak is a Thunderbird extension for per-mail forensic header and body analysis. It surfaces MUA fingerprints, server stack, M365 tenant data, relay path, auth verdicts, and integrity signals — fully offline.

WebExtension for Thunderbird 115+. Analyses headers and body on a per-message basis and shows structured OSINT intel — either as a popup or directly inline above the mail body.

- **MUA / client**: from `User-Agent`, `Message-ID` patterns, HTML-body signatures, MIME-Version parenthetical, and MIME-boundary prefixes (Apple-Mail / enig / _000_ / _NextPart_) — five independent signals, cross-validated
- **Server stack**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · delivery markers (Proofpoint / Mimecast / Barracuda)
- **M365 tenant GUID** + **datacenter region**: direct org attribution without whois
- **Relay path**: hop count, external relays, **internal hostname leaks** (incl. single-label NetBIOS / k8s pod names), **private IPs** from Received (IPv4 + IPv6 ULA / link-local), per-hop context ("10.x.x.x at relay.example.com from ws-eve.corp.local")
- **Authentication**: SPF / DKIM / DMARC / ARC / BIMI verdicts + DKIM signatures (domain, selector, vendor hint)
- **Crypto**: Enigmail version (via `X-Enigmail-Version` or the `enig…` boundary prefix), OpenPGP/MIME, S/MIME, Autocrypt / Autocrypt-Gossip, OpenPGP keyserver hint, Symantec PGP-Universal, Tutanota, ProtonMail
- **Integrity**: missing Date/MID, From↔Sender divergence, Reply-To cross-domain, DKIM h=-coverage gaps, oversigning
- **Timezone**: UTC normalisation + TZ offset
- **MIME structure**: compact tree fingerprint
- **Per-card visibility toggles**: hide any of the seven cards from the options page

**100 % offline.** No network access, no telemetry, no external dependencies. Raw mail bytes never leave the Thunderbird process.

---

## Installation

### Temporary (development)
1. `Tools → Add-ons and Themes → ⚙ → Debug Add-ons → Load Temporary Add-on …`
2. Pick `manifest.json` from this directory.

### Packaged
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (current: 0.5.9)
```
Then: `Tools → Add-ons → ⚙ → Install Add-on From File …` and pick the XPI. For `xpinstall.signatures.required=false` to work, your Thunderbird build must allow it (distro builds like Arch / Debian / ESR usually do).

---

## Usage

**Popup mode** (default + currently the only mode): click the icon in the message toolbar → popup opens with all intel cards. The inline-panel mode is still gated off while a per-layout injection bug is tracked down — the code paths are in place and re-enabling is a one-line change once the root cause is fixed.

Open settings: `Tools → Add-ons → mleak → Preferences`. Options:
- Colour scheme (auto / dark / light)
- Popup width (440 / 500 / 600 / 720 px) — 600 is the default
- Density (compact / normal / airy)
- Default view (cards / JSON)
- Visible cards (hide any of the seven categories)
- Analysis cache size + clear-now button
- Debug log (opt-in) + log viewer
- About (version + call to contribute unrecognised fingerprints)

---

## Security & privacy

| Property | Status |
|---|---|
| Network requests | **none** (no `fetch`, `XHR`, `sendBeacon`, `WebSocket`) |
| DOM injection | **none** (only `textContent`/`createElement`; no `innerHTML` with dynamic values) |
| CSP | strict: `script-src 'self'; object-src 'none'; base-uri 'none'` |
| Permissions | **minimal**: only `messagesRead` + `storage` + `tabs` (no `messagesModify`, no `<all_urls>`) |
| Storage | only UI preferences in `storage.local`; **no mail content** |
| Debug log | opt-in, ring buffer (max 500 entries, status strings only, no headers) |
| ReDoS protection | length caps on header values (8 KB) + Message-IDs (1 KB) before regex match |

Every line is auditable. Technical details, detector architecture, threat model and build instructions live in [DEVELOPING.md](DEVELOPING.md).

---

## Glossary

Terms you'll see in the popup and inline panel:

- **MUA** — Mail User Agent; the email client that authored the message (Thunderbird, Outlook, Apple Mail, …).
- **Server stack** — the server-side product the mail passed through (Gmail, Exchange/M365, Apple iCloud, Yahoo, Proofpoint, Mimecast, Barracuda).
- **M365 tenant** — the GUID that Microsoft 365 stamps into outgoing mail headers; identifies the sender's organisation directly, no whois needed.
- **Relay path** — the list of external servers (`by`-hosts in Received chain) the mail passed through, top = first hop.
- **Private IP leak** — an RFC 1918 address (10.x.x.x, 172.16-31.x.x, 192.168.x.x) exposed in Received headers; leaks the sender's internal LAN.
- **Internal hostname leak** — a `.local` / `.corp` / `.internal` / `.lan` style hostname in Received; leaks the sender's intranet.
- **Auth verdicts** — SPF, DKIM, DMARC, ARC, BIMI pass/fail as reported by the receiver.
- **DKIM oversigning** — listing a header name **multiple times** in the `h=` tag of a DKIM signature (e.g. `h=from:from:subject:subject`). Defeats header-injection attacks: if a later relay adds a second `From:`, the signature breaks instead of silently validating a forged header.
- **DKIM h=-coverage gap** — a security-relevant header (`From`, `Subject`, `Reply-To`, `Date`, `Message-ID`) is *not* listed in the signature's `h=` tag, meaning that header can be altered in transit without breaking the signature.
- **Hop count** — number of Received headers in the chain. Sudden jumps vs. a baseline are often forwarding/relay-rewrite evidence.
- **Chronology anomaly** — Received timestamps aren't monotonically decreasing top-down; usually relay clock drift, occasionally chain tampering.
- **Integrity flags** — structural oddities: missing Date/Message-ID, From↔Sender divergence, Reply-To cross-domain.
- **Enigmail** — the Thunderbird PGP add-on. Detected via `X-Enigmail-Version` *or* via the `-------enig…` MIME-boundary prefix (survives header stripping).
- **OpenPGP/MIME** — RFC 3156 encrypted/signed multipart; detected via `multipart/{encrypted,signed}` + `protocol=application/pgp-*`.
- **S/MIME** — RFC 2633 / PKCS#7 signed or encrypted; detected via `application/(x-)?pkcs7-*` content types.
- **Autocrypt** — RFC-draft automatic-key-exchange header; its presence is a MUA-capability signal.
- **Boundary MUA hint** — MUAs stamp product-specific prefixes into MIME boundaries (`Apple-Mail=`, `_000_`, `_NextPart_`, `----=_Part_`). Since the boundary survives relay rewrites, it's a useful MUA fingerprint *even on encrypted mails* where body-HTML scanners have nothing to inspect.

---

## Versions

- **0.5.9** — fix: toolbar and message-display icons were invisible because `icons/logo.svg` used `stroke="currentColor"` without a CSS context at rasterization time; manifest now ships explicit PNG icons at 16/32/48/96 px. Preview images moved to `branding/` (not included in the XPI).
- **0.5.8** — licensed under **MPL-2.0** (LICENSE + SPDX headers on every source file); i18n expanded to nine locales (added zh, hi, pt); user READMEs now ship in seven languages (DE/EN/ES/ZH/HI/PT/PL); LICENSE bundled inside the XPI.
- **0.5.6** — user docs split from developer docs; XPI ships all three language READMEs; release pipeline (`scripts/release.sh`) produces exactly `.xpi` + `.sha256`, nothing else.
- **0.5.5** — XPI now contains `README_DE.md` / `README_EN.md` / `README_ES.md` next to the index; regression test enforces the layout.
- **0.5.4** — red-team hygiene: `inline/inline.js` on-message payload shape-checked symmetric to `background.js`; TB binary resolved via absolute path for one less ambient-PATH concern.
- **0.5.3** — defence-in-depth hardening: `SAFE_HTML_KEYS` allowlist gates every `data-i18n-html` key in `lib/i18n.js`; manifest version format-validated before it's interpolated into the About card's innerHTML; `runtime.onMessage` entry point type-checks `msg.type` + `msg.messageId`.
- **0.5.2** — two correctness nits surfaced during static analysis: `mid_patterns.js` `domain.endsWith("gmail.com")` now an exact-or-subdomain check; `ua_parser.js` Mutt regex character class simplified (overlapping ranges).
- **0.5.1** — inline-mode UI temporarily gated off (per-layout injection bug); detector failures funnel through the opt-in debug log; startup IIFE wrapped against unhandled promise rejections. Security audit pass: no network, no obfuscation, no backdoor-shaped code, `messages.getFull` single call site gated behind our own message types.
- **0.5.0** — new `crypto_headers.js` detector (Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, gateway headers, boundary-prefix MUA hints). Received-chain fixes: by-parenthetical parsing, `from [IP]` HELO-bare-IP extraction, single-label internal-hostname heuristic with sentinel filter, IPv6 private ranges (ULA / link-local / mapped). MIME-Version parenthetical as secondary MUA source. Latent `ReferenceError` in external-relay loop fixed.
- **0.4.2** — by-side parenthetical capture + single-label hostname detection (1&1 Kubernetes-pod-name / NetBIOS leak class).
- **0.4.1** — inline-mode lifecycle rewritten on `onMessageDisplayed` + `tabs.executeScript` with verbose dlog (attempt to make inline-mode reliably work; partially successful — still disabled in 0.5.1).
- **0.4.0** — per-card visibility toggles (7 cards), per-hop context on leak rows, vertical relay path, glossary in EN/DE/ES, About section with contribute CTA.
- **0.3.0** — i18n in six languages (en/de/es/fr/pl/it), envelope-with-magnifier icon, multilingual READMEs, `default_locale` set.
- **0.2.0** — inline-mode (initial attempt), settings page, responsive popup, security hardening (length caps, ReDoS protection), SVG logo, rename to *mleak*.
- **0.1.0** — initial release: popup + 9 detector modules.

---

## Contribute unknown MUA / server fingerprints

Found a mail the extension **couldn't classify** — and you already know which client or server stack it came from? Please send us the relevant headers. Those contributions are how the detector catalogue grows.

What to send:

1. Open the mail, View → Message Source (or Ctrl+U).
2. Copy the top header block down to (and including) the first blank line — roughly `Received:` through `Message-ID:`, `User-Agent:`, plus anything else that looked interesting.
3. Note which client / webmail / relay product you know (or suspect) this came from.
4. Redact personal addresses if you want; **never redact `Received`, `Message-ID`, `X-*` or auth headers** — those are the bits we need.
5. Email: **mlux@undisclose.de**, subject starting with `mleak-sample`.

If you prefer Git: open an issue or PR at **<https://github.com/c0decave/mleak/>** with the same info.

---

~ Proudly engineered with Claude ~

## Licence

Licensed under the **Mozilla Public License 2.0** — see [LICENSE](LICENSE).

MPL-2.0 is a file-level copyleft licence: modifications to MPL files must stay MPL, but you can freely combine mleak with code under other licences (including proprietary) in a Larger Work. The licence includes an explicit patent grant.

Contact: mlux@undisclose.de
