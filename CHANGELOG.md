# Changelog

All notable user-facing changes are tracked here.

## 0.6.12 - 2026-05-10

Security + privacy hardening sweep. Two audit rounds + a red-team pass
on every detector module and every IPC surface. Real-mail Tier-1 corpus
(103 fixtures): 0 crashes, 0 schema, 0 goldens missed.

### Defence-in-depth fixes

- **Prototype-pollution-adjacent lookups closed off.** Three modules
  built lookup tables as plain `{...}` literals and then read them with
  attacker-controlled keys (mail header names, Content-Type
  `protocol=` parameter, `<meta>` attribute names). A crafted mail with
  a header literally called `constructor` / `toString` / `__proto__`
  would surface a JS function or `[object Object]` in the popup
  summary. Switched to null-prototype tables and an allowlist:
  - `lib/header_order.js` — `CANONICAL` now uses
    `Object.assign(Object.create(null), …)`.
  - `lib/crypto_headers.js` — `PROTO_LABEL` likewise.
  - `lib/body_html.js` — `metaAttrs()`'s attribute store likewise.
  - `lib/detectors.js` — `mergeAuthVerdicts()` now reads only keys
    from a whitelisted `_AUTH_VERDICT_KEYS` set with explicit
    `hasOwnProperty` guards.
- **DKIM oversigning counter resistant to crafted h= keys.** The
  oversigning detector previously used `{}` as a counter map; a DKIM
  signature with `h=__proto__:__proto__:from` would silently mis-count
  through `Object.prototype.__proto__`'s setter. `lib/integrity.js`
  now seeds the counter with `Object.create(null)`.
- **isPrivateIP detects the IPv4-mapped IPv6 hex form.**
  `::ffff:0a00:0001` is the same address as `::ffff:10.0.0.1` — a
  private RFC 1918 leak — but the legacy regex only matched the
  dotted-quad form and missed the hex one. Also added the deprecated
  IPv4-compatible `::N.N.N.N` form, and tightened the `fe80::/10`
  link-local check to use the `0xfe80–0xfebf` numeric range instead of
  a string-startsWith that could mis-detect at the /10 boundary.

### Test-fixture privacy

- **Anonymiser strips display names.** Real-world mailing-list traffic
  carries the poster's full name in the From/To display-name slot
  (`From: "Jane Doe" <jane@host>`). The corpus extractor's regex only
  rewrote the address part, so committed corpus fixtures kept dozens
  of real names (Mark Thomas, Eli Zaretskii, …). `extract_goldens.py`
  now applies a `_strip_display_names()` pass to ADDRESS_HEADERS
  values after the address-anonymiser, leaving only
  `<user-HASH@domain>` shapes. Every previously-committed corpus
  fixture (100 files) re-scrubbed in this release.

### Regression-test coverage

- 13 new assertions in `tests/run.py` pin each fix:
  - `isPrivateIP` private-address contract in every form (IPv4
    RFC1918, IPv6 ULA/link-local/loopback, IPv4-mapped both
    dotted-quad and hex, IPv4-compatible)
  - DKIM oversigning counter survives crafted `h=` entries
  - Display-name stripping for address-list headers
  - `corpus_*.eml` fixtures carry no display-name PII
  - `header_order` / `crypto_headers` / `body_html` /
    `mergeAuthVerdicts` null-proto contracts
  - Optional Node-VM exercise: a crafted mail with `__proto__` /
    `constructor` / `toString` headers, DKIM `h=`, MIME
    `protocol=`, and `<meta>` attribute names must not surface any
    inherited Object.prototype member in the analyse() output.

### Network / code-injection lockdown

- New tests pin the existing "100% local" privacy contract:
  - No exfil-shaped DOM constructors in shipped code (`new Image()`,
    `createElement("img")`, dynamic `import()`,
    `navigator.clipboard.readText`, geolocation/bluetooth/usb/serial).
  - Every `<a target="_blank">` must carry
    `rel="noopener noreferrer"`.
  - `messenger.tabs.create({url:…})` must always pass a URL produced
    by `messenger.runtime.getURL(…)` — never a literal string.
  - The full set of `messenger.*` APIs the plugin reaches for is now
    pinned to an audited allowlist (any new API surface triggers
    a test failure for review).
  - `inline.js` / `background.js` may not log `location.href` /
    `location.pathname` (would leak the messageId-bearing frame URL).

## 0.6.11 - 2026-05-10

User caught that the mleak-family inline panel protocol was out of
sync between this repo and `mleak-files`. `mleak-files` had landed a
forward-compat tightening that mleak hadn't:

- Each panel now also carries `data-mleak-protocol="1"`.
- Compositors only sort siblings that advertise the **same** protocol
  value, so a future v2 sibling (with different sort direction /
  tiebreak) can't fight a v1 compositor in a mutation feedback loop —
  it's invisible to v1's sort instead.

Mid-state risk before this commit: mleak's panel did NOT set
`data-mleak-protocol`, so a strictly-protocol-filtering sibling (like
mleak-files now is) would treat mleak's panel as "outside the v1
contract" and leave it untouched. The system still mostly worked
because mleak's own compositor *didn't* filter on protocol and so
still sorted both panels — but as soon as a third sibling joined,
the omission would have caused the third sibling to skip mleak's
panel from its sort.

Changes:

- `inline/inline.js`: new `MLEAK_FAMILY_PROTOCOL = "1"` constant;
  the panel root carries `data-mleak-protocol`; the compositor's
  `Array.from(body.children).filter(...)` now also requires
  `el.dataset.mleakProtocol === MLEAK_FAMILY_PROTOCOL`.
- `DEVELOPING.md`: protocol spec gains the new attribute row plus a
  "Forward compatibility" section explaining the why.
- `tests/run.py`: two new assertions on `inline.js` — protocol
  constant must be `"1"`, panel must set the attribute, compositor
  must filter on it.

## 0.6.10 - 2026-05-10

User caught that the 0.6.9 Tier-3 sweep ("850,783 messages, 0 crashes")
was misleading — the runner had a `MBOX_PER_FILE_CAP = 500` baked in,
so any mailbox file with more than 500 messages was silently truncated.
Counted: the corpus has **5,167,357 messages** in 3,447 mbox files;
983 files (28 %) exceeded the cap. Tier-3 0.6.9 covered only **16 %**
of the corpus.

This release rips out the silent-truncation, surfaces the silent-skip
behavior in the report, and fixes every UA-version-loss case the new
exhaustive audit found.

### Runner: exhaustive Tier-3 + visible silent skips

- `tests/corpus/runner.py`: split `MBOX_PER_FILE_CAP` into
  `MBOX_SAMPLE_CAP = 500` (Tier-2 stratified sampling) and `NO_CAP = 0`
  for Tier-3. `_stream_mbox(path, max_messages=0)` now means
  "exhaustive" and Tier-3 calls it with the no-cap form.
- `enumerate_corpus(root, mbox_cap=NO_CAP, skip_log=None)`: new
  `skip_log` param collects every silently-skipped file (corrupt .gz,
  truncated mbox) as `{"path": ..., "reason": ...}`. Both Tier-2 and
  Tier-3 attach the list to their report under `result.enumeration` so
  the silent-loss is now explicit rather than buried in stderr noise.

### UA parser: real version-loss cases the 50k audit surfaced

A new `tests/corpus/bin/audit_versions.py` script exhaustively walks
the corpus, extracts every digit-token from raw User-Agent / X-Mailer
strings, and reports the cases where the parser-produced label
*doesn't preserve* any of them. After the slash→space and V-prefix
tolerance fixes in the audit's comparison logic, the 50k-mail spot
check went from 41 misses (0.29 %) to **0 misses** with these parser
fixes:

- **Mozilla Thunderbird** version capture: `[\d.]+` → `[\w.]+` so the
  beta-suffix survives (`Thunderbird/2.0b2`, `3.0.3pre`, `3.1b2`).
- **Shredder** added as a Mozilla Thunderbird Beta family — it's the
  upstream codename for TB Beta channel builds and shows up in real
  archive UAs.
- **Lightning** rule moved AFTER all Thunderbird/Icedove/Shredder/
  Postbox rules so it stays a *fallback*: the host MUA wins the label
  when present (otherwise we'd report "Lightning 1.0" for what is
  clearly an Icedove mail).
- **GNOME Evolution** version regex now captures the distro patch
  suffix (`-0ubuntu6`, `-1+b1`, `-0ubuntu2`) instead of silently
  truncating.
- **Roundcube Webmail**: same — captures `-beta`, `-stable`, `-rc` etc.
- **Yahoo Mail**: combined-version rule now captures the build counter
  (`_NN`) on both halves: `YahooMailClassic/6.0.19_56
  YahooMailWebService/0.8.111_27` produces `Yahoo Mail
  6.0.19_56 (WebService 0.8.111_27)` instead of dropping the build
  counter and the frontend version.
- **Gnus / Emacs**: single rule now reports BOTH versions
  (`Gnus 5.110011 / Emacs 23.1.50`) instead of just Gnus.

### Tooling: `tests/corpus/bin/audit_versions.py`

New corpus tool. For every UA in the corpus:
- Pull every digit-bearing token from the raw UA-Header / X-Mailer.
- Run the message through the bridge and collect the parser's label.
- Tolerate the `Foo/1.2.3` → `Foo 1.2.3` rewrite and the V→strip
  rewrite when comparing.
- Report the families where label loses the raw version, with up to
  3 sample UAs and the top expected-version tokens.

Output: `tests/corpus/reports/ua-version-audit-<utc>.json`.

### Verification

  python3 tests/run.py             → 120 passed, 0 failed, 1 skipped
  audit (50k random)               → 0 lost / 13,992 with raw version (0.00 %)
  Tier-3 EXHAUSTIVE (5.17M mails)  → in flight; report when done

Tier-3 0.6.9's "0 crashes" claim was correct as far as the messages it
saw; the bug was that it saw fewer than 1 in 6 of them. The exhaustive
Tier-3 is the verdict that matters and it goes in the next release if
it surfaces anything.

## 0.6.9 - 2026-05-10

Code-review pass against the 0.6.8 work plus the first full Tier-3
corpus sweep (850,783 messages, 0 crashes, 0 schema violations,
1 soft-cap warning). Three real bugs surfaced and fixed:

- **`lib/ua_parser.js`**: a `Thunderbird 1.5.0.7 (Windows/20060909)`-style
  UA (no slash, no `Mozilla` prefix) used to fall through to the bare
  `\bThunderbird\b` rule and lose its version. Added a dedicated
  space-separated rule above the bare fallback. Tier-3 had ~14k of
  these in the corpus; they now extract cleanly.
- **`tests/corpus/lib/node_bridge.py`**: bridge.js's `setTimeout`
  protection doesn't fire when a detector hangs synchronously
  (Node's event loop is blocked → no timer ticks). Added a
  Python-side `select()` with a 30 s wall-clock cap per message; on
  stall we kill the bridge and let the runner re-spawn. The original
  bridge-side timeout stays as defense-in-depth for async code paths.
- **`tests/corpus/bin/extract_goldens.py`**: anonymizer left email
  addresses inside `Received-SPF` (`envelope-from=…`),
  `Authentication-Results` / `ARC-*` (`smtp.mailfrom=…`,
  `header.from=…`), `Resent-*`, `Disposition-Notification-To`,
  `Mail-Followup-To`, and various vendor `X-*` headers. New
  `ADDRESS_HEADERS` set covers the explicit cases; a defensive
  `_looks_personal_header()` fallback catches unknown X-* whose name
  contains `from`/`to`/`sender`/`recipient`/`envelope`/etc. Mailing-
  list and Message-ID structures are explicitly preserved (detector
  needs them).
- **Goldens regenerated** with the tightened anonymizer; manual
  sweep confirms no residual real addresses outside known-public
  list infra.
- **`lib/body_html.js`**: added explicit `MAX_MIME_STRUCTURE = 1024`
  cap on the assembled MIME-tree fingerprint string. Per-element
  caps existed (240-char Content-Type, depth 6, breadth 16); a
  worst-case combination at all levels could grow longer than the
  corpus runner's schema check expected. Tier-3's single soft warning
  was at 529 chars — the new cap (1024) is comfortable headroom for
  real traffic and the runner's schema check now matches the cap.

**Tier-3 verification (850,783 messages from 38 GB corpus):**

| metric | value |
|---|---|
| crashes | 0 |
| schema violations | 0 |
| MUA signals present | 97.8 % |
| server stacks present | 88.7 % |
| relay hops present | 97.9 % |
| DKIM signatures present | 40.0 % |
| internal hostname leak | 97.7 % |
| M365 tenant detected | 2.1 % (mostly OSS lists) |

After-fix Tier-2 spot check (5000 mails, with the improved heuristic):
"families missing version" report is now empty — Apple build IDs,
vendor-prefixed semver, and dotted decimals all correctly recognised.

## 0.6.8 - 2026-05-10

- **UA parser detector improvements** driven by the corpus run's
  version-coverage report. Real-world UA strings that lost their version
  before:
  - **Coremail** — `Coremail Webmail Server Version SP_ntes V3.5 build …`
    now extracts `V3.5` instead of dropping at "SP_ntes". Two-stage rule:
    prefer dotted V-version when present, otherwise the first token after
    `Version`.
  - **NeoMutt** — `NeoMutt/20180716 (1.7.1)` now reports `1.7.1 (20180716)`
    via the new `verBuild` callback, not just the date build.
  - **Mozilla Thunderbird Beta / Daily / Earlybird** — channel suffixes
    are captured as version-like markers when present.
  - **Bare `Thunderbird`** — added as Mozilla Thunderbird family fallback
    (was previously unparsed).
  - **Postbox** — `PostboxApp/<ver>` (the actual desktop UA) now matches
    the Postbox rule.
  - **Icedove** — case-insensitive match (corpus has both `Icedove/` and
    `IceDove/`).
  - **Mozilla rv:** fallback — captures `rv:X.Y` from generic Mozilla/5.0
    UAs so the Gecko-based fallback now reports a version too.
  - The `parseUA` rule shape grew an optional `verBuild(match)` callback
    for rules that need to combine two capture groups into one version
    string.
- **`tests/corpus/lib/checks.py` heuristic** for the version-coverage
  report now recognises Apple build IDs (`15B93`, `9A405`), single-token
  versions (`Outlook 11`), 8-digit dates (`20180716`), `v.`/`V`-prefixed
  versions (`v.4.1.8`, `V6.00.2800`), vendor-prefixed semver
  (`XT5.0.10`, `f.15.1.160411`), and channel labels — false-positive
  "0% with version" reports for these families are gone.
- **i18n + READMEs** extended to 18 languages: added `fr` and `it` to
  the existing 16 stubs; polished all 11 stub READMEs (was: skeleton
  with title + install + license; now: highlights bullets + usage
  paragraph + security/privacy table + contribute section + link to
  README_EN.md for the full glossary).
- Language picker now spans 18 entries across every README.
- `scripts/seed_new_readmes.py` updated to keep the 11 stubs
  re-generatable from one place.

## 0.6.7 - 2026-05-10

- **Bug 1 — external IPs in path/leaks**: `lib/received.js` now surfaces a per-hop `{by_host, by_ip, from_host, from_ip}` array (`relay_path.leaks.hops`) so the popup renders `host (ip)` for every relay, not just the hostname. External (public) IPs intentionally stay out of the *Leaks* card — they're routing data, not RFC1918-style internal leakage.
- **Bug 2 — "3 hops" displayed as 2**: removed the dedup of consecutive identical `by_host` entries from the rich hop array. Each parsed `Received:` header is now one entry; the legacy hostnames-only `relays` summary keeps its dedup for the one-line fallback.
- **Bug 3 — relay path direction**: new setting **Relay path direction** (originFirst | receiverFirst). Default is `originFirst` so the chain reads "sender → me" forward in time. Storage stays in canonical wire-order; only the renderer flips. Origin label (the bottom-Received's `from` side, with IP) is shown above the path in origin-first mode.
- **Bug 4 — PHPMailer version dropped**: added a dedicated `PHPMailer\s+([\d.]+)` rule to `lib/ua_parser.js` *before* the generic `PHP\/?` fallback, so `PHPMailer 6.0.3 (https://github.com/PHPMailer/PHPMailer)` now reports as "PHPMailer (PHP library) 6.0.3" instead of the bare "PHP mail() (script)" with empty version.
- Added 7 regression tests covering the new schema, the dedup removal, the origin field, the direction setting, the popup renderer, and the PHPMailer rule.

## 0.6.6 - 2026-05-10

- Adopted the **mleak-family inline panel protocol v1**. When `mleak` and `mleak-files` are both installed in `bodyInline` mode, their panels now stack deterministically (mleak on top, mleak-files below) regardless of which extension's `messageDisplayed` listener fires first. Each panel carries `class="mleak-family-panel"`, `data-mleak-id` and `data-mleak-order`; an idempotent in-frame compositor with a `MutationObserver` re-sorts on insert. Either extension can be absent — no install-order coupling. Spec lives in `DEVELOPING.md`.

## 0.6.5 - 2026-05-09

- Expanded the offline OSINT detector catalogue with corpus-derived client, Message-ID, MIME-boundary, mailing-list, sender-IP, crypto, server-stack, and header-order signals.
- Restored and hardened the optional `bodyInline` display mode using Thunderbird message-display script registration plus a fallback for already-open message tabs.
- Added deeper defense-in-depth across the extension: stricter runtime message and tab/message ID validation, bounded debug-log storage, capped raw JSON rendering, capped UI row rendering, MIME/header fan-out limits, and length caps before surfacing leak values.
- Hardened parser edge cases for repeated headers, folded/case-varied DKIM tags, Authentication-Results aggregation, Date timezone parsing, HTML generator metadata, scoped/mapped IPv6, malformed IPv6 rejection, and compact MIME tree rendering.
- Added Thunderbird GUI fixtures and regression coverage for the new detector families and hardening checks.
- Rebuilt the installable XPI as `dist/mleak-0.6.5.xpi`.

## 0.6.3 - 2026-05-08

- Replaced legacy `inlineMode` with `displayMode`.
- Restored selectable body-inline rendering above the mail body.
- Declared `messagesModify` explicitly for Thunderbird `messageDisplayScripts.*`.
- Added a headless Thunderbird smoke path for the real `browser#messagepane` frame.

## 0.6.2 - 2026-05-08

- Added offline OSINT modules for header-order fingerprints, MIME-boundary families, mailing-list fingerprints, direct sender-IP leaks, and crypto-header aggregation.
- Surfaced the new signals in popup and inline summaries.
- Added parser hardening for repeated Authentication-Results, DKIM folding/case variants, Date offsets with trailing comments, repeated sender-IP headers, IPv6 literals, scoped/mapped IPv6, and MIME tree rendering limits.

## 0.5.9 - 2026-04-23

- Shipped explicit PNG icons at 16/32/48/96 px.
- Moved preview images to `branding/`.

## 0.5.8 - 2026-04-22

- Licensed the project under MPL-2.0.
- Added SPDX headers and bundled LICENSE in the XPI.
- Expanded i18n and shipped multilingual user READMEs.

## 0.5.6 - 2026-04-22

- Split user documentation from developer documentation.
- Added a release pipeline that produces `.xpi` plus `.sha256`.

## 0.5.3 - 2026-04-21

- Added defense-in-depth around safe i18n HTML keys, manifest-version interpolation, and runtime message payload checks.

## 0.5.0 - 2026-04-21

- Added crypto-header detection for Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, gateway headers, and MIME-boundary MUA hints.
- Improved Received-chain parsing and internal hostname/private IP detection.

## 0.1.0 - 2026-04-21

- Initial release: popup UI plus the first detector modules.
