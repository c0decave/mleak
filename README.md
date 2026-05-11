<p align="center">
  <img src="branding/logo-256.png" alt="mleak logo" width="160">
</p>

# mleak

**Brief description.** mleak is a Thunderbird extension for per-mail forensic header and body analysis. It surfaces MUA fingerprints, server stack, M365 tenant data, relay path, auth verdicts, mailing-list markers, direct sender-IP leaks, header-order fingerprints, MIME-boundary hints, crypto signals, and integrity findings — fully offline.

**Current version: 0.6.16.** Popup mode remains the default. 0.6.16 ships a corpus-driven regression find: a Tier-3-equivalent run of the new bug-class asserts against **100 000 real-world mails** flagged that the 0.6.15 control-char sanitiser missed the body-HTML `<meta name=generator>` path — MS-Word's "filtered medium" HTML export wraps the generator string across source lines and the captured `\r\n` landed in `summary.mua_signals[*].label`. Same bug-class as Round 5 (control chars in surfaced summary), structurally; no XSS (textContent rendering) but downstream-parser-confusion risk on copy-paste. Fix: new `sanitiseValue()` helper exported from `lib/util.js` and applied in `lib/body_html.js metaAttrs()` + the legacy `GEN_RX` path. Plus a seeded-PRNG fuzz suite ported from `mleak-files-remover` — 16 800 randomised adversarial inputs per run across every detector entry point. See `CHANGELOG.md`.

---

**User docs** (install, usage, glossary, contribute) — pick your language:

[Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)

Developer docs (build, tests, detector architecture, threat model):

- [DEVELOPING.md](DEVELOPING.md)

---

- WebExtension for Thunderbird 115+
- 100 % offline — no network, no telemetry, no external dependencies
- Display modes: popup by default, optional body-inline panel above the mail body
- Parser hardening: repeated `Authentication-Results`, DKIM tag variants, IPv6 `Received` literals, and size-capped MIME rendering
- Minimal offline permissions: `messagesRead` · `messagesModify` · `storage` · `tabs`
- Source / issues / PRs: <https://github.com/c0decave/mleak/>
- Changes: [CHANGELOG.md](CHANGELOG.md)
- Contact: mlux@undisclose.de

---

~ Proudly engineered with Claude ~

## Licence

Licensed under the **Mozilla Public License 2.0** — see [LICENSE](LICENSE).
