# mleak

**Brief description.** mleak is a Thunderbird extension for per-mail forensic header and body analysis. It surfaces MUA fingerprints, server stack, M365 tenant data, relay path, auth verdicts, mailing-list markers, direct sender-IP leaks, header-order fingerprints, MIME-boundary hints, crypto signals, and integrity findings — fully offline.

**Current version: 0.6.3.** Popup mode remains the default. The optional `bodyInline` display mode can show mleak findings automatically above the mail body without any internet access. It uses Thunderbird `messageDisplayScripts.register()` plus an `executeScript` fallback, and the headless smoke test verifies the panel in the real `browser#messagepane` mail frame.

---

User docs (install, usage, glossary, contribute) — pick your language:

- [Deutsch — README_DE.md](README_DE.md)
- [English — README_EN.md](README_EN.md)
- [Español — README_ES.md](README_ES.md)
- [中文 — README_ZH.md](README_ZH.md)
- [हिन्दी — README_HI.md](README_HI.md)
- [Português — README_PT.md](README_PT.md)
- [Polski — README_PL.md](README_PL.md)

Developer docs (build, tests, detector architecture, threat model):

- [DEVELOPING.md](DEVELOPING.md)

---

- WebExtension for Thunderbird 115+
- 100 % offline — no network, no telemetry, no external dependencies
- Display modes: popup by default, optional body-inline panel above the mail body
- Parser hardening: repeated `Authentication-Results`, DKIM tag variants, IPv6 `Received` literals, and size-capped MIME rendering
- Minimal offline permissions: `messagesRead` · `messagesModify` · `storage` · `tabs`
- Source / issues / PRs: <https://github.com/c0decave/mleak/>
- Contact: mlux@undisclose.de

---

~ Proudly engineered with Claude ~

## Licence

Licensed under the **Mozilla Public License 2.0** — see [LICENSE](LICENSE).
