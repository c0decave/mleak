# mleak

**Brief description.** mleak is a Thunderbird extension for per-mail forensic header and body analysis. It surfaces MUA fingerprints, server stack, M365 tenant data, relay path, auth verdicts, mailing-list markers, direct sender-IP leaks, header-order fingerprints, MIME-boundary hints, crypto signals, and integrity findings — fully offline.

**Current version: 0.6.12.** Popup mode remains the default. 0.6.12 is a security + privacy hardening release: two audit rounds + a red-team pass closed off several prototype-pollution-adjacent lookup paths (a mail header literally called `constructor` / `toString` / `__proto__` could surface a JS function in the panel summary), tightened the IPv6 private-IP detector to recognise `::ffff:HHHH:HHHH` and `::N.N.N.N` mapped forms, scrubbed display-name PII out of the committed corpus fixtures, and pinned the existing "100 % offline" contract with explicit tests (no network APIs, no exfil-shaped DOM constructors, allowlist on `messenger.*` surface). See `CHANGELOG.md`.

---

User docs (install, usage, glossary, contribute) — pick your language:

- [Deutsch — README_DE.md](README_DE.md)
- [English — README_EN.md](README_EN.md)
- [Español — README_ES.md](README_ES.md)
- [Français — README_FR.md](README_FR.md)
- [Italiano — README_IT.md](README_IT.md)
- [中文 — README_ZH.md](README_ZH.md)
- [हिन्दी — README_HI.md](README_HI.md)
- [Português — README_PT.md](README_PT.md)
- [Polski — README_PL.md](README_PL.md)
- [العربية — README_AR.md](README_AR.md)
- [Русский — README_RU.md](README_RU.md)
- [日本語 — README_JA.md](README_JA.md)
- [한국어 — README_KO.md](README_KO.md)
- [Türkçe — README_TR.md](README_TR.md)
- [Tiếng Việt — README_VI.md](README_VI.md)
- [Bahasa Indonesia — README_ID.md](README_ID.md)
- [বাংলা — README_BN.md](README_BN.md)
- [فارسی — README_FA.md](README_FA.md)

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
