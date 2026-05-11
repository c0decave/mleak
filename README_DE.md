<p align="center">
  <img src="branding/logo-256.png" alt="mleak logo" width="160">
</p>

# mleak — Per-Mail-OSINT für Thunderbird

*Sprachen: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)*

**Quelle:** <https://github.com/c0decave/mleak/>

**Kurzbeschreibung.** mleak ist eine Thunderbird-Erweiterung für forensische Header- und Body-Analyse einzelner E-Mails. Sie extrahiert MUA-Fingerprint, Server-Stack, M365-Tenant-Daten, Relay-Pfad, Auth-Verdicts, Mailinglisten-Marker, direkte Sender-IP-Leaks, Header-Order-Fingerprints, MIME-Boundary-Hinweise, Crypto-Signale und Integritätsbefunde — vollständig offline.

WebExtension für Thunderbird 115+. Analysiert pro Mail Header und Body und zeigt strukturierte OSINT-Intel — entweder im Popup oder direkt inline über dem Mail-Text.

- **MUA / Client**: aus `User-Agent`, `Message-ID`-Pattern, HTML-Body-Signaturen, `MIME-Version`-Parenthetical, MIME-Boundary-Prefixes (Apple-Mail / enig / _000_ / _NextPart_) und Authored-Header-Reihenfolge — sechs unabhängige Signale, Kreuzvalidierung
- **Server-Stack**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · Delivery-Marker (Proofpoint / Mimecast / Barracuda)
- **M365-Tenant-GUID** + **Datacenter-Region**: direkte Org-Attribution ohne Whois
- **Relay-Pfad**: Hop-Count, externe Relays, **interne Hostname-Leaks** (inkl. Single-Label-NetBIOS / k8s-Pod-Namen), **private IPs** aus Received (IPv4 + IPv6 ULA / link-local), Per-Hop-Kontext („10.x.x.x at relay.example.com from ws-eve.corp.local")
- **Direkte Sender-IP-Leaks**: `X-Originating-IP`, `X-Forwarded-For`, `X-Real-IP` und verwandte Header, inklusive scoped IPv6 und IPv4-mapped IPv6
- **Mailinglisten-Marker**: Standard-`List-*`-Header plus Mailman-, Sympa-, Google-Groups-, Listserv/LSV- und ezmlm-Fingerprints
- **Authentifizierung**: SPF / DKIM / DMARC / ARC / BIMI Verdicts + DKIM-Signaturen (Domain, Selektor, Vendor-Hint)
- **Crypto**: Enigmail-Version (via `X-Enigmail-Version` oder `enig…`-Boundary-Prefix), OpenPGP/MIME, S/MIME, Autocrypt / Autocrypt-Gossip, OpenPGP-Keyserver-Hint, Symantec PGP-Universal, Tutanota, ProtonMail
- **Integrität**: fehlendes Date/MID, From↔Sender-Divergenz, Reply-To-Cross-Domain, DKIM h=-Coverage-Lücken, Oversigning
- **Zeitzone**: Normierung auf UTC + TZ-Offset
- **MIME-Struktur**: kompakter, größenbegrenzter Baum-Fingerprint
- **Per-Card-Sichtbarkeit**: jede der sieben Karten in den Einstellungen ein-/ausblendbar

**100 % offline.** Kein Netzwerkzugriff, keine Telemetrie, keine externen Abhängigkeiten. Roh-Mail-Bytes verlassen nie den Thunderbird-Prozess.

---

## Installation

### Temporär (Entwicklung)
1. `Extras → Add-ons und Themes → ⚙ → Debug Add-ons → Temporäres Add-on laden …`
2. `manifest.json` aus diesem Verzeichnis auswählen.

### Gepackt
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (aktuell: 0.6.12)
```
Dann: `Extras → Add-ons → ⚙ → Add-on aus Datei installieren …` und die XPI auswählen. Für die `xpinstall.signatures.required=false`-Unterstützung muss dein Thunderbird-Build das erlauben (Distro-Builds wie Arch / Debian / ESR tun das häufig).

---

## Nutzung

**Popup-Modus** bleibt Standard: Icon in der Nachrichten-Toolbar klicken → Popup öffnet sich mit allen Intel-Karten. Optional kann der **Body-Inline-Modus** aktiviert werden; dann erscheint das mleak-Panel automatisch oberhalb des Mail-Texts, ohne Icon-Klick. Das Icon blendet das Inline-Panel dann ein bzw. aus.

Einstellungen erreichen: `Extras → Add-ons → mleak → Einstellungen`. Optionen:
- Farbschema (auto / dunkel / hell)
- Popup-Breite (440 / 500 / 600 / 720 px) — 600 ist Default
- Dichte (kompakt / normal / luftig)
- Standard-Ansicht (Karten / JSON)
- Anzeige-Modus (Popup / Body-Inline oberhalb des Mail-Texts)
- Sichtbare Karten (jede der sieben Kategorien ein-/ausblendbar)
- Analyse-Cache-Größe + Jetzt-leeren-Button
- Debug-Log (opt-in) + Log-Viewer
- About (Version + Aufruf zur Fingerprint-Einsendung)

---

## Sicherheit & Datenschutz

| Eigenschaft | Status |
|---|---|
| Netzwerk-Requests | **keine** (kein `fetch`, `XHR`, `sendBeacon`, `WebSocket`) |
| DOM-Injection | **keine** (nur `textContent`/`createElement`; kein `innerHTML` mit dynamischen Werten) |
| CSP | streng: `script-src 'self'; object-src 'none'; base-uri 'none'` |
| Berechtigungen | **offline und eng begrenzt**: `messagesRead` + `messagesModify` + `storage` + `tabs` (`messagesModify` nur für Thunderbird-`messageDisplayScripts`; kein `<all_urls>`) |
| Storage | nur UI-Präferenzen in `storage.local`; **keine Mail-Inhalte** |
| Debug-Log | opt-in, bereinigter Ring-Buffer (max. 500 Einträge, begrenzte Status-Strings, keine Header) |
| ReDoS-/Fan-out-Schutz | Längen-Caps auf Header-Values (8 KB), Message-IDs (1 KB), MIME-Tree-Breite, wiederholte Header, Raw-JSON und UI-Zeilen |

Jede Zeile ist auditierbar. Technische Details, Detektor-Architektur, Threat-Model und Build-Anleitung liegen in [DEVELOPING.md](DEVELOPING.md).

---

## Glossar

Begriffe, die im Popup und Inline-Panel auftauchen:

- **MUA** — Mail User Agent; das E-Mail-Programm, mit dem die Nachricht verfasst wurde (Thunderbird, Outlook, Apple Mail, …).
- **Server Stack** — das serverseitige Produkt, durch das die Mail lief (Gmail, Exchange/M365, Apple iCloud, Yahoo, Proofpoint, Mimecast, Barracuda).
- **M365 Tenant** — die GUID, die Microsoft 365 ausgehenden Mails in den Headern beigibt; identifiziert die Absender-Organisation direkt, ohne Whois.
- **Relay path** — die Liste externer Server (`by`-Hosts in der Received-Chain), durch die die Mail gelaufen ist, oben = erster Hop.
- **Private IP leak** — eine RFC-1918-Adresse (10.x.x.x, 172.16–31.x.x, 192.168.x.x) in den Received-Headern; legt das interne LAN des Absenders offen.
- **Internal hostname leak** — ein `.local` / `.corp` / `.internal` / `.lan`-Hostname in Received; legt das Intranet des Absenders offen.
- **Auth verdicts** — SPF, DKIM, DMARC, ARC, BIMI Pass/Fail, wie vom Empfänger-MTA protokolliert.
- **Header-Order-Fingerprint** — Reihenfolge der authored Header wie `Subject`, `Date`, `From`, `To`, `Message-ID`; hilfreich, um MUA-Selfreport-Widersprüche zu erkennen.
- **Direkter Sender-IP-Leak** — Sender- oder Forwarding-IPs in `X-Originating-IP`, `X-Forwarded-For`, `X-Real-IP` und ähnlichen Headern. Private/lokale Bereiche werden hervorgehoben.
- **Mailinglisten-Marker** — `List-*`- und MLM-spezifische Header (Mailman, Sympa, Google Groups, Listserv/LSV, ezmlm), die Listensoftware und Posting-Kontext verraten.
- **DKIM oversigning** — ein Header-Name wird **mehrfach** im `h=`-Tag einer DKIM-Signatur gelistet (z. B. `h=from:from:subject:subject`). Schutz gegen Header-Injection: fügt ein späterer Relay ein zweites `From:` hinzu, bricht die Signatur, statt einen gefälschten Header stillschweigend zu validieren.
- **DKIM h=-Coverage-Lücke** — ein sicherheitsrelevanter Header (`From`, `Subject`, `Reply-To`, `Date`, `Message-ID`) fehlt im `h=`-Tag der Signatur, d. h. er lässt sich unterwegs verändern, ohne die Signatur zu brechen.
- **Hop count** — Anzahl der Received-Header in der Chain. Plötzliche Sprünge gegenüber der Baseline sind oft Forwarding-/Relay-Rewrite-Evidenz.
- **Chronology anomaly** — Received-Zeitstempel sind nicht monoton abnehmend; meist Relay-Clock-Drift, gelegentlich Chain-Manipulation.
- **Integrity flags** — strukturelle Auffälligkeiten: fehlender Date/Message-ID, From↔Sender-Divergenz, Reply-To-Cross-Domain.
- **Enigmail** — Thunderbird-PGP-Add-on. Erkannt über `X-Enigmail-Version` *oder* über den `-------enig…`-MIME-Boundary-Prefix (überlebt Header-Stripping).
- **OpenPGP/MIME** — RFC 3156 encrypted/signed Multipart; erkannt via `multipart/{encrypted,signed}` + `protocol=application/pgp-*`.
- **S/MIME** — RFC 2633 / PKCS#7 Sign/Encrypt; erkannt via `application/(x-)?pkcs7-*`-Content-Types.
- **Autocrypt** — RFC-Draft-Header für automatischen Key-Exchange; Anwesenheit ist ein MUA-Capability-Signal.
- **Boundary-MUA-Hinweis** — MUAs stempeln Produkt-Prefixes in MIME-Boundaries (`Apple-Mail=`, `_000_`, `_NextPart_`, `----=_Part_`). Da Boundaries Relay-Rewrites überleben, sind sie ein MUA-Fingerprint **auch bei verschlüsselten Mails**, wo der HTML-Body-Scanner nichts sieht.

---

## Versionen

- **0.6.12** — Security- und Privacy-Härtungs-Pass. Vier Prototype-Pollution-Pfade in `header_order` / `crypto_headers` / `body_html` / `detectors` geschlossen (eine Mail mit Header-Namen `constructor`/`__proto__` konnte vorher eine JS-Funktion ins Popup-Summary einschleusen). `isPrivateIP` erkennt jetzt auch die Hex-Form von IPv4-mapped IPv6 (`::ffff:0a00:0001`) und das alte `::N.N.N.N`. Klar-Namen aus den 100 committed Corpus-Fixtures anonymisiert. „100 % offline“-Vertrag mit fünf neuen Tests verriegelt (keine Exfil-DOM-Konstruktoren, `target=_blank` muss `rel=noopener noreferrer` tragen, `tabs.create`-URLs nur via `runtime.getURL`, vollständige `messenger.*`-API-Allowlist). 0 Crashes / 0 Schema-Verstöße über alle 103 Tier-1-Fixtures. Siehe [CHANGELOG.md](CHANGELOG.md).
- **0.6.5** — Release-Build für den erweiterten Offline-OSINT-Katalog und die Härtungsrunde: corpus-basierte Message-ID-/Client-/MIME-Boundary-/Mailinglisten-/Sender-IP-/Server-Stack-/Header-Order-Signale, strengere Runtime-Message- und Tab-/Message-ID-Prüfungen, begrenzter Debug-Storage, gecapptes Raw-JSON- und UI-Rendering, MIME-/Header-Fan-out-Limits und Längencaps bevor Leak-Werte in Summary/UI auftauchen. Neu gebaut als `dist/mleak-0.6.5.xpi`. Siehe [CHANGELOG.md](CHANGELOG.md).
- **0.6.3** — `displayMode` ersetzt den alten `inlineMode` (`popup` als Default, `bodyInline` aktivierbar, `headerInline` reserviert). Body-Inline ist wieder in den Einstellungen verfügbar und nutzt `messageDisplayScripts.register()` für neu geöffnete Nachrichten plus `executeScript`-Fallback für bereits offene Tabs; ein kurzer Retry verhindert dabei die Race-Condition zwischen `onMessageDisplayed` und frisch registriertem Message-Display-Script. Review-Fix: `messagesModify` ist nun explizit deklariert, weil Thunderbird diese Permission für `messageDisplayScripts.*` verlangt. Der neue Headless-Smoke prüft, dass das Panel im echten Thunderbird-Frame `browser#messagepane` erscheint. Keine Netzwerkzugriffe.
- **0.6.2** — Offline-OSINT-Erweiterung: Header-Order-Fingerprints mit UA-Konsistenzchecks, MIME-Boundary-Familienerkennung, Mailinglisten-Fingerprints, direkte Sender-IP-Leak-Erkennung, Crypto-Header-Aggregation und Anzeige in Popup-/Inline-Summaries. Parser-Hardening für wiederholte Authentication-Results, gefaltete/groß-kleingemischte DKIM-Tags, Date-Offsets mit trailing comments, umgedrehte HTML-Generator-Meta-Attribute, wiederholte Sender-IP-Header, IPv6-`Received`-Literals, scoped/mapped IPv6, malformed-IPv6-Rejection und größenbegrenztes MIME-Tree-Rendering. Das XPI macht weiterhin keinerlei Internetzugriffe.
- **0.5.9** — Fix: Toolbar- und Nachrichtenkopf-Icons waren unsichtbar, weil `icons/logo.svg` `stroke="currentColor"` ohne CSS-Kontext beim Rasterisieren nutzte; Manifest liefert nun explizite PNG-Icons in 16/32/48/96 px. Vorschaubilder nach `branding/` verschoben (nicht im XPI enthalten).
- **0.5.8** — lizenziert unter **MPL-2.0** (LICENSE + SPDX-Header in jeder Quelldatei); i18n auf neun Sprachen erweitert (zh, hi, pt hinzugefügt); User-READMEs jetzt in sieben Sprachen (DE/EN/ES/ZH/HI/PT/PL); LICENSE im XPI enthalten.
- **0.5.6** — User-Doku von Entwickler-Doku getrennt; XPI enthält jetzt alle drei Sprach-READMEs; Release-Pipeline (`scripts/release.sh`) erzeugt exakt `.xpi` + `.sha256`, sonst nichts.
- **0.5.5** — XPI enthält jetzt `README_DE.md` / `README_EN.md` / `README_ES.md` neben dem Index; Regression-Test sichert das Layout ab.
- **0.5.4** — Red-Team-Hygiene: `inline/inline.js` prüft Nachrichten-Payload-Shape symmetrisch zu `background.js`; TB-Binary wird über absoluten Pfad aufgerufen — ein ambient-PATH-Risiko weniger.
- **0.5.3** — Defense-in-Depth-Hardening: `SAFE_HTML_KEYS`-Allowlist gated jeden `data-i18n-html`-Key in `lib/i18n.js`; Manifest-Version wird format-validiert bevor sie in die About-Karte per innerHTML landet; `runtime.onMessage`-Eingang typisiert jetzt `msg.type` + `msg.messageId`.
- **0.5.2** — Zwei Correctness-Nits aus statischer Analyse: `mid_patterns.js` prüft `domain.endsWith("gmail.com")` jetzt exact-or-subdomain; Mutt-Regex in `ua_parser.js` hatte überlappende Character-Class, vereinfacht.
- **0.5.1** — Inline-Modus-UI vorübergehend deaktiviert (Per-Layout-Injection-Bug); Detektor-Fehler laufen jetzt durch den opt-in Debug-Log; Startup-IIFE gegen unhandled Promise Rejections abgesichert. Security-Audit: kein Netzwerk, keine Obfuscation, kein Backdoor-ähnlicher Code, `messages.getFull` genau ein Call-Site gated hinter eigenen Message-Types.
- **0.5.0** — Neuer `crypto_headers.js`-Detektor (Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, Gateway-Header, Boundary-Prefix-MUA-Hinweise). Received-Chain-Fixes: by-Parenthetical-Parsing, `from [IP]` HELO-Bare-IP-Extraktion, Single-Label-Internal-Host-Heuristik mit Sentinel-Filter, IPv6-Private-Ranges (ULA / link-local / mapped). MIME-Version-Parenthetical als zweite MUA-Quelle. Latenter `ReferenceError` in External-Relay-Loop gefixt.
- **0.4.2** — by-side-Parenthetical-Capture + Single-Label-Hostname-Erkennung (1&1 k8s-Pod-Name / NetBIOS-Leak-Klasse).
- **0.4.1** — Inline-Lifecycle-Rewrite auf `onMessageDisplayed` + `tabs.executeScript` mit verbose dlog (Versuch, Inline-Mode stabil zu machen; teilweise erfolgreich — in 0.5.1 trotzdem deaktiviert).
- **0.4.0** — Per-Card-Sichtbarkeit (7 Karten), Per-Hop-Kontext für Leaks, vertikaler Relay-Pfad, Glossar in EN/DE/ES, About-Section mit Contribute-CTA.
- **0.3.0** — i18n in sechs Sprachen (en/de/es/fr/pl/it), Umschlag+Lupe-Icon, mehrsprachige READMEs, `default_locale` gesetzt.
- **0.2.0** — Inline-Modus (erster Versuch), Einstellungs-Seite, responsiver Popup, Security-Hardening (Length-Caps, ReDoS-Schutz), SVG-Logo, Rename zu *mleak*.
- **0.1.0** — Initial-Release: Popup + 9 Detektor-Module.

---

## Unbekannte MUA- / Server-Fingerprints beisteuern

Mail gefunden, die die Erweiterung **nicht klassifizieren** konnte — und du weißt, welcher Client oder Server-Stack sie erzeugt hat? Bitte schick uns die relevanten Header. Solche Beiträge sind der einzige Weg, den Detektor-Katalog sinnvoll wachsen zu lassen.

So geht's:

1. Mail öffnen, Ansicht → Quelltext der Nachricht (oder Strg+U).
2. Den oberen Header-Block bis zur ersten Leerzeile kopieren — also `Received:` über `Message-ID:`, `User-Agent:` und alles, was auffällig wirkt.
3. Notier den Client / Webmailer / Relay-Product, den du kennst (oder vermutest).
4. Persönliche Adressen gern schwärzen; **niemals `Received`, `Message-ID`, `X-*` oder Auth-Header entfernen** — genau die brauchen wir.
5. Mail an: **mlux@undisclose.de**, Betreff beginnend mit `mleak-sample`.

Alternativ Issue oder PR unter **<https://github.com/c0decave/mleak/>**.

---

~ Proudly engineered with Claude ~

## Lizenz

Lizenziert unter der **Mozilla Public License 2.0** — siehe [LICENSE](LICENSE).

MPL-2.0 ist eine Copyleft-Lizenz auf Datei-Ebene: Änderungen an MPL-Dateien müssen MPL bleiben, aber mleak darf frei mit anders lizenziertem (auch proprietärem) Code zu einem „Larger Work" kombiniert werden. Die Lizenz enthält eine ausdrückliche Patent-Klausel.

Kontakt: mlux@undisclose.de
