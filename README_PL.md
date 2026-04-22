# mleak — OSINT per-mail dla Thunderbirda

*Języki: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md)*

**Źródło:** <https://github.com/c0decave/mleak/>

**Krótki opis.** mleak to rozszerzenie Thunderbirda do kryminalistycznej analizy nagłówków i treści każdej wiadomości. Pokazuje odciski palców MUA, stack serwera, dane tenanta M365, trasę przekaźników, werdykty uwierzytelniania i sygnały integralności — w pełni offline.

WebExtension dla Thunderbirda 115+. Analizuje nagłówki i treść osobno dla każdej wiadomości i wyświetla ustrukturyzowane dane OSINT — jako popup lub bezpośrednio inline nad treścią wiadomości.

- **MUA / klient**: z `User-Agent`, wzorców `Message-ID`, sygnatur HTML-body, parentetyków MIME-Version i prefiksów granicy MIME (Apple-Mail / enig / _000_ / _NextPart_) — pięć niezależnych sygnałów, krzyżowo walidowanych
- **Stack serwera**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · znaczniki dostarczania (Proofpoint / Mimecast / Barracuda)
- **GUID tenanta M365** + **region datacenter**: bezpośrednia atrybucja organizacyjna bez whois
- **Trasa przekaźników**: liczba hopów, przekaźniki zewnętrzne, **wycieki wewnętrznych nazw hostów** (w tym NetBIOS z pojedynczą etykietą / nazwy podów k8s), **prywatne IP** z Received (IPv4 + IPv6 ULA / link-local), kontekst per-hop ("10.x.x.x przez relay.example.com z ws-eve.corp.local")
- **Uwierzytelnianie**: werdykty SPF / DKIM / DMARC / ARC / BIMI + sygnatury DKIM (domena, selector, wskazówka vendor)
- **Kryptografia**: wersja Enigmail (przez `X-Enigmail-Version` lub prefiks granicy `enig…`), OpenPGP/MIME, S/MIME, Autocrypt / Autocrypt-Gossip, wskazówka keyserver OpenPGP, Symantec PGP-Universal, Tutanota, ProtonMail
- **Integralność**: brakujące Date/MID, rozbieżność From↔Sender, Reply-To w innej domenie, luki w pokryciu h= DKIM, oversigning
- **Strefa czasowa**: normalizacja UTC + offset TZ
- **Struktura MIME**: zwarty odcisk drzewiasty
- **Przełączniki widoczności per-karta**: schowaj dowolną z siedmiu kart ze strony opcji

**100 % offline.** Brak dostępu do sieci, brak telemetrii, brak zewnętrznych zależności. Surowe bajty maila nigdy nie opuszczają procesu Thunderbirda.

---

## Instalacja

### Tymczasowa (dev)
1. `Narzędzia → Dodatki i motywy → ⚙ → Debuguj dodatki → Wczytaj tymczasowy dodatek…`
2. Wybierz `manifest.json` z tego katalogu.

### Spakowana
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (aktualnie: 0.5.8)
```
Następnie: `Narzędzia → Dodatki → ⚙ → Zainstaluj dodatek z pliku…` i wybierz XPI. Żeby `xpinstall.signatures.required=false` zadziałało, Twoja kompilacja Thunderbirda musi na to pozwalać (kompilacje dystrybucyjne Arch / Debian / ESR zwykle pozwalają).

---

## Użycie

**Tryb popup** (domyślny i obecnie jedyny): kliknij ikonę w pasku narzędzi wiadomości → otworzy się popup z wszystkimi kartami OSINT. Tryb inline-panel jest wciąż wyłączony, dopóki nie zostanie namierzony bug z iniekcją zależny od układu — ścieżki kodu są na miejscu, a ponowne włączenie to zmiana jednego wiersza po naprawie przyczyny.

Otwórz ustawienia: `Narzędzia → Dodatki → mleak → Preferencje`. Opcje:
- Schemat kolorów (auto / ciemny / jasny)
- Szerokość popupu (440 / 500 / 600 / 720 px) — 600 to domyślna
- Gęstość (kompaktowa / normalna / luźna)
- Domyślny widok (karty / JSON)
- Widoczne karty (ukryj dowolną z siedmiu kategorii)
- Rozmiar cache analizy + przycisk wyczyść teraz
- Log debug (opt-in) + przeglądarka logów
- O rozszerzeniu (wersja + wezwanie do udostępniania nierozpoznanych odcisków)

---

## Bezpieczeństwo i prywatność

| Właściwość | Status |
|---|---|
| Zapytania sieciowe | **brak** (brak `fetch`, `XHR`, `sendBeacon`, `WebSocket`) |
| Wstrzyknięcia DOM | **brak** (tylko `textContent`/`createElement`; brak `innerHTML` z dynamicznymi wartościami) |
| CSP | ścisłe: `script-src 'self'; object-src 'none'; base-uri 'none'` |
| Uprawnienia | **minimalne**: tylko `messagesRead` + `storage` + `tabs` (brak `messagesModify`, brak `<all_urls>`) |
| Przechowywanie | jedynie preferencje UI w `storage.local`; **żadnej treści maili** |
| Log debug | opt-in, bufor pierścieniowy (maks. 500 wpisów, tylko napisy stanu, brak nagłówków) |
| Ochrona ReDoS | limity długości wartości nagłówków (8 KB) + Message-ID (1 KB) przed dopasowaniem regex |

Każda linia jest audytowalna. Szczegóły techniczne, architektura detektorów, model zagrożeń i instrukcja builda są w [DEVELOPING.md](DEVELOPING.md).

---

## Słownik

Terminy, które zobaczysz w popupie i w panelu inline:

- **MUA** — Mail User Agent; klient pocztowy, który napisał wiadomość (Thunderbird, Outlook, Apple Mail, …).
- **Stack serwera** — produkt server-side, przez który przeszedł mail (Gmail, Exchange/M365, Apple iCloud, Yahoo, Proofpoint, Mimecast, Barracuda).
- **Tenant M365** — GUID, który Microsoft 365 wbija w nagłówki wychodzących maili; bezpośrednia identyfikacja organizacji nadawcy bez whois.
- **Trasa przekaźników** — lista zewnętrznych serwerów (hosty `by` w łańcuchu Received), przez które przeszedł mail, góra = pierwszy hop.
- **Wyciek prywatnego IP** — adres RFC 1918 (10.x.x.x, 172.16-31.x.x, 192.168.x.x) ujawniony w nagłówkach Received; zdradza wewnętrzną sieć nadawcy.
- **Wyciek wewnętrznej nazwy hosta** — nazwa hosta w stylu `.local` / `.corp` / `.internal` / `.lan` w Received; zdradza intranet nadawcy.
- **Werdykty uwierzytelniania** — SPF, DKIM, DMARC, ARC, BIMI pass/fail wg odbiorcy.
- **DKIM oversigning** — wymienienie tej samej nazwy nagłówka **wielokrotnie** w tagu `h=` sygnatury DKIM (np. `h=from:from:subject:subject`). Udaremnia ataki wstrzyknięcia nagłówków: jeżeli późniejszy przekaźnik doda drugi `From:`, sygnatura się psuje, zamiast po cichu walidować sfałszowany nagłówek.
- **Luka pokrycia h= DKIM** — nagłówek istotny dla bezpieczeństwa (`From`, `Subject`, `Reply-To`, `Date`, `Message-ID`) *nie* jest wymieniony w tagu `h=`, co oznacza, że może zostać zmodyfikowany w tranzycie bez psucia sygnatury.
- **Liczba hopów** — liczba nagłówków Received w łańcuchu. Nagłe skoki względem bazowej wartości to często dowód na forwarding / przepisanie przez przekaźnik.
- **Anomalia chronologiczna** — znaczniki czasu Received nie maleją monotonicznie z góry na dół; zwykle dryf zegara przekaźnika, sporadycznie manipulacja łańcuchem.
- **Flagi integralności** — dziwactwa strukturalne: brakujące Date/Message-ID, rozbieżność From↔Sender, Reply-To w innej domenie.
- **Enigmail** — dodatek PGP do Thunderbirda. Wykrywany przez `X-Enigmail-Version` *lub* prefiks granicy MIME `-------enig…` (przetrwa usuwanie nagłówków).
- **OpenPGP/MIME** — multipart szyfrowany/podpisany wg RFC 3156; wykrywany przez `multipart/{encrypted,signed}` + `protocol=application/pgp-*`.
- **S/MIME** — RFC 2633 / PKCS#7 podpisany lub szyfrowany; wykrywany przez typy zawartości `application/(x-)?pkcs7-*`.
- **Autocrypt** — nagłówek automatycznej wymiany kluczy (RFC-draft); jego obecność to sygnał zdolności MUA.
- **Podpowiedź MUA z granicy** — MUA wstawiają prefiksy specyficzne dla produktu w granice MIME (`Apple-Mail=`, `_000_`, `_NextPart_`, `----=_Part_`). Ponieważ granica przetrwa przepisania przekaźnika, to przydatny odcisk MUA — *nawet dla zaszyfrowanych maili*, gdzie skanery body-HTML nie mają co analizować.

---

## Wersje

- **0.5.8** — licencja **MPL-2.0** (LICENSE + nagłówki SPDX w każdym pliku źródłowym); i18n rozszerzone do dziewięciu języków (dodane zh, hi, pt); READMEs użytkownika dostępne teraz w siedmiu językach (DE/EN/ES/ZH/HI/PT/PL); LICENSE spakowany w XPI.
- **0.5.6** — dokumenty użytkownika oddzielone od developerskich; XPI zawiera wszystkie READMEs użytkownika; pipeline release (`scripts/release.sh`) produkuje dokładnie `.xpi` + `.sha256`, nic więcej.
- **0.5.5** — XPI zawiera teraz `README_DE.md` / `README_EN.md` / `README_ES.md` obok indexu; test regresyjny wymusza układ.
- **0.5.4** — higiena red-team: payload on-message w `inline/inline.js` walidowany symetrycznie do `background.js`; binarka TB rozwiązywana przez ścieżkę absolutną (jeden mniej problem z ambient PATH).
- **0.5.3** — hardening obronny w głąb: allowlist `SAFE_HTML_KEYS` w `lib/i18n.js` bramkuje każdy klucz `data-i18n-html`; wersja z manifestu jest walidowana formatem przed wpisaniem do innerHTML karty About; entry-point `runtime.onMessage` type-check'uje `msg.type` + `msg.messageId`.
- **0.5.2** — dwie drobne poprawki z analizy statycznej: `mid_patterns.js` `domain.endsWith("gmail.com")` przeszło w dokładne lub sub-domenowe sprawdzanie; klasa znaków w regex Mutta w `ua_parser.js` uproszczona (nakładające się zakresy).
- **0.5.1** — UI trybu inline tymczasowo wyłączone (bug iniekcji zależny od układu); awarie detektorów trafiają do opt-in loga debug; startowe IIFE owinięte przeciwko nieobsłużonym rejekcjom promise. Pass audit: bez sieci, bez ofuskacji, bez kodu w kształcie backdoora, pojedyncze wywołanie `messages.getFull` zabramkowane naszymi własnymi typami wiadomości.
- **0.5.0** — nowy detektor `crypto_headers.js` (Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, nagłówki gateway, MUA z prefiksów granic). Poprawki łańcucha Received: parsowanie parentetyku by, ekstrakcja HELO-bare-IP z `from [IP]`, heurystyka pojedynczo-etykietowej nazwy wewnętrznej z filtrem sentinel, prywatne zakresy IPv6 (ULA / link-local / mapped). Parentetyk MIME-Version jako wtórne źródło MUA. Naprawiony latentny `ReferenceError` w pętli przekaźników zewnętrznych.
- **0.4.2** — przechwyt parentetyku po stronie by + detekcja pojedynczo-etykietowego hosta (klasa wycieku 1&1 nazw podów Kubernetes / NetBIOS).
- **0.4.1** — cykl życia trybu inline przepisany na `onMessageDisplayed` + `tabs.executeScript` z gadatliwym dlog (próba zmuszenia trybu inline do niezawodnej pracy; częściowo udana — wciąż wyłączony w 0.5.1).
- **0.4.0** — przełączniki widoczności per-karta (7 kart), kontekst per-hop w wierszach wycieków, pionowa trasa przekaźników, słownik EN/DE/ES, sekcja O rozszerzeniu z CTA wkładu.
- **0.3.0** — i18n w sześciu językach (en/de/es/fr/pl/it), ikona koperty-z-lupą, wielojęzyczne READMEs, ustawione `default_locale`.
- **0.2.0** — tryb inline (pierwsza próba), strona ustawień, responsywny popup, hardening bezpieczeństwa (limity długości, ochrona ReDoS), logo SVG, zmiana nazwy na *mleak*.
- **0.1.0** — pierwsze wydanie: popup + 9 modułów detektora.

---

## Wkład w nieznane odciski MUA / serwera

Znalazłeś maila, którego rozszerzenie **nie umiało zaklasyfikować** — a już wiesz, od jakiego klienta lub stacka serwera pochodzi? Prześlij nam odpowiednie nagłówki. Takie datki sprawiają, że katalog detektorów rośnie.

Co wysłać:

1. Otwórz maila, Widok → Źródło wiadomości (lub Ctrl+U).
2. Skopiuj blok nagłówków od góry do (i włącznie z) pierwszej pustej linii — mniej więcej od `Received:` po `Message-ID:`, `User-Agent:`, plus cokolwiek innego ciekawego.
3. Zanotuj, z jakiego klienta / webmaila / produktu przekaźnikowego pochodzi (lub domyślasz się).
4. Jeśli chcesz, zredaguj adresy prywatne; **nigdy nie redaguj `Received`, `Message-ID`, `X-*` ani nagłówków auth** — te są nam potrzebne.
5. Email: **mlux@undisclose.de**, temat zaczynający się od `mleak-sample`.

Jeśli wolisz Gita: otwórz issue lub PR na **<https://github.com/c0decave/mleak/>** z tymi samymi informacjami.

---

~ Proudly vibec0ded with Claude ~

## Licencja

Licencjonowane na **Mozilla Public License 2.0** — zobacz [LICENSE](LICENSE).

MPL-2.0 to licencja copyleft na poziomie pliku: modyfikacje plików MPL muszą pozostać pod MPL, ale mleak można swobodnie łączyć z kodem na innych licencjach (nawet zamkniętych) w ramach «Larger Work». Licencja zawiera wyraźną klauzulę patentową.

Kontakt: mlux@undisclose.de
