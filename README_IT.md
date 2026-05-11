<p align="center">
  <img src="branding/logo-256.png" alt="mleak logo" width="160">
</p>

# mleak — OSINT per-email per Thunderbird

*Lingue: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)*

**Sorgente:** <https://github.com/c0decave/mleak/>

**Descrizione breve.** mleak è un'estensione Thunderbird per l'analisi forense di header e corpo di ogni email. Espone fingerprint MUA, stack server, dati tenant M365, percorso dei relay, verdetti di autenticazione, marcatori di mailing list, fughe dirette di IP del mittente, fingerprint dell'ordine degli header, indizi sui boundary MIME, segnali crittografici e controlli di integrità — completamente offline.

WebExtension · Thunderbird 115+ · 100 % offline · MPL-2.0.

---

## Punti salienti

Cosa mleak espone per ogni messaggio:

- **Client / MUA** da `User-Agent`, pattern `Message-ID`, firme HTML, boundary MIME — verifica incrociata
- **Stack server**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · Proofpoint · Mimecast · Barracuda
- **Percorso relay**: numero di hop, IP esterni, **fughe di hostname interni**, **IP RFC1918** per-hop
- **Autenticazione**: verdetti SPF / DKIM / DMARC / ARC / BIMI + firme DKIM (dominio, selettore)
- **Crypto**: Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, ProtonMail, Tutanota — header e boundary
- **Integrità**: Date/MID mancanti, From↔Sender divergenti, Reply-To cross-domain, anomalie DKIM h=
- **100 % offline**: nessuna rete, nessuna telemetria, nessuna dipendenza esterna

---

## Installazione

### Temporanea (sviluppo)
1. `Strumenti → Componenti aggiuntivi e Temi → ⚙ → Debug dei componenti aggiuntivi → Carica componente aggiuntivo temporaneo …`
2. Selezionare `manifest.json` da questa directory.

### Pacchettizzata
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (attuale: 0.6.12)
```
Poi: `Strumenti → Componenti aggiuntivi → ⚙ → Installa componente da file …` e selezionare l'XPI.

---

## Uso

**Modalità popup** è quella predefinita: clic sull'icona nella barra del messaggio apre il popup con tutte le card di intel. La **modalità body-inline** (opzionale) mostra il pannello mleak automaticamente sopra il corpo della mail; l'icona allora alterna il pannello. Impostazioni: `Strumenti → Componenti aggiuntivi → mleak → Preferenze`.

---

## Sicurezza e privacy

| Proprietà | Stato |
|---|---|
| Richieste di rete | **nessuna** (niente `fetch`, `XHR`, `sendBeacon`, `WebSocket`) |
| Iniezione DOM | **nessuna** (solo `textContent`/`createElement`) |
| Permessi | `messagesRead` · `messagesModify` · `storage` · `tabs` (nessun `<all_urls>`) |
| Memoria | solo preferenze UI in `storage.local`; **nessun contenuto delle mail** |
| Log di debug | opt-in, ring buffer limitato (max 500 voci, senza header) |

---

## Documentazione completa

Guida dettagliata (funzionalità, glossario, modello di minaccia, cronologia versioni): [README_EN.md](README_EN.md).

---

## Contribuire

Hai trovato una mail il cui MUA o stack server mleak *non* riconosce, e sai da quale client/prodotto proviene? Invia gli header rilevanti (Received, Message-ID, X-*, Authentication-Results, User-Agent) a `mlux@undisclose.de` con oggetto **mleak-sample**. Puoi oscurare gli indirizzi personali; non oscurare mai gli header stessi.

---

## Licenza

Distribuita sotto **Mozilla Public License 2.0** — vedere [LICENSE](LICENSE).
