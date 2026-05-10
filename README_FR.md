# mleak — OSINT par e-mail pour Thunderbird

*Langues: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)*

**Source :** <https://github.com/c0decave/mleak/>

**Description courte.** mleak est une extension Thunderbird pour l'analyse forensique des en-têtes et du corps de chaque message. Elle révèle les empreintes MUA, la pile serveur, les données de tenant M365, le chemin des relais, les verdicts d'authentification, les marqueurs de listes de diffusion, les fuites directes d'IP de l'expéditeur, les empreintes d'ordre des en-têtes, les indices de frontière MIME, les signaux cryptographiques et les vérifications d'intégrité — entièrement hors-ligne.

WebExtension · Thunderbird 115+ · 100 % offline · MPL-2.0.

---

## Points forts

Ce que mleak révèle pour chaque message :

- **Client / MUA** depuis `User-Agent`, motifs `Message-ID`, signatures HTML, frontières MIME — recoupement
- **Pile serveur** : Gmail · Exchange/M365 · Apple iCloud · Yahoo · Proofpoint · Mimecast · Barracuda
- **Chemin des relais** : nombre de sauts, IPs externes, **fuites de noms internes**, **IPs RFC1918** par-saut
- **Authentification** : verdicts SPF / DKIM / DMARC / ARC / BIMI + signatures DKIM (domaine, sélecteur)
- **Crypto** : Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, ProtonMail, Tutanota — détection par en-tête et frontière
- **Intégrité** : Date/MID manquant, From↔Sender divergent, Reply-To croisé, anomalies DKIM h=
- **100 % hors-ligne** : aucun réseau, aucune télémétrie, aucune dépendance externe

---

## Installation

### Temporaire (développement)
1. `Outils → Modules complémentaires et thèmes → ⚙ → Déboguer les modules → Charger un module temporaire …`
2. Sélectionner `manifest.json` dans ce répertoire.

### Packagé
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (actuelle: 0.6.12)
```
Puis : `Outils → Modules complémentaires → ⚙ → Installer un module à partir d'un fichier …` et choisir le XPI.

---

## Utilisation

**Mode popup** par défaut : cliquer sur l'icône dans la barre du message ouvre la popup avec toutes les cartes d'intel. Le **mode body-inline** (optionnel) affiche le panneau mleak automatiquement au-dessus du corps du message ; l'icône bascule alors le panneau. Réglages : `Outils → Modules complémentaires → mleak → Préférences`.

---

## Sécurité et confidentialité

| Propriété | État |
|---|---|
| Requêtes réseau | **aucune** (pas de `fetch`, `XHR`, `sendBeacon`, `WebSocket`) |
| Injection DOM | **aucune** (uniquement `textContent`/`createElement`) |
| Permissions | `messagesRead` · `messagesModify` · `storage` · `tabs` (pas de `<all_urls>`) |
| Stockage | préférences UI uniquement dans `storage.local` ; **aucun contenu de mail** |
| Journal de débogage | opt-in, anneau borné (max 500 entrées, sans en-têtes) |

---

## Documentation complète

Guide détaillé (fonctionnalités, glossaire, modèle de menaces, historique des versions) : [README_EN.md](README_EN.md).

---

## Contribuer

Trouvé un mail dont mleak ne reconnaît *pas* le MUA ou la pile serveur, et vous savez d'où il vient ? Envoyez les en-têtes pertinents (Received, Message-ID, X-*, Authentication-Results, User-Agent) à `mlux@undisclose.de` avec le sujet **mleak-sample**. Vous pouvez masquer les adresses personnelles ; ne masquez jamais les en-têtes eux-mêmes.

---

## Licence

Sous licence **Mozilla Public License 2.0** — voir [LICENSE](LICENSE).
