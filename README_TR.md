# mleak — Thunderbird için posta-başına OSINT

*Diller: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)*

**Kaynak:** <https://github.com/c0decave/mleak/>

**Kısa açıklama.** mleak, her e-postanın başlık ve gövdesini adli olarak inceleyen bir Thunderbird eklentisidir. MUA parmak izleri, sunucu yığını, M365 tenant verisi, aktarım yolu, kimlik doğrulama yargıları, e-posta listesi belirteçleri, doğrudan gönderen IP sızıntıları, başlık sırası parmak izi, MIME sınır ipuçları, kripto sinyaller ve bütünlük bulgularını tamamen çevrimdışı ortaya koyar.

WebExtension · Thunderbird 115+ · 100 % offline · MPL-2.0.

---

## Öne çıkanlar

mleak'in her mesaj için ortaya çıkardıkları:

- **İstemci / MUA**: `User-Agent`, `Message-ID` desenleri, HTML imzaları, MIME sınırlarından çapraz doğrulama
- **Sunucu yığını**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · Proofpoint · Mimecast · Barracuda
- **Aktarım yolu**: hop sayısı, dış IP'ler, **iç hostname sızıntıları**, **RFC1918 IP** hop bazında
- **Kimlik doğrulama**: SPF / DKIM / DMARC / ARC / BIMI yargıları + DKIM imzaları (alan, seçici)
- **Kripto**: Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, ProtonMail, Tutanota — başlık ve sınır
- **Bütünlük**: Date/MID eksik, From↔Sender uyuşmazlığı, Reply-To etki alanları arası, DKIM h= anomalileri
- **%100 çevrimdışı**: ağ yok, telemetri yok, dış bağımlılık yok

---

## Kurulum

### Geçici (geliştirme)
1. `Araçlar → Eklentiler ve Temalar → ⚙ → Eklentileri Hata Ayıkla → Geçici Eklenti Yükle …`
2. Bu dizinden `manifest.json` seç.

### Paketlenmiş
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (geçerli: 0.6.12)
```
Ardından: `Araçlar → Eklentiler → ⚙ → Dosyadan Eklenti Yükle …` ve XPI'yi seç.

---

## Kullanım

**Popup modu** varsayılandır: ileti araç çubuğundaki simgeye tıklamak tüm istihbarat kartlarını içeren popup'ı açar. **body-inline modu** (isteğe bağlı) mleak panelini ileti gövdesinin üstünde otomatik olarak gösterir; simge sonra paneli açıp kapatır. Ayarlar: `Araçlar → Eklentiler → mleak → Tercihler`.

---

## Güvenlik ve gizlilik

| Özellik | Durum |
|---|---|
| Ağ istekleri | **yok** (`fetch`, `XHR`, `sendBeacon`, `WebSocket` kullanılmaz) |
| DOM enjeksiyonu | **yok** (yalnızca `textContent`/`createElement`) |
| İzinler | `messagesRead` · `messagesModify` · `storage` · `tabs` (`<all_urls>` yok) |
| Depolama | yalnızca UI tercihleri `storage.local`'da; **e-posta içeriği saklanmaz** |
| Hata ayıklama günlüğü | isteğe bağlı, sınırlı halka tampon (en fazla 500 girdi, başlıklar olmadan) |

---

## Tam belgeler

Ayrıntılı kılavuz (özellikler, sözlük, tehdit modeli, sürüm notları): [README_EN.md](README_EN.md).

---

## Katkı

mleak'in MUA veya sunucu yığınını tanımadığı bir e-postayla karşılaştınız ve hangi istemci/üründen geldiğini biliyor musunuz? İlgili başlıkları (Received, Message-ID, X-*, Authentication-Results, User-Agent) `mlux@undisclose.de` adresine **mleak-sample** konusuyla gönderin. Kişisel adresleri gizleyebilirsiniz; başlıkların kendisini değil.

---

## Lisans

**Mozilla Public License 2.0** altında lisanslıdır — [LICENSE](LICENSE) bakınız.
