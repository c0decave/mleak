# mleak — OSINT per-surel untuk Thunderbird

*Bahasa: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)*

**Sumber:** <https://github.com/c0decave/mleak/>

**Deskripsi singkat.** mleak adalah ekstensi Thunderbird untuk analisis forensik header/badan setiap surel. Ia menampilkan sidik jari MUA, tumpukan server, data tenant M365, jalur relay, putusan autentikasi, penanda mailing list, kebocoran IP pengirim langsung, sidik jari urutan header, petunjuk batas MIME, sinyal kripto, dan temuan integritas — sepenuhnya luring.

WebExtension · Thunderbird 115+ · 100 % offline · MPL-2.0.

---

## Sorotan

Apa yang mleak ungkapkan per pesan:

- **Klien / MUA**: dari `User-Agent`, pola `Message-ID`, tanda tangan HTML, batas MIME — verifikasi silang
- **Tumpukan server**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · Proofpoint · Mimecast · Barracuda
- **Jalur relay**: jumlah hop, IP eksternal, **kebocoran hostname internal**, **IP RFC1918** per-hop
- **Autentikasi**: putusan SPF / DKIM / DMARC / ARC / BIMI + tanda tangan DKIM (domain, selector)
- **Kripto**: Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, ProtonMail, Tutanota — header dan boundary
- **Integritas**: Date/MID hilang, From↔Sender berbeda, Reply-To lintas domain, anomali DKIM h=
- **100% luring**: tanpa jaringan, tanpa telemetri, tanpa dependensi eksternal

---

## Pemasangan

### Sementara (pengembangan)
1. `Peralatan → Pengaya & Tema → ⚙ → Debug Pengaya → Muat Pengaya Sementara …`
2. Pilih `manifest.json` dari direktori ini.

### Dikemas
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (saat ini: 0.6.12)
```
Lalu: `Peralatan → Pengaya → ⚙ → Pasang Pengaya Dari Berkas …` dan pilih XPI.

---

## Penggunaan

**Mode popup** adalah bawaan: klik ikon di bilah alat pesan membuka popup dengan semua kartu intel. **Mode body-inline** (opsional) menampilkan panel mleak otomatis di atas badan surel; ikon kemudian mengalihkan panel. Pengaturan: `Peralatan → Pengaya → mleak → Preferensi`.

---

## Keamanan dan privasi

| Properti | Status |
|---|---|
| Permintaan jaringan | **tidak ada** (tanpa `fetch`, `XHR`, `sendBeacon`, `WebSocket`) |
| Injeksi DOM | **tidak ada** (hanya `textContent`/`createElement`) |
| Izin | `messagesRead` · `messagesModify` · `storage` · `tabs` (tanpa `<all_urls>`) |
| Penyimpanan | hanya preferensi UI di `storage.local`; **tanpa konten surel** |
| Log debug | opt-in, ring buffer terbatas (maksimum 500 entri, tanpa header) |

---

## Dokumentasi lengkap

Panduan rinci (fitur, glosarium, model ancaman, riwayat versi): [README_EN.md](README_EN.md).

---

## Kontribusi

Menemukan surel yang MUA atau tumpukan servernya tidak dikenali mleak dan Anda tahu klien/produk asalnya? Kirim header terkait (Received, Message-ID, X-*, Authentication-Results, User-Agent) ke `mlux@undisclose.de` dengan subjek **mleak-sample**. Boleh menyamarkan alamat pribadi; jangan menyamarkan headernya.

---

## Lisensi

Dilisensikan di bawah **Mozilla Public License 2.0** — lihat [LICENSE](LICENSE).
