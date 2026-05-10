# mleak — اطلاعات هر-ایمیلی برای Thunderbird

*زبان‌ها: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)*

**سورس:** <https://github.com/c0decave/mleak/>

**توضیح کوتاه.** mleak یک افزونه Thunderbird برای تحلیل فارنزیک سرنامه و بدنه‌ی هر ایمیل است. اثرانگشت MUA، پشتهٔ سرور، دادهٔ مستأجر M365، مسیر بازپخش، احکام احراز هویت، نشانگرهای فهرست‌های پستی، نشتی مستقیم IP فرستنده، اثرانگشت ترتیب سرنامه‌ها، نشانه‌های مرز MIME، سیگنال‌های رمزنگاری و یافته‌های یکپارچگی را کاملاً آفلاین آشکار می‌کند.

WebExtension · Thunderbird 115+ · 100 % offline · MPL-2.0.

---

## نکات برجسته

آنچه mleak برای هر پیام نمایش می‌دهد:

- **کلاینت / MUA**: از `User-Agent`، الگوهای `Message-ID`، امضاهای HTML، مرزهای MIME — اعتبارسنجی متقاطع
- **پشتهٔ سرور**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · Proofpoint · Mimecast · Barracuda
- **مسیر بازپخش**: تعداد گام‌ها، IPهای بیرونی، **نشتی نام میزبان داخلی**، **IP در رنج RFC1918** در هر گام
- **احراز هویت**: احکام SPF / DKIM / DMARC / ARC / BIMI + امضاهای DKIM (دامنه، انتخابگر)
- **رمزنگاری**: Enigmail، OpenPGP/MIME، S/MIME، Autocrypt، ProtonMail، Tutanota — سرنامه و مرز
- **یکپارچگی**: نبود Date/MID، اختلاف From↔Sender، Reply-To بین‌دامنه، ناهنجاری‌های DKIM h=
- **۱۰۰٪ آفلاین**: بدون شبکه، بدون تله‌متری، بدون وابستگی بیرونی

---

## نصب

### موقت (توسعه)
1. `ابزارها → افزونه‌ها و پوسته‌ها → ⚙ → اشکال‌زدایی افزونه‌ها → بارگذاری افزونه موقت …`
2. `manifest.json` را از این پوشه انتخاب کنید.

### بسته‌بندی‌شده
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (نسخه فعلی: 0.6.12)
```
سپس: `ابزارها → افزونه‌ها → ⚙ → نصب افزونه از پرونده …` و XPI را انتخاب کنید.

---

## استفاده

**حالت پاپ‌آپ** پیش‌فرض است: کلیک روی آیکون نوار ابزار پیام، پاپ‌آپی با تمام کارت‌های اطلاعاتی باز می‌کند. **حالت body-inline** (اختیاری) پنل mleak را به‌طور خودکار بالای بدنهٔ ایمیل نمایش می‌دهد؛ آیکون سپس پنل را روشن/خاموش می‌کند. تنظیمات: `ابزارها → افزونه‌ها → mleak → تنظیمات برگزیده`.

---

## امنیت و حریم خصوصی

| ویژگی | وضعیت |
|---|---|
| درخواست‌های شبکه | **هیچ‌کدام** (نه `fetch`، نه `XHR`، نه `sendBeacon`، نه `WebSocket`) |
| تزریق DOM | **هیچ‌کدام** (فقط `textContent`/`createElement`) |
| مجوزها | `messagesRead` · `messagesModify` · `storage` · `tabs` (بدون `<all_urls>`) |
| ذخیره‌سازی | تنها تنظیمات UI در `storage.local`؛ **هیچ محتوای ایمیلی ذخیره نمی‌شود** |
| گزارش اشکال‌زدایی | اختیاری، بافر حلقوی محدود (حداکثر ۵۰۰ ورودی، بدون سرنامه‌ها) |

---

## مستندات کامل

راهنمای جامع (ویژگی‌ها، واژه‌نامه، مدل تهدید، تاریخچه نسخه‌ها): [README_EN.md](README_EN.md).

---

## مشارکت

ایمیلی پیدا کرده‌اید که mleak MUA یا پشتهٔ سرور آن را نشناخته و می‌دانید از کدام کلاینت/محصول آمده است؟ سرنامه‌های مرتبط (Received، Message-ID، X-*، Authentication-Results، User-Agent) را با موضوع **mleak-sample** به `mlux@undisclose.de` بفرستید. می‌توانید نشانی‌های شخصی را پنهان کنید؛ ولی هرگز خود سرنامه‌ها را پنهان نکنید.

---

## مجوز

تحت **Mozilla Public License 2.0** مجوزدار — به [LICENSE](LICENSE) مراجعه کنید.
