# mleak — استخباراتُ كل بريد لـ Thunderbird

*اللغات: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)*

**المصدر:** <https://github.com/c0decave/mleak/>

**وصف موجز.** mleak هو امتداد لـ Thunderbird يقوم بتحليل جنائي للترويسات والجسم على مستوى كل رسالة. يكشف بصمات MUA، حِزمة الخادم، بيانات مستأجر M365، مسار التبديل، نتائج المصادقة، علامات القوائم البريدية، تسريبات IP المباشرة للمرسل، بصمات ترتيب الترويسات، تلميحات حدود MIME، إشارات التشفير، ونتائج السلامة — كله بدون اتصال.

WebExtension · Thunderbird 115+ · 100 % offline · MPL-2.0.

---

## أبرز النقاط

ما الذي يستخرجه mleak لكل رسالة:

- **العميل / MUA** من `User-Agent` وأنماط `Message-ID` وتوقيعات HTML وحدود MIME — تحقق متبادل
- **حزمة الخادم**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · Proofpoint · Mimecast · Barracuda
- **مسار التبديل**: عدد القفزات، عناوين IP الخارجية، **تسريبات الأسماء الداخلية**، **عناوين IP RFC1918** لكل قفزة
- **المصادقة**: نتائج SPF / DKIM / DMARC / ARC / BIMI + توقيعات DKIM (النطاق، المحدد)
- **التشفير**: Enigmail، OpenPGP/MIME، S/MIME، Autocrypt، ProtonMail، Tutanota — عبر الترويسة والحدود
- **السلامة**: غياب Date/MID، اختلاف From↔Sender، Reply-To عبر النطاقات، شذوذات DKIM h=
- **100 % دون اتصال**: لا شبكة، لا تتبع، لا تبعيات خارجية

---

## التثبيت

### مؤقت (تطوير)
1. `الأدوات → الإضافات والسمات → ⚙ → تصحيح الإضافات → تحميل إضافة مؤقتة …`
2. اختر `manifest.json` من هذا المجلد.

### مُحزَّمة
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (الإصدار الحالي: 0.6.12)
```
ثم: `الأدوات → الإضافات → ⚙ → تثبيت إضافة من ملف …` واختر XPI.

---

## الاستخدام

**وضع المنبثق** هو الافتراضي: انقر الأيقونة في شريط أدوات الرسالة لفتح المنبثق بكل بطاقات المعلومات. **وضع body-inline** (اختياري) يعرض لوحة mleak تلقائياً أعلى نص الرسالة؛ النقر على الأيقونة يبدّل اللوحة. الإعدادات: `الأدوات → الإضافات → mleak → التفضيلات`.

---

## الأمن والخصوصية

| الخاصية | الحالة |
|---|---|
| طلبات الشبكة | **لا شيء** (لا `fetch`، لا `XHR`، لا `sendBeacon`، لا `WebSocket`) |
| حقن DOM | **لا شيء** (فقط `textContent`/`createElement`) |
| الأذونات | `messagesRead` · `messagesModify` · `storage` · `tabs` (لا `<all_urls>`) |
| التخزين | تفضيلات الواجهة فقط في `storage.local`؛ **لا محتوى للرسائل** |
| سجل التصحيح | اختياري، مخزن دائري محدود (حتى 500 سجل، بدون ترويسات) |

---

## وثائق كاملة

للحصول على دليل كامل (الميزات، الزجاج، نموذج التهديدات، السجل): [README_EN.md](README_EN.md).

---

## المساهمة

وجدتَ رسالة لم يتعرَّف mleak على MUA أو حِزمة خادمها وتعرف مصدرها؟ أرسل الترويسات ذات الصلة (Received، Message-ID، X-*، Authentication-Results، User-Agent) إلى `mlux@undisclose.de` مع الموضوع **mleak-sample**. يمكنك إخفاء العناوين الشخصية؛ لا تخفِ الترويسات نفسها.

---

## الرخصة

مرخَّص بموجب **Mozilla Public License 2.0** — انظر [LICENSE](LICENSE).
