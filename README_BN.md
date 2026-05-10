# mleak — Thunderbird-এর জন্য প্রতি-মেইল OSINT

*ভাষা: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)*

**সোর্স:** <https://github.com/c0decave/mleak/>

**সংক্ষিপ্ত পরিচিতি।** mleak হলো Thunderbird-এর একটি এক্সটেনশন, যা প্রতিটি মেইলের হেডার ও বডিতে ফরেনসিক বিশ্লেষণ চালায়। MUA ফিঙ্গারপ্রিন্ট, সার্ভার স্ট্যাক, M365 টেন্যান্ট তথ্য, রিলে পথ, অথেন্টিকেশন রায়, মেইলিং লিস্ট চিহ্ন, সরাসরি প্রেরক IP ফাঁস, হেডার ক্রম ফিঙ্গারপ্রিন্ট, MIME সীমানা সংকেত, ক্রিপ্টো সংকেত এবং ইন্টিগ্রিটি ফলাফল প্রকাশ করে — সম্পূর্ণ অফলাইনে।

WebExtension · Thunderbird 115+ · 100 % offline · MPL-2.0.

---

## প্রধান বৈশিষ্ট্য

mleak প্রতি বার্তায় যা প্রকাশ করে:

- **ক্লায়েন্ট / MUA**: `User-Agent`, `Message-ID` প্যাটার্ন, HTML স্বাক্ষর, MIME সীমানা থেকে ক্রস-ভেরিফিকেশন
- **সার্ভার স্ট্যাক**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · Proofpoint · Mimecast · Barracuda
- **রিলে পথ**: হপ সংখ্যা, বহিরাগত IP, **অভ্যন্তরীণ হোস্টনাম ফাঁস**, **RFC1918 IP** প্রতি-হপে
- **অথেন্টিকেশন**: SPF / DKIM / DMARC / ARC / BIMI রায় + DKIM স্বাক্ষর (ডোমেন, সিলেক্টর)
- **ক্রিপ্টো**: Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, ProtonMail, Tutanota — হেডার ও সীমানা
- **ইন্টিগ্রিটি**: Date/MID অনুপস্থিত, From↔Sender অমিল, Reply-To ক্রস-ডোমেন, DKIM h= অসংগতি
- **১০০% অফলাইন**: কোনও নেটওয়ার্ক, টেলিমেট্রি বা বহিরাগত নির্ভরতা নেই

---

## ইনস্টলেশন

### অস্থায়ী (ডেভেলপমেন্ট)
1. `টুলস → অ্যাড-অন এবং থিম → ⚙ → অ্যাড-অন ডিবাগ → অস্থায়ী অ্যাড-অন লোড করুন …`
2. এই ডিরেক্টরির `manifest.json` নির্বাচন করুন।

### প্যাকেজড
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (বর্তমান: 0.6.12)
```
তারপর: `টুলস → অ্যাড-অন → ⚙ → ফাইল থেকে অ্যাড-অন ইনস্টল করুন …` এবং XPI নির্বাচন করুন।

---

## ব্যবহার

**পপআপ মোড** ডিফল্ট: বার্তা টুলবারের আইকনে ক্লিক করলে সব ইনটেল কার্ড সহ পপআপ খোলে। **body-inline মোড** (ঐচ্ছিক) মেইল বডির উপরে mleak প্যানেল স্বয়ংক্রিয়ভাবে দেখায়; আইকন তখন প্যানেল টগল করে। সেটিংস: `টুলস → অ্যাড-অন → mleak → পছন্দসমূহ`।

---

## সুরক্ষা ও গোপনীয়তা

| বৈশিষ্ট্য | অবস্থা |
|---|---|
| নেটওয়ার্ক রিকোয়েস্ট | **নেই** (কোনও `fetch`, `XHR`, `sendBeacon`, `WebSocket` নেই) |
| DOM ইনজেকশন | **নেই** (শুধু `textContent`/`createElement`) |
| অনুমতি | `messagesRead` · `messagesModify` · `storage` · `tabs` (কোনও `<all_urls>` নেই) |
| স্টোরেজ | শুধু UI পছন্দ `storage.local`-এ; **মেইল কন্টেন্ট নেই** |
| ডিবাগ লগ | অপ্ট-ইন, সীমিত রিং বাফার (সর্বোচ্চ ৫০০ এন্ট্রি, হেডার ছাড়া) |

---

## পূর্ণাঙ্গ ডকুমেন্টেশন

বিস্তারিত গাইড (বৈশিষ্ট্য, পরিভাষা, হুমকির মডেল, সংস্করণ ইতিহাস): [README_EN.md](README_EN.md)।

---

## অবদান

এমন একটি মেইল পেলেন যার MUA বা সার্ভার স্ট্যাক mleak চিনতে পারেনি, এবং আপনি জানেন কোন ক্লায়েন্ট/পণ্য থেকে এসেছে? প্রাসঙ্গিক হেডার (Received, Message-ID, X-*, Authentication-Results, User-Agent) সাবজেক্ট **mleak-sample** সহ `mlux@undisclose.de`-এ পাঠান। ব্যক্তিগত ঠিকানা মুছতে পারেন; হেডার নয়।

---

## লাইসেন্স

**Mozilla Public License 2.0**-এর অধীনে লাইসেন্সকৃত — [LICENSE](LICENSE) দেখুন।
