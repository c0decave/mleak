<p align="center">
  <img src="branding/logo-256.png" alt="mleak logo" width="160">
</p>

# mleak — Per-Mail OSINT для Thunderbird

*Языки: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)*

**Исходный код:** <https://github.com/c0decave/mleak/>

**Краткое описание.** mleak — расширение Thunderbird для криминалистического анализа заголовков и тела каждого письма. Извлекает отпечатки MUA, серверный стек, данные тенанта M365, путь ретрансляторов, вердикты аутентификации, маркеры почтовых рассылок, прямые утечки IP отправителя, отпечатки порядка заголовков, подсказки MIME-границ, криптосигналы и проверки целостности — полностью офлайн.

WebExtension · Thunderbird 115+ · 100 % offline · MPL-2.0.

---

## Ключевые возможности

Что mleak извлекает для каждого письма:

- **Клиент / MUA** из `User-Agent`, шаблонов `Message-ID`, HTML-подписей, MIME-границ — перекрёстная проверка
- **Серверный стек**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · Proofpoint · Mimecast · Barracuda
- **Путь ретрансляторов**: число хопов, внешние IP, **утечки внутренних имён**, **IP RFC1918** по-хоп
- **Аутентификация**: вердикты SPF / DKIM / DMARC / ARC / BIMI + подписи DKIM (домен, селектор)
- **Криптография**: Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, ProtonMail, Tutanota — заголовки и границы
- **Целостность**: отсутствие Date/MID, расхождение From↔Sender, Reply-To кросс-домен, аномалии DKIM h=
- **100 % офлайн**: ни сети, ни телеметрии, ни внешних зависимостей

---

## Установка

### Временно (разработка)
1. `Инструменты → Дополнения и темы → ⚙ → Отладка дополнений → Загрузить временное дополнение …`
2. Выберите `manifest.json` из этого каталога.

### Упакованное
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (текущая: 0.6.12)
```
Затем: `Инструменты → Дополнения → ⚙ → Установить дополнение из файла …` и выберите XPI.

---

## Использование

**Режим popup** — стандартный: клик на иконку в панели сообщения открывает popup со всеми карточками. **Режим body-inline** (опциональный) показывает панель mleak автоматически над телом письма; иконка тогда переключает панель. Настройки: `Инструменты → Дополнения → mleak → Параметры`.

---

## Безопасность и приватность

| Свойство | Состояние |
|---|---|
| Сетевые запросы | **нет** (ни `fetch`, ни `XHR`, ни `sendBeacon`, ни `WebSocket`) |
| Внедрение DOM | **нет** (только `textContent`/`createElement`) |
| Разрешения | `messagesRead` · `messagesModify` · `storage` · `tabs` (без `<all_urls>`) |
| Хранение | только UI-настройки в `storage.local`; **никакого содержимого писем** |
| Отладочный лог | по подписке, кольцевой буфер с лимитом (макс. 500 записей, без заголовков) |

---

## Полная документация

Подробное руководство (функции, глоссарий, модель угроз, журнал изменений): [README_EN.md](README_EN.md).

---

## Содействие

Нашли письмо, чей MUA или серверный стек mleak не распознал, и знаете, какой клиент/продукт его создал? Пришлите соответствующие заголовки (Received, Message-ID, X-*, Authentication-Results, User-Agent) на `mlux@undisclose.de` с темой **mleak-sample**. Личные адреса можно вычеркнуть; сами заголовки — нет.

---

## Лицензия

Лицензировано под **Mozilla Public License 2.0** — см. [LICENSE](LICENSE).
