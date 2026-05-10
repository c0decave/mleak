# mleak — OSINT từng-thư cho Thunderbird

*Ngôn ngữ: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)*

**Nguồn:** <https://github.com/c0decave/mleak/>

**Mô tả ngắn.** mleak là một tiện ích mở rộng Thunderbird thực hiện phân tích pháp y header/thân của từng thư. Nó hiển thị dấu vân tay MUA, stack máy chủ, dữ liệu tenant M365, lộ trình relay, phán quyết xác thực, dấu hiệu mailing list, rò rỉ IP người gửi trực tiếp, dấu vân tay thứ tự header, gợi ý ranh giới MIME, tín hiệu mật mã và kiểm tra tính toàn vẹn — hoàn toàn ngoại tuyến.

WebExtension · Thunderbird 115+ · 100 % offline · MPL-2.0.

---

## Điểm nổi bật

Những gì mleak hiển thị cho mỗi thư:

- **Trình khách / MUA**: từ `User-Agent`, mẫu `Message-ID`, chữ ký HTML, ranh giới MIME — đối chiếu chéo
- **Stack máy chủ**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · Proofpoint · Mimecast · Barracuda
- **Tuyến chuyển tiếp**: số hop, IP công cộng, **rò rỉ tên máy nội bộ**, **IP RFC1918** theo hop
- **Xác thực**: phán quyết SPF / DKIM / DMARC / ARC / BIMI + chữ ký DKIM (domain, selector)
- **Mật mã**: Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, ProtonMail, Tutanota — header và ranh giới
- **Toàn vẹn**: thiếu Date/MID, From↔Sender lệch, Reply-To khác domain, bất thường DKIM h=
- **100% ngoại tuyến**: không mạng, không telemetry, không phụ thuộc bên ngoài

---

## Cài đặt

### Tạm thời (phát triển)
1. `Công cụ → Tiện ích & Chủ đề → ⚙ → Gỡ lỗi tiện ích → Tải tiện ích tạm thời …`
2. Chọn `manifest.json` từ thư mục này.

### Đóng gói
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (hiện tại: 0.6.12)
```
Sau đó: `Công cụ → Tiện ích → ⚙ → Cài tiện ích từ tệp …` và chọn XPI.

---

## Sử dụng

**Chế độ popup** là mặc định: nhấn biểu tượng trên thanh công cụ thư để mở popup với tất cả thẻ thông tin. **Chế độ body-inline** (tùy chọn) hiển thị bảng mleak tự động phía trên thân thư; biểu tượng sau đó bật/tắt bảng. Cài đặt: `Công cụ → Tiện ích → mleak → Tùy chọn`.

---

## Bảo mật và quyền riêng tư

| Thuộc tính | Trạng thái |
|---|---|
| Yêu cầu mạng | **không có** (không `fetch`, `XHR`, `sendBeacon`, `WebSocket`) |
| Tiêm DOM | **không có** (chỉ `textContent`/`createElement`) |
| Quyền | `messagesRead` · `messagesModify` · `storage` · `tabs` (không `<all_urls>`) |
| Lưu trữ | chỉ tùy chọn UI trong `storage.local`; **không có nội dung thư** |
| Nhật ký gỡ lỗi | opt-in, ring buffer giới hạn (tối đa 500 mục, không header) |

---

## Tài liệu đầy đủ

Hướng dẫn chi tiết (tính năng, thuật ngữ, mô hình mối đe dọa, lịch sử phiên bản): [README_EN.md](README_EN.md).

---

## Đóng góp

Bạn tìm thấy thư mà mleak không nhận diện được MUA hoặc stack máy chủ và biết nó đến từ trình khách/sản phẩm nào? Vui lòng gửi các header liên quan (Received, Message-ID, X-*, Authentication-Results, User-Agent) đến `mlux@undisclose.de` với chủ đề **mleak-sample**. Có thể che địa chỉ cá nhân; nhưng đừng che chính các header.

---

## Giấy phép

Cấp phép theo **Mozilla Public License 2.0** — xem [LICENSE](LICENSE).
