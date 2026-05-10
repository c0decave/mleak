# mleak — Thunderbird용 Per-Mail OSINT

*언어: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)*

**소스:** <https://github.com/c0decave/mleak/>

**간단한 설명.** mleak은 Thunderbird 확장으로, 메일별 헤더/본문을 포렌식 분석합니다. MUA 지문, 서버 스택, M365 테넌트 데이터, 릴레이 경로, 인증 판정, 메일링 리스트 표지, 직접 발신자 IP 누출, 헤더 순서 지문, MIME 경계 단서, 암호 신호, 무결성 결과를 전부 오프라인으로 제공합니다.

WebExtension · Thunderbird 115+ · 100 % offline · MPL-2.0.

---

## 주요 기능

mleak이 각 메시지에서 표시하는 정보:

- **클라이언트 / MUA**: `User-Agent`, `Message-ID` 패턴, HTML 서명, MIME 경계의 교차검증
- **서버 스택**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · Proofpoint · Mimecast · Barracuda
- **릴레이 경로**: 홉 수, 외부 IP, **내부 호스트명 누출**, **RFC1918 IP** 홉별 표시
- **인증**: SPF / DKIM / DMARC / ARC / BIMI 판정 + DKIM 서명(도메인, 셀렉터)
- **암호화**: Enigmail, OpenPGP/MIME, S/MIME, Autocrypt, ProtonMail, Tutanota — 헤더와 경계 양쪽
- **무결성**: Date/MID 누락, From↔Sender 불일치, Reply-To 도메인 교차, DKIM h= 이상
- **100% 오프라인**: 네트워크 없음, 텔레메트리 없음, 외부 의존성 없음

---

## 설치

### 임시 (개발용)
1. `도구 → 부가 기능 및 테마 → ⚙ → 부가 기능 디버그 → 임시 부가 기능 로드 …`
2. 이 디렉터리의 `manifest.json`을 선택.

### 패키지
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (현재: 0.6.12)
```
이어서: `도구 → 부가 기능 → ⚙ → 파일에서 부가 기능 설치 …`로 XPI를 선택.

---

## 사용법

**팝업 모드**가 기본값입니다: 메시지 도구 모음의 아이콘을 클릭하면 모든 정보 카드가 포함된 팝업이 열립니다. **body-inline 모드**(선택)는 mleak 패널을 메일 본문 위에 자동 표시하며, 아이콘으로 패널을 토글합니다. 설정: `도구 → 부가 기능 → mleak → 환경 설정`.

---

## 보안 및 개인정보

| 속성 | 상태 |
|---|---|
| 네트워크 요청 | **없음** (`fetch`, `XHR`, `sendBeacon`, `WebSocket` 전혀 사용 안 함) |
| DOM 주입 | **없음** (`textContent`/`createElement` 만 사용) |
| 권한 | `messagesRead` · `messagesModify` · `storage` · `tabs` (`<all_urls>` 없음) |
| 저장 | UI 환경설정만 `storage.local`에 저장; **메일 내용 저장 안 함** |
| 디버그 로그 | 옵트인, 제한된 링 버퍼(최대 500건, 헤더 없음) |

---

## 전체 문서

자세한 가이드(기능, 용어집, 위협 모델, 변경 이력): [README_EN.md](README_EN.md).

---

## 기여

mleak가 인식하지 못한 MUA나 서버 스택의 메일을 발견하고 어떤 클라이언트/제품에서 보냈는지 안다면, 관련 헤더(Received, Message-ID, X-*, Authentication-Results, User-Agent)를 제목 **mleak-sample**로 `mlux@undisclose.de`에 보내주세요. 개인 주소는 가려도 좋지만 헤더 자체는 가리지 마세요.

---

## 라이선스

**Mozilla Public License 2.0**로 라이선스됨 — [LICENSE](LICENSE) 참조.
