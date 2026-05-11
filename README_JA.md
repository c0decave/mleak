<p align="center">
  <img src="branding/logo-256.png" alt="mleak logo" width="160">
</p>

# mleak — Thunderbird 用 Per-Mail OSINT

*言語: [Deutsch](README_DE.md) · [English](README_EN.md) · [Español](README_ES.md) · [Français](README_FR.md) · [Italiano](README_IT.md) · [中文](README_ZH.md) · [हिन्दी](README_HI.md) · [Português](README_PT.md) · [Polski](README_PL.md) · [العربية](README_AR.md) · [Русский](README_RU.md) · [日本語](README_JA.md) · [한국어](README_KO.md) · [Türkçe](README_TR.md) · [Tiếng Việt](README_VI.md) · [Bahasa Indonesia](README_ID.md) · [বাংলা](README_BN.md) · [فارسی](README_FA.md)*

**ソース:** <https://github.com/c0decave/mleak/>

**概要。** mleak はメール毎のヘッダー/本文をフォレンジック解析する Thunderbird 拡張です。MUA フィンガープリント、サーバースタック、M365 テナントデータ、リレー経路、認証結果、メーリングリスト指標、送信者 IP 直接漏えい、ヘッダー順序フィンガープリント、MIME 境界ヒント、暗号信号、整合性検査を完全オフラインで提示します。

WebExtension · Thunderbird 115+ · 100 % offline · MPL-2.0.

---

## ハイライト

mleak が各メッセージで提示する情報:

- **クライアント / MUA**: `User-Agent`、`Message-ID` パターン、HTML 署名、MIME 境界からの相互検証
- **サーバースタック**: Gmail · Exchange/M365 · Apple iCloud · Yahoo · Proofpoint · Mimecast · Barracuda
- **リレー経路**: ホップ数、外部 IP、**内部ホスト名漏えい**、**RFC1918 IP** をホップ単位で表示
- **認証**: SPF / DKIM / DMARC / ARC / BIMI 結果 + DKIM 署名(ドメイン、セレクター)
- **暗号**: Enigmail、OpenPGP/MIME、S/MIME、Autocrypt、ProtonMail、Tutanota — ヘッダーと境界の両方
- **整合性**: Date/MID 欠落、From↔Sender 不一致、Reply-To 異ドメイン、DKIM h= 異常
- **100% オフライン**: ネットワーク・テレメトリ・外部依存なし

---

## インストール

### 一時的(開発)
1. `ツール → アドオンとテーマ → ⚙ → アドオンをデバッグ → 一時的なアドオンを読み込む …`
2. このディレクトリから `manifest.json` を選択。

### パッケージ済み
```bash
bash pack.sh
# → dist/mleak-<version>.xpi   (現行: 0.6.12)
```
続いて: `ツール → アドオン → ⚙ → ファイルからアドオンをインストール …` で XPI を選びます。

---

## 使い方

**ポップアップモード**が既定です: メッセージツールバーのアイコンをクリックすると、すべてのインテルカード付きのポップアップが開きます。**body-inline モード**(任意)は mleak パネルをメッセージ本文の上に自動表示し、アイコンでパネルを切り替えます。設定: `ツール → アドオン → mleak → 設定`。

---

## セキュリティとプライバシー

| 属性 | 状態 |
|---|---|
| ネットワーク要求 | **なし**(`fetch`、`XHR`、`sendBeacon`、`WebSocket` を一切使用せず) |
| DOM 注入 | **なし**(`textContent`/`createElement` のみ) |
| 権限 | `messagesRead` · `messagesModify` · `storage` · `tabs`(`<all_urls>` なし) |
| 保存 | UI 設定のみを `storage.local` に保存; **メール本文は保存しません** |
| デバッグログ | オプトイン、上限付きリングバッファ(最大 500 件、ヘッダーなし) |

---

## 完全なドキュメント

詳細なガイド(機能、用語集、脅威モデル、変更履歴): [README_EN.md](README_EN.md)。

---

## コントリビューション

mleak が認識できなかった MUA / サーバースタックのメールを見つけ、その送信元を ご存じなら、関連ヘッダー(Received, Message-ID, X-*, Authentication-Results, User-Agent)を件名 **mleak-sample** で `mlux@undisclose.de` 宛にお送りください。個人アドレスは伏せて構いませんが、ヘッダー自体は伏せないでください。

---

## ライセンス

**Mozilla Public License 2.0** の下でライセンスされています — [LICENSE](LICENSE) を参照。
