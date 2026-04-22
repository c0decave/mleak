/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Crypto / PGP / S-MIME fingerprints.
//
// Pulls six signal classes out of the message:
//   1. X-Enigmail-Version     → Thunderbird-PGP add-on + exact version
//   2. MIME boundary "enig…"  → Enigmail-specific even without the header
//   3. Content-Type proto     → OpenPGP/MIME or S/MIME (mode=signed|encrypted)
//   4. Autocrypt / -Gossip    → RFC-draft auto-key-exchange marker
//   5. OpenPGP: lookup hint   → RFC 3156 §7 keyserver URL
//   6. Gateway headers        → Symantec PGP-Universal, Tutanota, ProtonMail
//
// All findings ride under detector="crypto". The orchestrator merges them
// into the MUA signals where they imply a client (Enigmail, Tutanota, …)
// and into the server-stack list where they imply an enterprise gateway.

"use strict";

(() => {

const { getHeader, finding, CONF } = globalThis.OSINTUtil;

// Walk the parsed-MIME tree (from messages.getFull()) and return every
// contentType string we encounter. Crypto markers can sit on inner parts
// (e.g. multipart/signed wrapping text/plain + application/pgp-signature).
function allContentTypes(part, depth, acc) {
  if (!part || depth > 6) return acc;
  if (part.contentType) acc.push(part.contentType);
  if (Array.isArray(part.parts)) {
    for (const sub of part.parts) allContentTypes(sub, depth + 1, acc);
  }
  return acc;
}

function detectCrypto(message) {
  const out = [];
  const headers = message && message.headers || {};

  // ---- 1. Enigmail version header ---------------------------------------
  const enigmailVer = getHeader(headers, "X-Enigmail-Version");
  if (enigmailVer) {
    out.push(finding("crypto", "enigmail_version",
                     `Enigmail ${enigmailVer}`, CONF.HIGH, {
      leaks: { family: "Enigmail", version: enigmailVer,
               src: "X-Enigmail-Version" },
      notes: ["Thunderbird-PGP add-on — version string is a precise MUA fingerprint."]
    }));
  }

  // Gather every Content-Type we can see — outer header plus every inner
  // MIME part. Limit to 8 KB each to stay inside the ReDoS length cap.
  const ctypes = [];
  const outer = getHeader(headers, "Content-Type");
  if (outer) ctypes.push(outer);
  for (const c of allContentTypes(message, 0, [])) {
    if (c && typeof c === "string") ctypes.push(c.slice(0, 8192));
  }

  // ---- 2. MUA fingerprint via MIME boundary prefix ---------------------
  // MUAs stamp a product-specific prefix into each boundary they generate.
  // The prefix survives gateway rewrites because a valid MIME message must
  // keep its boundaries byte-stable during transit. Useful as a MUA hint
  // *especially* on PGP/SMIME-encrypted mails where the body is opaque.
  const BOUNDARY_HINTS = [
    { re: /-{2,}enig([0-9A-Fa-f]{8,})/i, label: "Enigmail",                    captureVersion: false },
    { re: /\bApple-Mail[=_-]/,           label: "Apple Mail",                  captureVersion: false },
    { re: /^_000_/,                      label: "Microsoft Outlook / Exchange",captureVersion: false },
    { re: /^_NextPart_/,                 label: "Microsoft Outlook",           captureVersion: false },
    { re: /^----=_Part_/,                label: "JavaMail",                    captureVersion: false },
  ];
  const boundaryHits = new Set();
  for (const ct of ctypes) {
    const bm = ct.match(/boundary\s*=\s*"?([^";]+)"?/i);
    if (!bm) continue;
    const boundary = bm[1];
    for (const pat of BOUNDARY_HINTS) {
      if (pat.re.test(boundary) && !boundaryHits.has(pat.label)) {
        boundaryHits.add(pat.label);
        out.push(finding("crypto", "boundary_mua_hint", pat.label,
                         CONF.MEDIUM, {
          leaks: { family: pat.label, boundary: boundary.slice(0, 80),
                   src: "Content-Type boundary" },
          notes: ["MUA hint from MIME boundary prefix — works even on encrypted bodies."]
        }));
      }
    }
  }
  // Fold the Enigmail-specific boundary into the stronger enigmail finding
  // if the X-Enigmail-Version header wasn't present.
  if (!enigmailVer && boundaryHits.has("Enigmail")) {
    // Already emitted as "boundary_mua_hint" above; upgrade confidence by
    // adding an explicit enigmail_boundary finding too.
    out.push(finding("crypto", "enigmail_boundary", "Enigmail", CONF.HIGH, {
      leaks: { family: "Enigmail", src: "Content-Type boundary=…enig…" },
      notes: ["Enigmail-specific `enig` boundary prefix."]
    }));
  }

  // ---- 3. OpenPGP/MIME and S/MIME protocol -----------------------------
  // RFC 3156 (OpenPGP/MIME): multipart/{signed,encrypted} with protocol=…
  // RFC 2633 (S/MIME):       multipart/signed with application/pkcs7-*, or
  //                          application/pkcs7-mime opaque-signed inline.
  // Note: the `protocol=` parameter may appear in *any* position in the
  // Content-Type (before or after boundary=, name=, charset=, …). Use a
  // lookahead-free pattern that skims across `;` boundaries.
  const PROTO_LABEL = {
    "application/pgp-encrypted":    "OpenPGP/MIME (encrypted)",
    "application/pgp-signature":    "OpenPGP/MIME (signed)",
    "application/pkcs7-signature":  "S/MIME (signed)",
    "application/x-pkcs7-signature":"S/MIME (signed)",
    "application/pkcs7-mime":       "S/MIME (encrypted)",
    "application/x-pkcs7-mime":     "S/MIME (encrypted)",
  };
  const seenCrypto = new Set();
  for (const ct of ctypes) {
    const mwrap = ct.match(/multipart\/(encrypted|signed)/i);
    const mproto = ct.match(/\bprotocol\s*=\s*"?([^";\s]+)"?/i);
    if (mwrap && mproto) {
      const mode  = mwrap[1].toLowerCase();
      const proto = mproto[1].toLowerCase();
      const label = PROTO_LABEL[proto] || `${mode} / ${proto}`;
      if (!seenCrypto.has(label)) {
        seenCrypto.add(label);
        out.push(finding("crypto", "mime_crypto", label, CONF.HIGH, {
          leaks: { mode, protocol: proto },
          notes: ["RFC 3156 (OpenPGP/MIME) or RFC 2633 (S/MIME) marker."]
        }));
      }
    }
    // S/MIME can also appear as a plain content-type on an inner part,
    // without the multipart wrapper (e.g. opaque-signed PKCS#7).
    const m2 = ct.match(/application\/(x-)?pkcs7-mime/i);
    if (m2 && !seenCrypto.has("S/MIME (encrypted)")) {
      seenCrypto.add("S/MIME (encrypted)");
      out.push(finding("crypto", "mime_crypto", "S/MIME (encrypted)",
                       CONF.HIGH, { leaks: { protocol: m2[0].toLowerCase() } }));
    }
  }

  // ---- 4. Autocrypt / Autocrypt-Gossip ---------------------------------
  const autocrypt = getHeader(headers, "Autocrypt");
  if (autocrypt) {
    const addrMatch = autocrypt.match(/addr\s*=\s*([^;\s]+)/i);
    const prefMatch = autocrypt.match(/prefer-encrypt\s*=\s*([^;\s]+)/i);
    out.push(finding("crypto", "autocrypt", "Autocrypt", CONF.HIGH, {
      leaks: {
        addr: addrMatch ? addrMatch[1] : null,
        prefer_encrypt: prefMatch ? prefMatch[1] : null,
      },
      notes: ["Autocrypt header — MUA supports automatic key exchange."]
    }));
  }
  if (getHeader(headers, "Autocrypt-Gossip")) {
    out.push(finding("crypto", "autocrypt_gossip", "Autocrypt-Gossip",
                     CONF.MEDIUM, {
      notes: ["Multi-recipient Autocrypt-Gossip — sender shipped other recipients' keys."]
    }));
  }

  // ---- 5. OpenPGP lookup hint (RFC 3156 §7) ----------------------------
  const openpgp = getHeader(headers, "OpenPGP");
  if (openpgp) {
    const urlMatch = openpgp.match(/url\s*=\s*([^;\s]+)/i);
    const idMatch  = openpgp.match(/id\s*=\s*([0-9A-Fa-f]{8,40})/);
    out.push(finding("crypto", "openpgp_hint", "OpenPGP", CONF.MEDIUM, {
      leaks: {
        keyserver_url: urlMatch ? urlMatch[1] : null,
        key_id:        idMatch  ? idMatch[1]  : null,
      },
      notes: ["OpenPGP header — keyserver-URL / key-ID hint."]
    }));
  }

  // ---- 6. Enterprise / webmail gateway headers -------------------------
  const pgpu = getHeader(headers, "X-PGP-Universal");
  if (pgpu) {
    out.push(finding("crypto", "pgp_universal",
                     `Symantec PGP Universal (${pgpu})`, CONF.HIGH, {
      leaks: { state: pgpu, src: "X-PGP-Universal" },
      notes: ["Symantec/Broadcom PGP-Universal gateway — enterprise crypto hub."]
    }));
  }
  if (getHeader(headers, "X-Tuta-Encrypted")) {
    out.push(finding("crypto", "tutanota", "Tutanota", CONF.HIGH, {
      leaks: { family: "Tutanota", src: "X-Tuta-Encrypted" },
    }));
  }
  const pmAny = getHeader(headers, "X-Pm-Origin")
             || getHeader(headers, "X-Pm-Date")
             || getHeader(headers, "X-Pm-Content-Encryption");
  if (pmAny) {
    out.push(finding("crypto", "protonmail_header", "ProtonMail", CONF.HIGH, {
      leaks: { family: "ProtonMail", src: "X-Pm-*" },
    }));
  }

  return out;
}

globalThis.OSINTDetect = globalThis.OSINTDetect || {};
globalThis.OSINTDetect.crypto = detectCrypto;

})();
