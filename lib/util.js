/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Shared helpers for detectors. No external dependencies.

"use strict";

// Header access is case-insensitive. Thunderbird's getFull() gives headers
// under normalized lowercase keys but sometimes arrays; normalize here.
//
// We treat every byte of every header as attacker-controlled. Defence-in-
// depth: cap header length before it reaches any regex. Legitimate headers
// are well under this (MID ≤500, Received ≤2000, DKIM-Signature ≤4000 with
// long b=). A pathological 10 MB Message-ID designed to exercise nested-
// quantifier regex backtracking in mid_patterns.js would otherwise hang the
// background page. MAX_HEADER_LEN is large enough to not break real mails.
const MAX_HEADER_LEN = 8192;
const MAX_HEADER_COUNT = 64;

// Header sanitisation — applied to every header value at intake so the
// detector pipeline never carries ASCII control bytes, bidi-override
// characters, or zero-width characters into the surfaced summary.
//
// Why this matters even though we render via textContent:
//   * NUL (U+0000) contaminates copy-paste exports of the summary into
//     downstream parsers that treat NUL as terminator.
//   * Bidi-override (U+202A–202E, U+2066–2069) visually reverses or
//     isolates the displayed text — a Message-ID `<x@U+202Emoc.elgoogU+202C>`
//     looks like `<x@google.com>` in the popup; the user trusts a domain
//     that doesn't match the bytes.
//   * Zero-width chars (U+200B–200F, U+2060, U+FEFF) hide differences
//     between visually-identical domains; `googU+200Ble.com` looks
//     identical to `google.com` on screen but the captured hostname
//     differs.
//   * CR/LF in a single header value can break line layout in the
//     popup and contaminate copy-paste with header-injection-looking
//     content.
//
// We keep TAB (U+0009) — sometimes legitimately inside header folding
// remnants — and pass everything outside the unicode tripwire ranges
// through verbatim. Use \u escape sequences so the source file is
// byte-clean (no invisible chars sitting in source).
const _CTL_BIDI_ZW_RX = new RegExp(
  "[\\u0000-\\u0008\\u000A-\\u001F\\u007F"      // ASCII NUL/C0/DEL (keep TAB)
  + "\\u200B-\\u200F\\u2060\\uFEFF"             // zero-width set
  + "\\u202A-\\u202E\\u2066-\\u2069"            // bidi-override + isolate
  + "]",
  "g"
);

function _sanitiseHeaderValue(s) {
  if (typeof s !== "string") return "";
  // Strip control/bidi/zero-width first, then cap length.
  const cleaned = s.replace(_CTL_BIDI_ZW_RX, "");
  return cleaned.length > MAX_HEADER_LEN
    ? cleaned.slice(0, MAX_HEADER_LEN)
    : cleaned;
}

function _cap(s) {
  return _sanitiseHeaderValue(s);
}

function _headerValue(headers, name) {
  if (!headers) return undefined;
  const key = name.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(headers, key)) return headers[key];
  for (const [k, v] of Object.entries(headers)) {
    if (String(k).toLowerCase() === key) return v;
  }
  return undefined;
}

function getHeader(headers, name) {
  const v = _headerValue(headers, name);
  if (Array.isArray(v)) return _cap(v[0] || "");
  return _cap(v || "");
}

function getAllHeader(headers, name) {
  const v = _headerValue(headers, name);
  if (Array.isArray(v)) return v.slice(0, MAX_HEADER_COUNT).map(_cap);
  if (v) return [_cap(v)];
  return [];
}

// Strip < > around a Message-ID and trim whitespace.
function stripAngles(s) {
  if (!s) return "";
  return String(s).trim().replace(/^</, "").replace(/>$/, "").trim();
}

// Extract the first RFC-5322-ish email address from a From/To-style value.
function extractAddress(s) {
  if (!s) return "";
  const m = String(s).match(/<?([A-Z0-9._%+\-]+@[A-Z0-9._%+\-]+)>?/i);
  return m ? m[1].toLowerCase() : "";
}

// Structural signature: replace character runs with class+length tokens so
// unknown MUAs can be grouped by shape (ported from _util.structural_signature).
function structuralSignature(s) {
  if (!s) return "";
  const parts = s.split(/([^0-9A-Za-z]+)/);
  const out = [];
  for (const p of parts) {
    if (!p) continue;
    if (/^[0-9A-Za-z]+$/.test(p)) {
      let cls;
      if (/^[0-9A-F]+$/.test(p)) cls = "H";
      else if (/^[0-9a-f]+$/.test(p)) cls = "h";
      else if (/^[0-9]+$/.test(p)) cls = "D";
      else if (/^[A-Z]+$/.test(p)) cls = "U";
      else if (/^[a-z]+$/.test(p)) cls = "L";
      else if (/^[A-Za-z]+$/.test(p)) cls = "A";
      else cls = "X";
      out.push(`${cls}{${p.length}}`);
    } else {
      out.push(p);
    }
  }
  return out.join("");
}

// Confidence levels (match Python enum).
const CONF = Object.freeze({
  HIGH: "high", MEDIUM: "medium", LOW: "low",
});

// Helper: make a Finding-shaped object.
function finding(detector, kind, value, confidence = CONF.MEDIUM, extras = {}) {
  return {
    detector, kind, value,
    confidence,
    leaks: extras.leaks || {},
    notes: extras.notes || [],
  };
}

// Is a hostname/FQDN likely "internal"?  Used by Received and MID heuristics.
const INTERNAL_TLDS = new Set([
  "local", "lan", "intern", "internal", "corp", "ad", "localdomain",
  "home", "office", "private", "dmz",
]);

// Placeholder labels that appear in Received headers but aren't really
// hostnames — Postfix writes "unknown" when reverse DNS fails, and
// "localhost" just says "the mail hit this machine's own loopback".
// Neither is an OSINT leak; skip them.
const HOST_SENTINELS = new Set(["unknown", "localhost", "-", ""]);

function looksInternalDomain(domain) {
  if (!domain) return false;
  const lower = String(domain).slice(0, MAX_HEADER_LEN).toLowerCase();
  if (HOST_SENTINELS.has(lower)) return false;
  const parts = lower.split(".");
  // Single-label hostname (no dot at all) — NetBIOS, Kubernetes pod name,
  // Active-Directory short name, any LAN DNS. Public hosts on the open
  // internet always have at least one dot, so treat no-dot as internal.
  if (parts.length === 1) return true;
  return INTERNAL_TLDS.has(parts[parts.length - 1]);
}

// Private-address check for Received chains — both IPv4 and IPv6.
function isPrivateIP(ip) {
  if (!ip) return false;
  let s = String(ip).trim();
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);

  // IPv4 RFC 1918 / loopback / link-local / "this host".
  if (s.startsWith("10.") || s.startsWith("127.") ||
      s.startsWith("192.168.") || s.startsWith("169.254.") ||
      s.startsWith("0.")) return true;
  const m = s.match(/^172\.(\d+)\./);
  if (m) {
    const n = parseInt(m[1], 10);
    if (n >= 16 && n <= 31) return true;
  }

  // IPv6: anything with a ":" is an IPv6 literal. Check the well-known
  // private / locally-scoped ranges.
  if (s.includes(":")) {
    const lower = s.toLowerCase();
    // fc00::/7 — Unique Local Addresses (ULA, RFC 4193). Covers fc00–fdff.
    if (/^f[cd][0-9a-f]{2}:/.test(lower)) return true;
    // fe80::/10 — link-local. Compare against the first hex-quad to avoid
    // misclassifying e.g. fe8a::… as link-local just because it starts
    // with "fe8" — only fe80–febf is the /10.
    const ll = lower.match(/^([0-9a-f]{1,4}):/);
    if (ll) {
      const n = parseInt(ll[1], 16);
      if (n >= 0xfe80 && n <= 0xfebf) return true;
    }
    // ::1 loopback, :: unspecified.
    if (lower === "::1" || lower === "::") return true;
    // IPv4-mapped IPv6: ::ffff:10.x.y.z (dotted-quad embed).
    const mapped = lower.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (mapped) return isPrivateIP(mapped[1]);
    // IPv4-mapped IPv6: ::ffff:HHHH:HHHH (hex form — same address space,
    // produced by some stacks that normalise to all-hex). Decode the last
    // 32 bits to a dotted quad and recurse.
    const hexMapped = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
    if (hexMapped) {
      const hi = parseInt(hexMapped[1], 16) | 0;
      const lo = parseInt(hexMapped[2], 16) | 0;
      const v4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      return isPrivateIP(v4);
    }
    // IPv4-compatible IPv6 (deprecated, RFC 4291 §2.5.5.1): ::N.N.N.N.
    // Still seen in legacy logs and Received chains.
    const compat = lower.match(/^::(\d{1,3}(?:\.\d{1,3}){3})$/);
    if (compat) return isPrivateIP(compat[1]);
  }

  return false;
}

// Public sanitiser — for callers that read attacker-controlled content
// from somewhere OTHER than the header pipeline (e.g. lib/body_html.js
// extracting <meta name=generator content="…"> from the mail body).
// The header path goes through _cap() which already calls this; the
// body path used to bypass it, which let CR/LF in MS-Word's filtered
// HTML generator string surface as `mua_signals[*].label` with embedded
// newlines (found by 100k corpus sweep, 2 hits in 2019-10 Cassandra +
// 2017-06 Guacamole mboxes). Centralising the helper here means every
// surface that takes attacker bytes uses the same cleaning policy.
function sanitiseValue(s) {
  return _sanitiseHeaderValue(s);
}

// Export to the global scope of the background/popup context.
globalThis.OSINTUtil = {
  getHeader, getAllHeader, stripAngles, extractAddress,
  structuralSignature, CONF, finding,
  INTERNAL_TLDS, looksInternalDomain, isPrivateIP,
  sanitiseValue,
  MAX_HEADER_LEN, MAX_HEADER_COUNT,
};
