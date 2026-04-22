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

function _cap(s) {
  if (typeof s !== "string") return "";
  return s.length > MAX_HEADER_LEN ? s.slice(0, MAX_HEADER_LEN) : s;
}

function getHeader(headers, name) {
  if (!headers) return "";
  const key = name.toLowerCase();
  const v = headers[key];
  if (Array.isArray(v)) return _cap(v[0] || "");
  return _cap(v || "");
}

function getAllHeader(headers, name) {
  if (!headers) return [];
  const key = name.toLowerCase();
  const v = headers[key];
  if (Array.isArray(v)) return v.map(_cap);
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
  const lower = domain.toLowerCase();
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
  const s = String(ip).trim();

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
    // fe80::/10 — link-local.
    if (lower.startsWith("fe8") || lower.startsWith("fe9") ||
        lower.startsWith("fea") || lower.startsWith("feb")) return true;
    // ::1 loopback, :: unspecified.
    if (lower === "::1" || lower === "::") return true;
    // IPv4-mapped IPv6: ::ffff:10.x.y.z etc.
    const mapped = lower.match(/^::ffff:([0-9.]+)$/);
    if (mapped) return isPrivateIP(mapped[1]);
  }

  return false;
}

// Export to the global scope of the background/popup context.
globalThis.OSINTUtil = {
  getHeader, getAllHeader, stripAngles, extractAddress,
  structuralSignature, CONF, finding,
  INTERNAL_TLDS, looksInternalDomain, isPrivateIP,
  MAX_HEADER_LEN,
};
