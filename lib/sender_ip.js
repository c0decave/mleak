/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Direct sender-IP leak detector. Some clients/gateways stamp the sender's
// workstation or web edge IP into X-Originating-IP-style headers.

"use strict";

(() => {
const { getAllHeader, isPrivateIP, finding, CONF } = globalThis.OSINTUtil;

const CANDIDATE_HEADERS = [
  "X-Originating-IP",
  "X-Sender-IP",
  "X-Source-IP",
  "X-Apparently-From",
  "X-Originating-Client",
  "X-Real-IP",
  "X-Forwarded-For",
  "X-Client-IP",
];

const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

function validIPv4(ip) {
  const parts = String(ip).split(".");
  if (parts.length !== 4) return false;
  return parts.every(p => {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

function validIPv6(ip) {
  let s = String(ip).toLowerCase();
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  if (!s.includes(":")) return false;
  const mapped = s.match(/^::ffff:((?:\d{1,3}\.){3}\d{1,3})$/);
  if (mapped) return validIPv4(mapped[1]);
  if (s.includes(":::")) return false;
  if (!/^[0-9a-f:]+$/.test(s)) return false;
  if ((s.match(/::/g) || []).length > 1) return false;
  const validGroup = g => /^[0-9a-f]{1,4}$/.test(g);
  const parts = s.split(":");
  if (s.includes("::")) {
    const nonEmpty = parts.filter(Boolean);
    if (nonEmpty.length > 7) return false;
    return nonEmpty.every(validGroup);
  }
  return parts.length === 8 && parts.every(validGroup);
}

function extractIPs(raw) {
  const ips = [];
  const text = String(raw || "").slice(0, 8192);
  for (const m of text.matchAll(IPV4_RE)) {
    const before = text.slice(Math.max(0, m.index - 7), m.index).toLowerCase();
    if (before.endsWith("::ffff:")) continue;
    if (validIPv4(m[0])) ips.push(m[0]);
  }

  // Prefer bracketed IPv6 first: X-Originating-IP: [2001:db8::12]
  // Also preserve scoped link-local forms such as fe80::1%en0.
  for (const m of text.matchAll(/\[([0-9A-Za-z:.%_\-]{2,100})\]/g)) {
    if (validIPv6(m[1])) ips.push(m[1]);
  }
  // Then loose tokens, useful for X-Forwarded-For chains.
  for (const m of text.matchAll(/(?:^|[\s,;])([0-9A-Za-z:.%_\-]{2,100})(?=$|[\s,;])/g)) {
    if (validIPv6(m[1])) ips.push(m[1]);
  }

  return ips;
}

function detectSenderIp(headers) {
  const out = [];
  const seen = new Set();
  for (const header of CANDIDATE_HEADERS) {
    for (const raw of getAllHeader(headers, header)) {
      if (!raw) continue;
      const ips = extractIPs(raw);
      for (const ip of ips) {
        const key = `${header}:${ip}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const priv = isPrivateIP(ip);
        out.push(finding("sender_ip", "direct_ip_leak",
                         ip, CONF.HIGH, {
          leaks: { header, raw: raw.slice(0, 300), private: priv },
          notes: [priv
            ? "Private/local sender IP exposed by an originating-IP header."
            : "Sender or forwarding IP exposed by an originating-IP header."]
        }));
      }
    }
  }
  return out;
}

globalThis.OSINTDetect = globalThis.OSINTDetect || {};
globalThis.OSINTDetect.senderIp = detectSenderIp;

})();
