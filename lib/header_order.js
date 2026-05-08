/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Header-order fingerprint + UA/header-order consistency check.
//
// This is intentionally passive: the detector only inspects the header map
// already returned by Thunderbird's messages.getFull(). It never performs
// DNS, HTTP or any other external lookup.

"use strict";

(() => {
const { getHeader, finding, CONF } = globalThis.OSINTUtil;

const CANONICAL = Object.freeze({
  "return-path": "Return-Path",
  "delivered-to": "Delivered-To",
  "received": "Received",
  "authentication-results": "Authentication-Results",
  "arc-seal": "ARC-Seal",
  "arc-message-signature": "ARC-Message-Signature",
  "arc-authentication-results": "ARC-Authentication-Results",
  "dkim-signature": "DKIM-Signature",
  "domainkey-signature": "DomainKey-Signature",
  "from": "From",
  "sender": "Sender",
  "reply-to": "Reply-To",
  "to": "To",
  "cc": "Cc",
  "bcc": "Bcc",
  "subject": "Subject",
  "date": "Date",
  "sent": "Sent",
  "message-id": "Message-ID",
  "in-reply-to": "In-Reply-To",
  "references": "References",
  "mime-version": "MIME-Version",
  "content-type": "Content-Type",
  "content-transfer-encoding": "Content-Transfer-Encoding",
  "content-language": "Content-Language",
  "user-agent": "User-Agent",
  "x-mailer": "X-Mailer",
  "x-mimeole": "X-MimeOLE",
  "x-newsreader": "X-Newsreader",
  "x-priority": "X-Priority",
  "importance": "Importance",
  "organization": "Organization",
  "list-id": "List-Id",
  "list-post": "List-Post",
  "list-unsubscribe": "List-Unsubscribe",
  "precedence": "Precedence",
});

const AUTHORED_HEADERS = new Set([
  "From", "Sender", "Reply-To", "To", "Cc", "Bcc", "Subject", "Date",
  "Sent", "Message-ID", "In-Reply-To", "References", "MIME-Version",
  "Content-Type", "Content-Transfer-Encoding", "Content-Language",
  "User-Agent", "X-Mailer", "X-MimeOLE", "X-Newsreader", "X-Priority",
  "Importance", "Organization",
]);

const EXPECTED_PREFIXES = Object.freeze({
  thunderbird: [
    ["Date", "From", "To"],
    ["From", "Date", "Subject"],
    ["Message-ID", "Date"],
  ],
  outlook: [
    ["From", "To", "Subject"],
    ["From", "Sent", "To"],
    ["Date", "Subject", "From"],
  ],
  "apple mail": [
    ["From", "Subject", "Date"],
    ["Content-Transfer-Encoding", "From", "MIME-Version"],
  ],
  mutt: [
    ["From", "Date", "To"],
    ["Date", "From", "To"],
  ],
  evolution: [
    ["From", "To", "Subject"],
  ],
  kmail: [
    ["From", "To", "Subject"],
  ],
  "git-send-email": [
    ["From", "To", "Subject"],
    ["From", "To", "Cc"],
  ],
  gmail: [
    ["MIME-Version", "From", "Date"],
    ["Date", "Message-ID", "Subject"],
  ],
});

function titleCaseHeader(lower) {
  if (!lower) return "";
  if (CANONICAL[lower]) return CANONICAL[lower];
  if (lower.startsWith("x-ms-")) return "X-MS-*";
  if (lower.startsWith("x-google-")) return "X-Google-*";
  if (lower.startsWith("x-")) {
    return lower.split("-").map(p => p ? p[0].toUpperCase() + p.slice(1) : p).join("-");
  }
  return lower.split("-").map(p => p ? p[0].toUpperCase() + p.slice(1) : p).join("-");
}

function headerOrder(headers) {
  const out = [];
  const seen = new Set();
  for (const key of Object.keys(headers || {})) {
    const lower = String(key).toLowerCase();
    const label = titleCaseHeader(lower);
    if (!label || seen.has(label)) continue;
    seen.add(label);
    out.push(label);
    if (out.length >= 32) break;
  }
  return out;
}

function authoredOrder(headers) {
  const out = [];
  for (const label of headerOrder(headers)) {
    if (!AUTHORED_HEADERS.has(label)) continue;
    out.push(label);
    if (out.length >= 6) break;
  }
  return out;
}

function rawUa(headers) {
  return getHeader(headers, "User-Agent")
      || getHeader(headers, "X-Mailer")
      || getHeader(headers, "X-MimeOLE")
      || getHeader(headers, "X-Newsreader");
}

function claimedFamily(headers) {
  const raw = rawUa(headers);
  const low = raw.toLowerCase();
  if (!low) return "";
  if (low.includes("thunderbird") || low.includes("betterbird") ||
      low.includes("icedove")) return "thunderbird";
  if (low.includes("outlook") || low.includes("microsoft-macoutlook") ||
      low.includes("mimeole") || low.includes("exchange")) return "outlook";
  if (low.includes("apple mail") || low.includes("iphone mail") ||
      low.includes("ipad mail")) return "apple mail";
  if (low.includes("neomutt") || low.includes("mutt/")) return "mutt";
  if (low.includes("evolution")) return "evolution";
  if (low.includes("kmail")) return "kmail";
  if (low.includes("git-send-email")) return "git-send-email";
  if (low.includes("gmail")) return "gmail";
  return "";
}

function orderedSubsequence(expected, observed) {
  let pos = -1;
  for (const h of expected) {
    const next = observed.indexOf(h, pos + 1);
    if (next < 0) return false;
    pos = next;
  }
  return true;
}

function isReply(headers) {
  const subject = getHeader(headers, "Subject");
  return Boolean(getHeader(headers, "In-Reply-To") ||
                 getHeader(headers, "References") ||
                 /^re\s*:/i.test(subject));
}

function detectHeaderOrder(headers) {
  const out = [];
  const order = headerOrder(headers);
  if (order.length) {
    out.push(finding("header_order", "order_fingerprint",
                     order.join("|"), CONF.LOW, {
      leaks: { order },
      notes: ["Header insertion order can fingerprint MUAs, scripts and MTAs."]
    }));
  }

  const family = claimedFamily(headers);
  const expected = family ? EXPECTED_PREFIXES[family] : null;
  if (!expected) return out;

  const observed = authoredOrder(headers);
  // Too little authored context is weaker than the signal itself; avoid
  // turning sparse forwarded/bounced mail into a false anomaly.
  if (observed.length < 3) return out;
  const prefix = observed.slice(0, 4);
  const ok = expected.some(seq => orderedSubsequence(seq, prefix));
  if (!ok) {
    const reply = isReply(headers);
    out.push(finding("ua_consistency", "ua_header_order_mismatch",
                     `${family}: ${observed.join("|")}`,
                     reply ? CONF.LOW : CONF.MEDIUM, {
      leaks: {
        ua: rawUa(headers).slice(0, 200),
        claimed_family: family,
        observed_order: observed,
        expected_any_of: expected,
        is_reply: reply,
      },
      notes: ["UA/X-Mailer claim does not match the typical authored-header order."]
    }));
  }

  return out;
}

globalThis.OSINTDetect = globalThis.OSINTDetect || {};
globalThis.OSINTDetect.headerOrder = detectHeaderOrder;

})();
