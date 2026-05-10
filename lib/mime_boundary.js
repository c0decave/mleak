/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Generic MIME-boundary detector. Complements crypto_headers.js by scanning
// every MIME message, not only encrypted/signed ones.

"use strict";

(() => {
const { getHeader, finding, CONF } = globalThis.OSINTUtil;

const BOUNDARY_PATTERNS = [
  { re: /^Apple-Mail[=_-]/i,              label: "Apple Mail" },
  { re: /^_000_/,                         label: "Microsoft Outlook / Exchange" },
  { re: /^_NextPart_/i,                   label: "Microsoft Outlook" },
  { re: /^----=_NextPart_/i,              label: "Outlook Express" },
  { re: /^----=_Part_/i,                  label: "JavaMail" },
  { re: /^------------[A-Fa-f0-9]{6,}$/,  label: "Thunderbird / Mozilla-style" },
  { re: /^===============\d+==$/,         label: "Python email / Mailman" },
  { re: /^b1_[A-Za-z0-9]{16,}/,           label: "PHPMailer" },
  { re: /^=-[A-Za-z0-9+/]{16,}/,          label: "Evolution / GMime" },
  { re: /^000000000000[0-9A-Fa-f]+/,      label: "Gmail Web" },
  { re: /^----boundary-LibPST-/i,         label: "Outlook / PST import" },
];

function collectContentTypes(part, depth, acc) {
  if (!part || depth > 6 || acc.length >= 256) return acc;
  if (part.contentType && typeof part.contentType === "string") {
    acc.push(part.contentType.slice(0, 8192));
  }
  if (Array.isArray(part.parts)) {
    for (const sub of part.parts.slice(0, 64)) {
      if (acc.length >= 256) break;
      collectContentTypes(sub, depth + 1, acc);
    }
  }
  return acc;
}

function unquoteBoundary(s) {
  if (!s) return "";
  const trimmed = s.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/\\"/g, '"').slice(0, 200);
  }
  return trimmed.replace(/^["']|["']$/g, "").slice(0, 200);
}

function extractBoundary(contentType) {
  if (!contentType) return "";
  const m = String(contentType).match(/\bboundary\s*=\s*("(?:(?:\\.)|[^"]){1,220}"|[^;\s]{1,220})/i);
  return m ? unquoteBoundary(m[1]) : "";
}

function boundaryLabel(boundary) {
  for (const pat of BOUNDARY_PATTERNS) {
    if (pat.re.test(boundary)) return pat.label;
  }
  return "";
}

function detectMimeBoundary(message) {
  const out = [];
  if (!message) return out;
  const headers = message.headers || {};
  const ctypes = [];
  const outer = getHeader(headers, "Content-Type");
  if (outer) ctypes.push(outer);
  collectContentTypes(message, 0, ctypes);

  const seenBoundaries = new Set();
  const seenLabels = new Set();
  let emittedRaw = false;
  for (const ct of ctypes) {
    const boundary = extractBoundary(ct);
    if (!boundary || seenBoundaries.has(boundary)) continue;
    seenBoundaries.add(boundary);

    const label = boundaryLabel(boundary);
    if (label) {
      if (seenLabels.has(label)) continue;
      seenLabels.add(label);
      out.push(finding("mime_boundary", "client_fingerprint",
                       label, CONF.MEDIUM, {
        leaks: { boundary: boundary.slice(0, 120), src: "Content-Type boundary" },
        notes: ["MUA hint from MIME boundary shape."]
      }));
    } else if (!emittedRaw) {
      emittedRaw = true;
      out.push(finding("mime_boundary", "boundary_raw",
                       boundary.slice(0, 80), CONF.LOW, {
        leaks: { boundary: boundary.slice(0, 120), src: "Content-Type boundary" },
        notes: ["Unknown MIME boundary shape; useful for clustering similar senders."]
      }));
    }
    if (out.length >= 6) break;
  }

  return out;
}

globalThis.OSINTDetect = globalThis.OSINTDetect || {};
globalThis.OSINTDetect.mimeBoundary = detectMimeBoundary;

})();
