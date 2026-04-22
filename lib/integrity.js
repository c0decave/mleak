/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Integrity checks — missing Date / MID, From↔Sender↔Reply-To divergence,
// DKIM h=-Coverage lightweight.

"use strict";


(() => {
const { getHeader, getAllHeader, finding, CONF,
        extractAddress } = globalThis.OSINTUtil;

function detectIntegrity(headers) {
  const out = [];

  if (!getHeader(headers, "Date")) {
    out.push(finding("integrity", "missing_date", "Date: header absent",
                     CONF.MEDIUM,
                     { notes: ["RFC 5322 verlangt Date — Fehlen ist Anomalie."] }));
  }
  if (!getHeader(headers, "Message-ID")) {
    out.push(finding("integrity", "missing_message_id", "Message-ID absent",
                     CONF.MEDIUM, { notes: ["RFC-konforme Mails haben MID."] }));
  }

  const frm = extractAddress(getHeader(headers, "From"));
  const snd = extractAddress(getHeader(headers, "Sender"));
  const rpl = extractAddress(getHeader(headers, "Reply-To"));
  if (frm && snd && frm !== snd) {
    out.push(finding("integrity", "from_sender_divergence",
                     `From:${frm}  ≠  Sender:${snd}`,
                     CONF.MEDIUM, {
      notes: ["From:/Sender:-Divergenz — legitim bei MLMs, " +
              "Phishing-Signal wenn kein MLM-Kontext."]
    }));
  }
  if (frm && rpl && frm !== rpl) {
    const frmDom = frm.split("@")[1] || "";
    const rplDom = rpl.split("@")[1] || "";
    if (frmDom !== rplDom) {
      out.push(finding("integrity", "reply_to_cross_domain",
                       `From:${frmDom}  ≠  Reply-To:${rplDom}`,
                       CONF.LOW, {
        notes: ["Reply-To auf Fremd-Domain — auffällig (Spear-Phishing-Pattern)."]
      }));
    }
  }

  // Multiple From (RFC forbids more than one in most contexts)
  const fromCount = getAllHeader(headers, "From").length;
  if (fromCount > 1) {
    out.push(finding("integrity", "multiple_from_headers",
                     `${fromCount} From: headers`,
                     CONF.HIGH, {
      notes: ["Mehrfach-From — Header-Confusion-Angriffsvektor " +
              "(CVE-2020-12272-Klasse)."]
    }));
  }

  // Lightweight DKIM oversigning check: h= should include every header it
  // claims to protect, but some MTAs re-sign and lose coverage.
  const dkimSigs = getAllHeader(headers, "DKIM-Signature");
  for (const sig of dkimSigs) {
    const hM = sig.match(/\bh=\s*([^;]+)/);
    if (!hM) continue;
    const hList = hM[1].split(":").map(s => s.trim().toLowerCase()).filter(Boolean);
    const protected_ = new Set(hList);
    const critical = ["from", "subject", "date", "message-id"];
    const missing = critical.filter(h => !protected_.has(h));
    if (missing.length) {
      out.push(finding("integrity", "dkim_coverage_gap",
                       missing.join(","),
                       CONF.MEDIUM, {
        notes: [`DKIM h= schützt nicht: ${missing.join(", ")} — Replay-/Spoof-Risiko.`]
      }));
    }
    // Oversigning check: header name listed twice in h= = explicit oversigning
    const counts = {};
    for (const h of hList) counts[h] = (counts[h] || 0) + 1;
    const oversigned = Object.keys(counts).filter(k => counts[k] > 1);
    if (oversigned.length) {
      out.push(finding("integrity", "dkim_oversigning",
                       oversigned.join(","),
                       CONF.HIGH, {
        notes: [`DKIM h= signiert diese Header doppelt: ${oversigned.join(", ")}  ` +
                "— konservative, korrekte Praxis."]
      }));
    }
  }

  return out;
}

globalThis.OSINTDetect = globalThis.OSINTDetect || {};
globalThis.OSINTDetect.integrity = detectIntegrity;

})();
