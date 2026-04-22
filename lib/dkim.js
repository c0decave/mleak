/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// DKIM signature + Authentication-Results parsing.
// Ported from det_dkim + det_auth_results.

"use strict";


(() => {
const { getAllHeader, getHeader, finding, CONF } = globalThis.OSINTUtil;

// Vendor hints — selector name often reveals who signed.
const DKIM_VENDOR_HINTS = [
  [/^selector1$|^selector2$/, "Microsoft Office 365"],
  [/^s\d+amazonses$/, "Amazon SES"],
  [/^sendgrid$|^[a-z]+\.sendgrid$|^s\d+-sendgrid/i, "SendGrid"],
  [/^mailgun$|^mg\.?/i, "Mailgun"],
  [/^mandrill$/, "Mandrill (Mailchimp)"],
  [/^mailchimp$|^k1$/i, "Mailchimp"],
  [/^postmark$|^\d+pm$/, "Postmark"],
  [/^fm\d+$|^fastmail$/i, "Fastmail"],
  [/^protonmail\d*$/, "ProtonMail"],
  [/^google$|^2015[0-9]{4}$|^2016[0-9]{4}$|^2017[0-9]{4}$/, "Google / Gmail (dated selector)"],
  [/^zohomail$|^zoho\d*$/, "Zoho Mail"],
  [/^tucows$|^hostedemail/, "HostedEmail (Tucows/OpenSRS)"],
];

// DKIM tags per RFC 6376 are 1–3 letters (v/a/b/bh/c/d/h/i/l/q/s/t/x/z).
// The previous regex only captured a single letter, so "bh=..." was silently
// dropped (bh is the body-hash — important for integrity reporting).
function parseDkimSig(raw) {
  const out = {};
  // Normalize DKIM line-folding (CRLF + whitespace) to single spaces.
  const flat = String(raw).replace(/\s+/g, " ");
  for (const part of flat.split(";")) {
    const m = part.match(/^\s*([a-zA-Z]{1,3})\s*=\s*(.*?)\s*$/);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

function detectDKIM(headers) {
  const out = [];
  const sigs = getAllHeader(headers, "DKIM-Signature");
  for (const raw of sigs) {
    const tags = parseDkimSig(raw);
    const leaks = { selector: tags.s, domain: tags.d,
                    algorithm: tags.a, canon: tags.c,
                    has_bh: !!tags.bh, has_b: !!tags.b };
    let vendorHint = null;
    if (tags.s) {
      for (const [rx, hint] of DKIM_VENDOR_HINTS) {
        if (rx.test(tags.s)) { vendorHint = hint; break; }
      }
    }
    if (vendorHint) {
      leaks.vendor_hint = vendorHint;
    }
    const hTag = tags.h || "";
    leaks.signed_headers = hTag.split(":").map(s => s.trim()).filter(Boolean);

    out.push(finding("dkim", "signature",
                     `${tags.d || "?"}/${tags.s || "?"}`,
                     CONF.HIGH, { leaks }));
  }
  return out;
}

function detectAuthResults(headers) {
  const out = [];
  const ar = getAllHeader(headers, "Authentication-Results");
  for (const raw of ar) {
    const leaks = {};
    for (const test of ["dkim", "spf", "dmarc", "arc", "bimi"]) {
      const m = raw.match(new RegExp(`\\b${test}=(pass|fail|none|neutral|softfail|temperror|permerror|bestguesspass)\\b`, "i"));
      if (m) leaks[test] = m[1].toLowerCase();
    }
    const serverMatch = raw.match(/^\s*([a-zA-Z0-9._\-]+)\s*;/);
    if (serverMatch) leaks.server = serverMatch[1];
    const summary = Object.entries(leaks)
      .filter(([k]) => k !== "server")
      .map(([k, v]) => `${k}=${v}`).join(" · ") || "no verdicts";
    out.push(finding("auth_results", "authentication_verdicts",
                     summary, CONF.HIGH, { leaks }));
  }
  return out;
}

globalThis.OSINTDetect = globalThis.OSINTDetect || {};
globalThis.OSINTDetect.dkim = detectDKIM;
globalThis.OSINTDetect.authResults = detectAuthResults;

})();
