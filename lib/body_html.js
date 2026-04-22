/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// HTML-body MUA signatures. Ported from _body_osint.scan_html.

"use strict";


(() => {
const { finding, CONF } = globalThis.OSINTUtil;

// Generator meta — direct self-claim
const GEN_RX = /<meta\s+name=3?D?"?generator"?\s+content=3?D?"([^"]{1,200})"/i;

// Pattern table: [label, regex]
const SIGS = [
  ["Microsoft Word",
    /<meta\s+name=3?D?"?generator"?\s+content=3?D?"Microsoft Word[^"]*"/i],
  ["Microsoft Word (HTML export)",
    /xmlns:w="urn:schemas-microsoft-com:office:word"/i],
  ["Microsoft Outlook (conditional comment)",
    /<!--\[if gte mso\s+\d+\]>/i],
  ["Microsoft Outlook (MsoNormal CSS)",
    /class=3?D?"?MsoNormal"?/i],
  ["Apple Mail",
    /Apple-interchange-newline|-webkit-text-size-adjust:\s*auto/i],
  ["Apple Mail (Apple-style-span)",
    /class=3?D?"?Apple-style-span"?/i],
  ["Mozilla Thunderbird (moz-cite-prefix)",
    /class=3?D?"?moz-cite-prefix"?|class=3?D?"?moz-signature"?/i],
  ["Gmail Web",
    /class=3?D?"?gmail_quote"?|class=3?D?"?gmail_signature"?/i],
  ["Google Docs (export)",
    /<meta\s+name=3?D?"?generator"?\s+content=3?D?"Google Docs[^"]*"/i],
  ["LibreOffice / OpenOffice",
    /<meta\s+name=3?D?"?generator"?\s+content=3?D?"(?:LibreOffice|OpenOffice)[^"]*"/i],
  ["Pages (Apple)",
    /<meta\s+name=3?D?"?generator"?\s+content=3?D?"Pages[^"]*"/i],
  ["WPS Office",
    /<meta\s+name=3?D?"?generator"?\s+content=3?D?"WPS Office[^"]*"/i],
  ["Outlook for Mac",
    /<meta\s+name=3?D?"?generator"?\s+content=3?D?"Microsoft Outlook for Mac[^"]*"/i],
  ["Outlook.com (webmail)",
    /id=3?D?"?x_divtagdefaultwrapper"?|id=3?D?"?divtagdefaultwrapper"?/i],
  ["Yahoo Mail",
    /class=3?D?"?yahoo_quoted"?|data-yahoo-mail-id/i],
  ["ProtonMail Web",
    /class=3?D?"?protonmail_quote"?|data-pm-style/i],
  ["Spark (Readdle)",
    /class=3?D?"?spark-/i],
  ["Superhuman",
    /x-superhuman-draft-id/i],
  ["HEY (Basecamp)",
    /id=3?D?"?hey-/i],
  ["Front",
    /class=3?D?"?front-/i],
];

// GtkHTML (Evolution) writes its version in generator — capture range.
const GTKHTML_RX = /<meta\s+name=3?D?"?GENERATOR"?\s+content=3?D?"GtkHTML\/([0-9.]+)"/i;

function scanBodyHtml(htmlStr) {
  if (!htmlStr) return [];
  const out = [];
  // Limit scan to first 128 KB
  const body = htmlStr.slice(0, 131072);

  const g = body.match(GEN_RX);
  if (g) {
    const gen = g[1].substring(0, 200);
    out.push(finding("body_osint", "html_generator", gen, CONF.HIGH, {
      notes: ["<meta name=generator> self-claim"]
    }));
    const tb = body.match(GTKHTML_RX);
    if (tb) {
      out.push(finding("body_osint", "html_signature",
                       `Evolution (GtkHTML/${tb[1]})`,
                       CONF.HIGH, {
        leaks: { mua: "GNOME Evolution", gtkhtml_version: tb[1] },
        notes: ["Evolution-MUA via GtkHTML-Versionsstring."]
      }));
    }
  }

  const seen = new Set();
  for (const [label, rx] of SIGS) {
    if (seen.has(label)) continue;
    if (rx.test(body)) {
      seen.add(label);
      out.push(finding("body_osint", "html_signature", label,
                       CONF.MEDIUM, {
        leaks: { mua: label },
      }));
    }
  }
  return out;
}

// Given a Thunderbird message parts tree (from messages.getFull), find the
// HTML part body and scan it.
function findHtmlPart(part) {
  if (!part) return null;
  if (part.contentType && part.contentType.toLowerCase().startsWith("text/html")) {
    return part.body || "";
  }
  if (Array.isArray(part.parts)) {
    for (const sub of part.parts) {
      const hit = findHtmlPart(sub);
      if (hit) return hit;
    }
  }
  return null;
}

function mimeStructure(part, depth = 0) {
  if (!part || depth > 6) return "(…)";
  const ct = (part.contentType || "").toLowerCase();
  if (!Array.isArray(part.parts) || part.parts.length === 0) return ct;
  const inner = part.parts.map(p => mimeStructure(p, depth + 1)).join(", ");
  return `${ct}(${inner})`;
}

function detectBody(message) {
  const out = [];
  if (!message) return out;
  out.push(finding("body_osint", "mime_structure",
                   mimeStructure(message), CONF.MEDIUM));
  const html = findHtmlPart(message);
  if (html) out.push(...scanBodyHtml(html));
  return out;
}

globalThis.OSINTDetect = globalThis.OSINTDetect || {};
globalThis.OSINTDetect.body = detectBody;

})();
