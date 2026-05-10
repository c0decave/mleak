/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Proprietary server-side headers: Gmail / Exchange / Apple iCloud / Yahoo /
// Delivery markers. Ported from det_server_headers in mail_osint.py.

"use strict";


(() => {
const { getHeader, getAllHeader, finding, CONF } = globalThis.OSINTUtil;

const FAMILIES = {
  gmail: [
    ["X-Gm-Message-State", "gm_state", "Gmail server-side state hash"],
    ["X-GM-THRID",         "gm_thrid", "Gmail 64-bit thread ID"],
    ["X-GM-MSGID",         "gm_msgid", "Gmail 64-bit message ID"],
    ["X-GM-LABELS",        "gm_labels","Gmail user labels (IMAP export)"],
    ["X-Google-Smtp-Source","gmail_smtp_src","Gmail SMTP relay base64 hash"],
    ["X-Google-DKIM-Signature","gmail_dkim","Gmail-generated DKIM sig"],
    ["X-Gm-Gg",            "gmail_gg","Gmail internal feature tag"],
    ["X-Gm-Features",      "gmail_feat","Gmail internal feature flags"],
    ["X-Received",         "gmail_x_received","Google/Gmail internal relay receipt"],
  ],
  exchange: [
    ["Thread-Index",                                "msft_thread_index","Exchange thread-index hash"],
    ["Thread-Topic",                                "msft_thread_topic","Exchange conversation topic"],
    ["X-MS-Exchange-CrossTenant-Id",                "msft_tenant_id","M365 Tenant-GUID"],
    ["X-MS-Exchange-Organization-AuthSource",       "msft_org_authsource","Exchange auth source host"],
    ["X-MS-Exchange-CrossTenant-AuthSource",        "msft_tenant_authsource","M365 cross-tenant auth source host"],
    ["X-MS-Exchange-CrossTenant-OriginalArrivalTime","msft_tenant_arrival",""],
    ["X-MS-Exchange-Organization-Network-Message-Id","msft_org_netmsg_id",""],
    ["X-MS-Exchange-Transport-CrossTenantHeadersStamped","msft_transport_stamped",""],
    ["X-Microsoft-Antispam",                        "msft_antispam","Antispam policy block"],
    ["X-Microsoft-Antispam-Mailbox-Delivery",       "msft_antispam_delivery",""],
    ["X-Microsoft-Antispam-Message-Info",           "msft_antispam_info",""],
    ["X-Forefront-Antispam-Report",                 "msft_forefront","Forefront/Defender spam report"],
    ["X-MS-Has-Attach",                             "msft_has_attach",""],
    ["X-MS-TNEF-Correlator",                        "msft_tnef","TNEF correlator — Outlook usage"],
    ["X-MS-Office365-Filtering-Correlation-Id",     "msft_o365_filter","Office 365 filter correlation ID"],
  ],
  apple: [
    ["X-Apple-Base-Url",                "apple_base_url",   "iCloud Mail internal"],
    ["X-Apple-Mail-Remote-Attachments", "apple_remote_att", ""],
    ["X-Apple-Auth-Domain",             "apple_auth_dom",   ""],
    ["X-ICL-InReplyTo",                 "apple_icl_irt",    "iCloud thread reference"],
  ],
  yahoo: [
    ["X-YMail-OSG",       "yahoo_ymail_osg",  "Yahoo outgoing SMTP gateway"],
    ["X-Ymail-ID",        "yahoo_ymail_id",   ""],
    ["X-Sonic-ID",        "yahoo_sonic_id",   "Yahoo Sonic relay ID"],
    ["X-Yahoo-Newman-Id", "yahoo_newman_id",  ""],
  ],
  delivery: [
    ["Delivered-To",  "delivered_to", "Final envelope recipient (mailbox-owner clue)"],
    ["X-Original-To", "original_to",  "Envelope-original recipient"],
    ["Return-Path",   "return_path",  "SMTP envelope-from"],
    ["Autocrypt",     "autocrypt",    "Autocrypt public-key advertisement"],
    ["Auto-Submitted","auto_submitted","RFC 3834 automation marker"],
    ["X-Auto-Response-Suppress","auto_suppress",""],
    ["X-Proofpoint-Virus-Version","proofpoint_virus","Proofpoint AV version"],
    ["X-Mimecast-Spam-Score",    "mimecast_spam","Mimecast spam score"],
    ["X-CMAE-Envelope",          "cmae_envelope","Cisco IronPort envelope"],
  ],
};

// Headers that start with these prefixes are always captured (wildcard).
const WILDCARD_PREFIXES = [
  { prefix: "x-barracuda-",  family: "delivery", kind: "barracuda_marker",
    note: "Barracuda filter marker" },
];

const RECEIVED_HOST_PATTERNS = [
  { family: "gmail", kind: "gmail_received_host",
    re: /(^|\.)google(?:mail)?\.com$|(^|\.)gmail\.com$/i,
    note: "Google/Gmail relay hostname in Received chain" },
  { family: "exchange", kind: "msft_received_host",
    re: /(^|\.)outlook\.com$|(^|\.)protection\.outlook\.com$|(^|\.)office365\.com$/i,
    note: "Microsoft 365 / Exchange relay hostname in Received chain" },
  { family: "apple", kind: "apple_received_host",
    re: /(^|\.)icloud\.com$|(^|\.)me\.com$/i,
    note: "Apple iCloud relay hostname in Received chain" },
  { family: "yahoo", kind: "yahoo_received_host",
    re: /(^|\.)yahoo\.com$/i,
    note: "Yahoo relay hostname in Received chain" },
];
const MAX_HEADER_KEYS_TO_SCAN = 512;
const MAX_RECEIVED_HOST_TOKENS = 16;
const MAX_RECEIVED_HOST_FINDINGS = 64;

function normalizeHostToken(host) {
  let h = String(host || "").trim().replace(/[<>]/g, "");
  if (!h) return "";
  if (h.startsWith("[") && h.endsWith("]")) return "";
  h = h.replace(/\.$/, "").toLowerCase();
  if (/^(?:ipv6:)?[0-9a-f:.%]+$/i.test(h) && h.includes(":")) return "";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(h)) return "";
  return h.length > 240 ? h.slice(0, 240) + "...[truncated]" : h;
}

function receivedHostTokens(receivedLine) {
  const out = [];
  const text = String(receivedLine || "").slice(0, 4096);
  for (const m of text.matchAll(/\b(?:from|by)\s+([^\s;()]+)/gi)) {
    const host = normalizeHostToken(m[1]);
    if (host) out.push(host);
    if (out.length >= MAX_RECEIVED_HOST_TOKENS) break;
  }
  return out;
}

function detectServerHeaders(headers) {
  const out = [];
  const seenFamilies = {};

  for (const [family, entries] of Object.entries(FAMILIES)) {
    const present = [];
    for (const [hdr, kind, note] of entries) {
      const v = getHeader(headers, hdr);
      if (!v) continue;
      let value = String(v).trim();
      if (value.length > 200) value = value.slice(0, 200) + "…";
      present.push({ hdr, kind, value, note });
      out.push(finding("server_headers", kind, value, CONF.HIGH, {
        leaks: { family, header: hdr },
        notes: note ? [note] : [],
      }));
    }
    if (present.length > 0) {
      seenFamilies[family] = present;
      out.push(finding("server_headers", family + "_stack", family,
                       CONF.HIGH, {
        leaks: { family, header_count: present.length,
                 headers: present.map(p => p.hdr) },
        notes: [`Message carries ${present.length} ${family} header(s).`],
      }));
    }
  }

  // Wildcard prefix scan
  const allKeys = Object.keys(headers || {}).slice(0, MAX_HEADER_KEYS_TO_SCAN);
  for (const w of WILDCARD_PREFIXES) {
    const hit = allKeys.find(k => k.toLowerCase().startsWith(w.prefix));
    if (hit) {
      const v = getHeader(headers, hit);
      out.push(finding("server_headers", w.kind, String(v).slice(0, 200),
                       CONF.HIGH, {
        leaks: { family: w.family, header: hit },
        notes: w.note ? [w.note] : [],
      }));
      if (!seenFamilies[w.family]) {
        seenFamilies[w.family] = [{ hdr: hit, kind: w.kind, value: v }];
        out.push(finding("server_headers", w.family + "_stack", w.family,
                         CONF.HIGH, {
          leaks: { family: w.family, header_count: 1, headers: [hit] },
          notes: [w.note || `Message carries ${w.family} marker(s).`],
        }));
      }
    }
  }

  const receivedHits = {};
  let receivedHitCount = 0;
  for (const line of getAllHeader(headers, "Received")) {
    for (const host of receivedHostTokens(line)) {
      for (const pat of RECEIVED_HOST_PATTERNS) {
        if (!pat.re.test(host)) continue;
        const key = `${pat.family}:${host}`;
        if (receivedHits[key]) continue;
        receivedHits[key] = { family: pat.family, host, kind: pat.kind, note: pat.note };
        receivedHitCount++;
        out.push(finding("server_headers", pat.kind, host, CONF.MEDIUM, {
          leaks: { family: pat.family, header: "Received", host },
          notes: [pat.note],
        }));
        if (receivedHitCount >= MAX_RECEIVED_HOST_FINDINGS) break;
      }
      if (receivedHitCount >= MAX_RECEIVED_HOST_FINDINGS) break;
    }
    if (receivedHitCount >= MAX_RECEIVED_HOST_FINDINGS) break;
  }
  for (const hit of Object.values(receivedHits)) {
    if (seenFamilies[hit.family]) continue;
    seenFamilies[hit.family] = [{ hdr: "Received", kind: hit.kind, value: hit.host }];
    out.push(finding("server_headers", hit.family + "_stack", hit.family,
                     CONF.MEDIUM, {
      leaks: { family: hit.family, header_count: 1, headers: ["Received"] },
      notes: [hit.note],
    }));
  }

  return out;
}

globalThis.OSINTDetect = globalThis.OSINTDetect || {};
globalThis.OSINTDetect.serverHeaders = detectServerHeaders;

})();
