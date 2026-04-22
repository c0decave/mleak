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
  ],
  exchange: [
    ["Thread-Index",                                "msft_thread_index","Exchange thread-index hash"],
    ["Thread-Topic",                                "msft_thread_topic","Exchange conversation topic"],
    ["X-MS-Exchange-CrossTenant-Id",                "msft_tenant_id","M365 Tenant-GUID"],
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
  const allKeys = Object.keys(headers || {});
  for (const w of WILDCARD_PREFIXES) {
    const hit = allKeys.find(k => k.toLowerCase().startsWith(w.prefix));
    if (hit) {
      const v = getHeader(headers, hit);
      out.push(finding("server_headers", w.kind, String(v).slice(0, 200),
                       CONF.HIGH, {
        leaks: { family: w.family, header: hit },
        notes: w.note ? [w.note] : [],
      }));
    }
  }

  return out;
}

globalThis.OSINTDetect = globalThis.OSINTDetect || {};
globalThis.OSINTDetect.serverHeaders = detectServerHeaders;

})();
