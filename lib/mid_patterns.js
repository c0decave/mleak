/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Message-ID pattern catalog — ported from tools/mail_osint.py.
// Order matters: first high-confidence match wins.

"use strict";

// All lib/*.js files share one global scope in the MV2 background page, so
// top-level `const` collisions across files are hard errors. IIFE-wrap to
// keep our locals (getHeader, finding, …) scoped to this file; only the
// `globalThis.OSINTDetect.*` assignments at the bottom escape.
(() => {

const { structuralSignature, finding, CONF,
        INTERNAL_TLDS, looksInternalDomain } = globalThis.OSINTUtil;

// M365 datacenter code → region hint
const M365_DC_CODES = {
  AM: "Amsterdam", AS: "Asia-Pacific", BE: "Belgium", BY: "Budapest",
  CH: "Chicago", CO: "Columbus", CY: "Cheyenne", DB: "Dublin",
  DM: "Des Moines", DU: "Dublin", EUR: "Europe", FR: "France",
  HE: "Helsinki", HK: "Hong Kong", IND: "India", JPN: "Japan",
  KL: "Kuala Lumpur", LO: "London", MN: "Montreal", MW: "Midwest US",
  NAM: "North America", PH: "Phoenix", PS: "Pusan (Korea)",
  PU: "Phoenix", QB: "Quebec", SI: "Singapore", SN: "San Antonio",
  SJ: "San Jose", SY: "Sydney", TO: "Toronto", TY: "Tokyo",
  VI: "Vienna", ZA: "South Africa",
};

// Each rule: {name, rx, label, handler?}
// handler(m, leaks, notes) → may set confidence via returned object.
const PATTERNS = [];

function P(name, rx, label, handler = null, confidence = "high") {
  PATTERNS.push({ name, rx, label, handler, confidence });
}

// Microsoft Exchange Online / M365 (very specific host-pod suffix)
P("exchange-online",
  /^<[A-Z0-9]+@([A-Z0-9]+)\.([a-z]+prd\d+)\.prod\.outlook\.com>$/i,
  "Microsoft Exchange Online / M365",
  (m, leaks, notes) => {
    const host = m[1], pod = m[2];
    const dc = host.match(/^([A-Z]{2,3}\d?)PR\d+(MB|CA|PU|HE|OLK)\d+/i);
    if (dc) {
      leaks.datacenter_code = dc[1];
      leaks.datacenter_hint = M365_DC_CODES[dc[1]] || "unknown";
      leaks.server_role = {
        MB: "Mailbox", CA: "ClientAccess", PU: "PublicFolder", OLK: "Outlook"
      }[dc[2]] || dc[2];
    }
    leaks.tenant_pod = pod;
    leaks.mailbox_host = host;
  });

// Gmail Web (modern CA*- prefix)
P("gmail-web-modern",
  /^<(CA[A-Z]*)[\-+=_][A-Za-z0-9+\/=_\-]+@mail\.gmail\.com>$/,
  "Gmail Web (modern)");

// Gmail Web (legacy pre-2015)
P("gmail-web-legacy",
  /^<[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+@mail\.gmail\.com>$/i,
  "Gmail Web (legacy)");

// Gmail via SMTP / mobile
P("gmail-smtp",
  /^<[A-Za-z0-9._\-]+@gmail\.com>$/,
  "Gmail SMTP / mobile / generic",
  null, "medium");

// Google Groups
P("google-groups",
  /^<[A-Za-z0-9._\-]+@googlegroups\.com>$/,
  "Google Groups Mailing List");

// Gmail (catch-all fallback for any @mail.gmail.com not matched above)
P("gmail-generic",
  /^<.+@mail\.gmail\.com>$/,
  "Gmail (mail.gmail.com; pre-CA* oder unerkannter Prefix)",
  null, "medium");

// Googlemail (pre-2010 domain)
P("gmail-old-domain",
  /^<[^>]+@googlemail\.com>$/,
  "Gmail (googlemail.com, ~pre-2010)");

// Apple Mail: UUID-style with hostname. Case-sensitive UPPERCASE to distinguish
// from Thunderbird's lowercase UUIDs (both share identical structure).
P("apple-mail-uuid",
  /^<[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}@([A-Za-z0-9.\-]+)>$/,
  "Apple Mail (macOS/iOS)",
  (m, leaks, notes) => {
    const host = m[1];
    leaks.hostname = host;
    if (looksInternalDomain(host) || /\.home$|\.local$/.test(host)) {
      leaks.hostname_leak = true;
      notes.push("Personal-Hostname im Message-ID (Default-Mac-Config leakt Device-Namen).");
    }
  });

// iCloud hosted mail
P("icloud",
  /^<[A-Za-z0-9._\-]+@icloud\.com>$/,
  "Apple iCloud Mail");

// Mozilla Thunderbird — lowercase UUID (case-sensitive to distinguish from Apple)
P("thunderbird",
  /^<[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}@([A-Za-z0-9.\-]+)>$/,
  "Mozilla Thunderbird",
  (m, leaks) => { leaks.hostname = m[1]; },
  "medium");

// mutt (YYYYMMDDHHMMSS + local tag)
P("mutt",
  /^<(\d{14})\.[A-Za-z]{6,10}@([A-Za-z0-9.\-]+)>$/,
  "mutt",
  (m, leaks, notes) => {
    leaks.timestamp_local = m[1];
    leaks.hostname = m[2];
    notes.push("mutt-Timestamp ist in LOKALER Zeitzone des Absenders.");
  });

// Pine / Alpine (UW-IMAP classic)
P("pine-alpine",
  /^<(Pine|alpine)\.[A-Z]{3}\.\d+\.[^>]+@([A-Za-z0-9.\-]+)>$/i,
  "Pine / Alpine (UW-IMAP)",
  (m, leaks) => { leaks.variant = m[1]; leaks.hostname = m[2]; });

// Evolution (GNOME mail client, classic .camel)
P("evolution",
  /^<\d+\.\d+\.\d+\.camel@([A-Za-z0-9.\-]+)>$/,
  "GNOME Evolution",
  (m, leaks) => { leaks.hostname = m[1]; });

// KMail
P("kmail",
  /^<\d+\.\d+\.[A-Za-z]+@([A-Za-z0-9.\-]+)>$/,
  "KDE KMail",
  (m, leaks) => { leaks.hostname = m[1]; },
  "medium");

// Outlook on-prem (OLKxxx prefix) — classic MAPI / Outlook 2007+
P("outlook-mapi",
  /^<OLK[A-Za-z0-9]+@([A-Za-z0-9.\-]+)>$/,
  "Microsoft Outlook (MAPI on-prem)",
  (m, leaks) => { leaks.host = m[1]; });

// Lotus Notes / Domino (OF-segment + optional ON-segment)
P("lotus-notes",
  /^<OF[0-9A-F.\-]+(?:ON[0-9A-F.\-]+)?@([A-Za-z0-9.\-]+)>$/i,
  "IBM Lotus Notes / Domino",
  (m, leaks, notes) => {
    leaks.domain = m[1];
    notes.push("OF/ON-Segmente kodieren NSF-DocID + Replica-ID.");
  });

// JavaMail / Jakarta Mail
P("javamail",
  /^<\d+\.\d+\.\d+\.JavaMail\.(root|[\w]+)@([A-Za-z0-9.\-]+)>$/,
  "JavaMail / Jakarta Mail",
  (m, leaks, notes) => {
    leaks.user = m[1]; leaks.host = m[2];
    notes.push("JavaMail leakt OS-User im Message-ID-Local-Part.");
  });

// git-send-email (classic: UNIX-epoch-PID-N-git-send-email-user)
P("git-send-email-classic",
  /^<(\d{10,13})-(\d+)-(\d+)-git-send-email-([^@]+)@([A-Za-z0-9.\-]+)>$/,
  "git-send-email (classic)",
  (m, leaks, notes) => {
    leaks.unix_epoch = m[1]; leaks.pid = m[2]; leaks.patch_index = m[3];
    leaks.user = m[4]; leaks.hostname = m[5];
    notes.push("Classic git-send-email leakt Epoch, PID und OS-Username.");
  });

// git-send-email (modern)
P("git-send-email-modern",
  /^<\d{14}\.\d+-\d+-[A-Za-z0-9._\-]+@[A-Za-z0-9.\-]+>$/,
  "git-send-email (modern)",
  null, "medium");

// b4 patch series (YYYYMMDD-topic-vN-M-hash12)
P("b4-patch-series",
  /^<(\d{8})-(.+?)-v(\d+)-(\d+)-([0-9a-f]{12})@([A-Za-z0-9.\-]+)>$/,
  "b4 (Kernel patch series)",
  (m, leaks) => {
    leaks.date = m[1]; leaks.topic = m[2]; leaks.version = m[3];
    leaks.patch_index = m[4]; leaks.hash12 = m[5]; leaks.hostname = m[6];
  });

// b4 cover-letter (YYYYMMDD-word-word-word-hash6)
P("b4-cover",
  /^<(\d{8})-([a-z]+(?:-[a-z]+)+)-([0-9a-f]{6})@([A-Za-z0-9.\-]+)>$/,
  "b4 (cover-letter / draft)",
  (m, leaks) => {
    leaks.date = m[1]; leaks.slug = m[2];
    leaks.hash6 = m[3]; leaks.hostname = m[4];
  });

// Fastmail web
P("fastmail-web",
  /^<[0-9a-f]{32}-[0-9a-f]{16}@[A-Za-z0-9.\-]+\.fastmail(?:usercontent)?\.com>$/i,
  "Fastmail Web");

// ProtonMail Bridge / Web
P("protonmail",
  /^<[A-Za-z0-9_\-]+@(protonmail\.com|pm\.me)>$/,
  "ProtonMail");

// Yahoo Mail
P("yahoo-mail",
  /^<[0-9]+\.[0-9]+\.[0-9]+\.JavaMail\.[^@]+@([a-z0-9.\-]+\.yahoo\.com)>$/i,
  "Yahoo Mail (JavaMail backend)");
P("yahoo-mail-modern",
  /^<\d+\.\d+\.[A-Za-z0-9]+@[a-z0-9.\-]+\.mail\.yahoo\.com>$/i,
  "Yahoo Mail");

// SquirrelMail (must come BEFORE roundcube: both start with 32-hex)
P("squirrelmail",
  /^<[0-9a-f]{32}\.squirrel@([A-Za-z0-9.\-]+)>$/,
  "SquirrelMail",
  (m, leaks) => { leaks.host = m[1]; });

// Roundcube (common webmail)
P("roundcube",
  /^<[0-9a-f]{32}@([A-Za-z0-9.\-]+)>$/,
  "Roundcube Webmail",
  (m, leaks) => { leaks.host = m[1]; },
  "medium");

// Evolution (modern, post-.camel: 40-hex.5-lower)
P("evolution-modern",
  /^<([0-9a-f]{40})\.([a-z]{5})@([A-Za-z0-9.\-]+)>$/,
  "GNOME Evolution (post-.camel)",
  (m, leaks) => {
    leaks.sha1_hash = m[1];
    leaks.suffix = m[2];
    leaks.hostname = m[3];
  });

// Tutanota
P("tutanota",
  /^<[^>]+@(?:tutanota|tutamail)\.(?:com|de)>$/,
  "Tutanota");

// Zoho Mail
P("zoho",
  /^<[^>]+@(?:zmail\.)?(?:mail\.)?zoho\.(?:com|eu)>$/,
  "Zoho Mail");

// Outlook Express classic (pre-2007)
P("outlook-express",
  /^<\$\$[^>]+\$@[^>]+>$/,
  "Outlook Express classic (pre-2007)",
  null, "medium");

// SOGo
P("sogo",
  /^<\d+-\d+-[A-Za-z0-9]+@([A-Za-z0-9.\-]+)>$/,
  "SOGo (Groupware)",
  null, "low");

// GitGitGadget bridge (GitHub → git mailing list)
P("gitgitgadget",
  /^<[a-f0-9]{40}\.\d+\.git\.gitgitgadget@gmail\.com>$/i,
  "GitGitGadget (GitHub → git mailing list bridge)");

// Mailman 2/3 generated IDs
P("mailman",
  /^<mailman\.\d+\.\d+\.\d+\.[\w\-]+@([A-Za-z0-9.\-]+)>$/,
  "Mailman (MLM-generated)",
  (m, leaks) => { leaks.list_host = m[1]; });

// Exim smart-host style (Debian)
P("exim-smart-host",
  /^<[Ee]\d[A-Za-z0-9]{5,}-\d{3,}[A-Za-z0-9]{3}-[A-Za-z0-9]{2,3}@([A-Za-z0-9.\-]+)>$/,
  "Exim (smart-host style)",
  (m, leaks) => { leaks.host = m[1]; });

// Postfix local (queue-ID prefix)
P("postfix-local",
  /^<\d{14}\.[0-9A-F]{6,10}@([A-Za-z0-9.\-]+)>$/,
  "Postfix (local-delivery queue ID)",
  (m, leaks) => { leaks.host = m[1]; },
  "medium");

// Sendmail mQ-style queue ID
P("sendmail-queue",
  /^<\d{9}\.[A-Z]{1,3}\d+@([A-Za-z0-9.\-]+)>$/,
  "Sendmail queue-id",
  (m, leaks) => { leaks.host = m[1]; },
  "medium");

// Sendmail fallback (generic generated form)
P("sendmail-fallback",
  /^<(\d{12,14})\.([A-Za-z0-9]+)@([A-Za-z0-9.\-]+)>$/,
  "Sendmail (generated fallback)",
  (m, leaks) => {
    leaks.timestamp = m[1]; leaks.queue_id = m[2]; leaks.hostname = m[3];
  },
  "medium");

// Exchange on-prem (runs LATE — otherwise 32-hex Roundcube IDs etc. get
// misclassified because the "20+ alphanumerics" prefix is very loose).
P("exchange-onprem",
  /^<[A-Za-z0-9]{20,}@([A-Za-z0-9\-]+)\.((?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+)>$/,
  "Microsoft Exchange (on-prem, likely)",
  (m, leaks, notes) => {
    const host = m[1], domain = m[2];
    // Exact-match or subdomain, not a suffix substring — "evilgmail.com"
    // would otherwise be treated the same as "gmail.com" and be skipped.
    const isPublic = (d, known) => d === known || d.endsWith("." + known);
    if (isPublic(domain, "outlook.com") || isPublic(domain, "gmail.com")) return false;
    const tld = domain.split(".").pop().toLowerCase();
    const looksExchange = /^[A-Z]{2,3}\d?PR\d+MB\d+$/i.test(host);
    if (!INTERNAL_TLDS.has(tld) && !looksExchange) return false;
    leaks.internal_hostname = host;
    leaks.internal_domain = domain;
    notes.push("Interner Hostname im Message-ID — klassischer On-prem-Exchange-Fingerprint.");
    return { confidence: INTERNAL_TLDS.has(tld) ? "medium" : "high" };
  });

// Forum / NNTP gateways — useful for mailing-list archive contexts
P("forum-nginx",
  /^<[a-f0-9]+@forum\.nginx\.org>$/,
  "forum.nginx.org (Nabble-based Forum→Mail-Bridge)");
P("ruby-forum",
  /^<[a-f0-9]+@ruby-forum\.com>$/,
  "ruby-forum.com (Forum→Mail-Bridge)");
P("nabble",
  /^<\d+\.post@[^>]*nabble\.com>$/,
  "Nabble Forum→Mail-Bridge");
P("gmane-nntp",
  /^<[^>]+@[a-z0-9]*\.?gmane\.org>$/,
  "Gmane (NNTP→Mail-Gateway)");


// ---- Main detection entry point -------------------------------------------

// Post-processing: if the matched pattern exposed a hostname/domain that is
// a single-word name or ends in an internal TLD, flag it explicitly.
function annotatePersonalHostnameLeak(leaks, notes) {
  const dom = leaks.hostname || leaks.domain || leaks.host ||
              leaks.internal_hostname || leaks.list_host || "";
  if (!dom) return;
  if (!dom.includes(".")) {
    leaks.personal_hostname_leak = dom;
    notes.push(`Single-Word-Hostname '${dom}' — wahrscheinlich geleakter Rechnername.`);
    return;
  }
  const tld = dom.toLowerCase().split(".").pop();
  if (INTERNAL_TLDS.has(tld)) {
    leaks.personal_hostname_leak = dom;
    notes.push(`Internal-TLD-Domain '${dom}' — wahrscheinlich geleakter interner Hostname.`);
  }
}

// Hard cap specific to Message-IDs: anything beyond this is either garbage
// or a ReDoS payload aimed at nested-quantifier patterns like exchange-onprem
// and b4-patch-series. Real Message-IDs top out around 200 bytes.
const MAX_MID_LEN = 1024;

function detectMessageId(headers) {
  let raw = ((headers["message-id"] || [""])[0] || "").trim();
  if (!raw) {
    return [finding("message_id", "missing", "",
                    CONF.LOW, { notes: ["keine Message-ID im Header"] })];
  }
  if (raw.length > MAX_MID_LEN) {
    return [finding("message_id", "oversized",
                    raw.slice(0, 64) + "…", CONF.LOW, {
      leaks: { length: raw.length },
      notes: [`Message-ID länger als ${MAX_MID_LEN} Zeichen — abgelehnt ` +
              "(keine legitime MID ist so lang; Schutz vor ReDoS-Payload)."]
    })];
  }

  for (const p of PATTERNS) {
    const m = raw.match(p.rx);
    if (!m) continue;
    const leaks = {};
    const notes = [];
    let result = null;
    if (p.handler) {
      try {
        result = p.handler(m, leaks, notes);
        if (result === false) continue;
      } catch (e) {
        const dl = globalThis.OSINTDebug && globalThis.OSINTDebug.dlog;
        if (dl) dl("warn", "mid", `handler "${p.name}" threw:`,
                   e && e.message || e);
        else console.warn("MID handler error", p.name, e);
      }
    }
    const confidence = (result && result.confidence) || p.confidence || CONF.HIGH;
    leaks.raw = raw;
    annotatePersonalHostnameLeak(leaks, notes);
    return [finding("message_id", "client_fingerprint", p.label,
                    confidence, { leaks, notes })];
  }

  // Unknown: compute structural signature for debugging / future-pattern work
  const midInner = raw.replace(/^</, "").replace(/>$/, "");
  const [localPart, ...rest] = midInner.split("@");
  const domain = rest.join("@");
  const sig = structuralSignature(localPart);
  return [finding("message_id", "client_fingerprint", "unknown",
                  CONF.LOW, {
    leaks: { raw, local: localPart, domain, signature: sig },
    notes: ["MID-Pattern nicht im Katalog — Struktur: " + sig]
  })];
}

globalThis.OSINTDetect = globalThis.OSINTDetect || {};
globalThis.OSINTDetect.messageId = detectMessageId;

})();
