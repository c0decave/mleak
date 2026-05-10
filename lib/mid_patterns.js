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

const { getHeader, structuralSignature, finding, CONF,
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
  /^<([A-Z0-9]+)@([A-Z0-9]+)\.([A-Z0-9]+)\.prod\.outlook\.com>$/i,
  "Microsoft Exchange Online / M365",
  (m, leaks, notes) => {
    const local = m[1], host = m[2], pod = m[3];
    const dc = host.match(/^([A-Z]{2,5}\d?)(?:PR|P)\d+(MB|CA|PU|HE|OLK)\d+/i);
    if (dc) {
      const code = dc[1].toUpperCase();
      leaks.datacenter_code = code;
      const dcLookup = code.replace(/\d+$/, "");
      leaks.datacenter_hint =
        M365_DC_CODES[code] || M365_DC_CODES[dcLookup] || "unknown";
      leaks.server_role = {
        MB: "Mailbox", CA: "ClientAccess", PU: "PublicFolder", OLK: "Outlook"
      }[dc[2].toUpperCase()] || dc[2];
    }
    if (local.toUpperCase().startsWith(host.toUpperCase())) {
      leaks.message_token = local.slice(host.length);
    }
    leaks.tenant_pod = pod;
    leaks.mailbox_host = host;
  });

P("exchange-corporate-hex",
  /^<([0-9A-F]{38,42})@(?![A-Za-z0-9._-]*(?:gmail|googlemail|outlook)\.com>)([A-Za-z0-9._-]*(?:EXCH(?:ANGE)?|VEXCH|XCH|MBX|MAIL|MSG|CORP|USRV|USEA)[A-Za-z0-9._-]*)>$/i,
  "Microsoft Exchange / corporate MTA (hex Message-ID)",
  (m, leaks) => {
    const host = m[2].toLowerCase();
    if (host.endsWith("gmail.com") || host.endsWith("googlemail.com") ||
        host.endsWith("outlook.com")) return false;
    leaks.opaque_hex_id = m[1];
    leaks.mail_host = m[2];
  },
  "medium");

// Gmail Web (modern CA*- prefix)
P("gmail-web-modern",
  /^<(CA[A-Z]*)[\-+=_][A-Za-z0-9+\/=_\-]+@mail\.gmail\.com>$/,
  "Gmail Web (modern)");

// Gmail Web (legacy pre-2015)
P("gmail-web-legacy",
  /^<[A-Z0-9]+-[A-Z0-9]+-[A-Z0-9]+@mail\.gmail\.com>$/i,
  "Gmail Web (legacy)");

// Mozilla / Thunderbird classic hex-timestamp format. This must run before
// the broad @gmail.com fallback because real Thunderbird replies often use a
// gmail.com domain in the id-right.
P("mozilla-classic",
  /^<([0-9A-F]{8})\.([0-9A-F]{3,8})@([A-Za-z0-9.\-]+)>$/,
  "Mozilla/Thunderbird (classic hex timestamp)",
  (m, leaks) => {
    leaks.hex_timestamp = m[1];
    leaks.random_or_pid = m[2];
    leaks.hostname = m[3];
  },
  "medium");

P("thunderbird-announce",
  /^<announce\.([0-9A-Fa-f]{8})\.([0-9A-Fa-f]{7})@([A-Za-z0-9.\-]+)>$/,
  "Thunderbird announce-style Message-ID",
  (m, leaks) => {
    leaks.hex_timestamp = m[1];
    leaks.random_or_pid = m[2];
    leaks.hostname = m[3];
  });

P("aerc",
  /^<([A-Z0-9]{12})\.([A-Z0-9]{13})@([A-Za-z0-9.\-]+)>$/,
  "aerc",
  (m, leaks) => {
    leaks.token1 = m[1]; leaks.token2 = m[2]; leaks.hostname = m[3];
  },
  "medium");

P("notmuch-generated",
  /^<([0-9a-f]{11,13})_([0-9a-f]{9,18})@([A-Za-z0-9.\-]+\.notmuch)>$/,
  "notmuch generated Message-ID",
  (m, leaks) => {
    leaks.timestamp_or_counter = m[1];
    leaks.token = m[2];
    leaks.hostname = m[3];
  },
  "medium");

P("coremail",
  /^<([0-9a-f]{8})\.([0-9a-f]{4})\.([0-9a-f]{11})\.Coremail\.([^@]+)@([A-Za-z0-9.\-]+)>$/,
  "Coremail",
  (m, leaks) => {
    leaks.token1 = m[1]; leaks.token2 = m[2]; leaks.token3 = m[3];
    leaks.user = m[4]; leaks.hostname = m[5];
  });

P("claws-sylpheed",
  /^<((?:19|20)\d{12})\.([0-9a-f]{8})\.([A-Za-z0-9._+\-]+)@([A-Za-z0-9.\-]+)>$/,
  "Claws Mail / Sylpheed",
  (m, leaks) => {
    leaks.timestamp = m[1];
    leaks.hex_token = m[2];
    leaks.user = m[3];
    leaks.hostname = m[4];
  },
  "medium");

P("open-xchange",
  /^<(\d{9,10})\.(\d{6,7})\.(\d{13})@([A-Za-z0-9.\-]+)>$/,
  "Open-Xchange / hosted webmail",
  (m, leaks) => {
    leaks.id1 = m[1]; leaks.id2 = m[2];
    leaks.timestamp_ms = m[3]; leaks.hostname = m[4];
  },
  "medium");

P("aquamail",
  /^<([0-9a-f]{11})\.([0-9A-F]{4})\.([0-9a-f]{32})@([A-Za-z0-9.\-]+)>$/,
  "AquaMail",
  (m, leaks) => {
    leaks.timestamp_or_counter = m[1]; leaks.code = m[2];
    leaks.device_or_account_hash = m[3]; leaks.hostname = m[4];
  },
  "medium");

P("apache-jenkins",
  /^<(\d{9,10})\.(\d{3,5})\.(\d{13})@((?:jenkins|ci-builds)[A-Za-z0-9.-]*\.apache\.org)>$/,
  "Apache Jenkins / CI notification",
  (m, leaks) => {
    leaks.id1 = m[1]; leaks.build_or_pid = m[2];
    leaks.timestamp_ms = m[3]; leaks.hostname = m[4];
  });

P("becky-internet-mail",
  /^<(?:[A-Za-z0-9_]+\.)?(\d{14})\.([0-9A-F]{4})\.([0-9A-F]{8}|[A-Z]{13})@([A-Za-z0-9.\-]+)>$/,
  "Becky! Internet Mail",
  (m, leaks) => {
    leaks.timestamp = m[1];
    leaks.token1 = m[2];
    leaks.token2 = m[3];
    leaks.hostname = m[4];
  },
  "medium");

// Gmail via SMTP / mobile
P("gmail-smtp",
  /^<(?![0-9A-Za-z]{8,14}(?:\.[0-9A-Za-z])?\.fsf(?:[-_+][^@]*)?@)[A-Za-z0-9._\-]+@gmail\.com>$/,
  "Gmail SMTP / mobile / generic",
  null, "medium");

// Google Groups
P("google-groups",
  /^<[A-Za-z0-9._\-]+@googlegroups\.com>$/,
  "Google Groups Mailing List");

P("tencent-qqmail",
  /^<tencent_([0-9A-F]{36})@qq\.com>$/,
  "Tencent QQ Mail",
  (m, leaks) => { leaks.opaque_id = m[1]; });

// Google backend-generated notifications (observed in public kernel archives)
P("google-generated",
  /^<([0-9a-f]{28})@google\.com>$/,
  "Google generated backend ID",
  (m, leaks) => { leaks.opaque_id = m[1]; },
  "medium");

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

P("mutt-send-email",
  /^<(\d{14})-mutt-send-email-([^@]+)@([A-Za-z0-9.\-]+)>$/,
  "mutt send-email wrapper",
  (m, leaks) => {
    leaks.timestamp = m[1]; leaks.user = m[2]; leaks.hostname = m[3];
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

P("vmime",
  /^<vmime\.([0-9a-f]{8})\.([0-9a-f]{4})\.([0-9a-f]{16})@([A-Za-z0-9.\-]+)>$/,
  "VMime library/client",
  (m, leaks) => {
    leaks.token1 = m[1]; leaks.token2 = m[2];
    leaks.token3 = m[3]; leaks.hostname = m[4];
  });

P("opera-mail",
  /^<op\.([0-9A-Za-z]{14})(?:\.([a-z]{5}))?@([A-Za-z0-9.\-]+)>$/,
  "Opera Mail",
  (m, leaks) => {
    leaks.token = m[1];
    if (m[2]) leaks.suffix = m[2];
    leaks.hostname = m[3];
  },
  "medium");

// KMail
P("kmail",
  /^<\d{12,14}\.\d+\.[A-Za-z0-9_-]+@([A-Za-z0-9.\-]+)>$/,
  "KDE KMail",
  (m, leaks) => { leaks.hostname = m[1]; },
  "medium");

P("kmail-qt-random",
  /^<(\d{7,8})\.(?=[A-Za-z0-9]{10}@)(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{10}@([A-Za-z0-9.\-]+)>$/,
  "KMail (KDE/Qt random Message-ID)",
  (m, leaks) => {
    leaks.numeric_prefix = m[1];
    leaks.hostname = m[2];
  },
  "medium");

// Emacs mailers
P("gnus-fsf",
  /^<([0-9A-Za-z]{8,14})(?:\.([0-9A-Za-z]))?\.fsf((?:[-_+][^@]*)?)@([A-Za-z0-9.\-]+)>$/,
  "Gnus / Emacs (fsf Message-ID)",
  (m, leaks) => {
    leaks.token = m[1];
    if (m[2]) leaks.subtoken = m[2];
    if (m[3]) leaks.fsf_suffix = m[3];
    leaks.hostname = m[4];
  });

P("wanderlust",
  /^<([0-9A-Za-z]{10,12})\.wl[-%]([^@]+)@([A-Za-z0-9.\-]+)>$/,
  "Wanderlust / Emacs",
  (m, leaks) => {
    leaks.token = m[1]; leaks.wl_identity = m[2]; leaks.hostname = m[3];
  });

P("mew",
  /^<((?:19|20)\d{6})\.(\d{6})\.(\d{7,20})\.([^@]+)@([A-Za-z0-9.\-]+)>$/,
  "Mew / Emacs",
  (m, leaks) => {
    leaks.date = m[1]; leaks.time = m[2]; leaks.nonce = m[3];
    leaks.user = m[4]; leaks.hostname = m[5];
  },
  "medium");

P("vm-emacs",
  /^<(\d{5})\.(\d{4,5})\.(\d{5,6})\.(\d{5,6})@([A-Za-z0-9.\-]+)>$/,
  "VM / Emacs",
  (m, leaks) => {
    leaks.vm_field_1 = m[1]; leaks.vm_field_2 = m[2];
    leaks.vm_field_3 = m[3]; leaks.vm_field_4 = m[4];
    leaks.hostname = m[5];
  },
  "medium");

P("mh-e",
  /^<(\d{5,6})\.(\d{10})@([A-Za-z0-9.\-]+)>$/,
  "MH-E / Emacs",
  (m, leaks) => {
    leaks.field1 = m[1]; leaks.field2 = m[2]; leaks.hostname = m[3];
  },
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

P("b4-thanks",
  /^<(\d{12})\.(\d{6,7})\.(\d{18,20})\.b4-([a-z]{2})@([A-Za-z0-9.\-]+)>$/,
  "b4 (thanks / notification)",
  (m, leaks) => {
    leaks.timestamp_ms_or_epoch = m[1]; leaks.pid_or_counter = m[2];
    leaks.nonce = m[3]; leaks.suffix = m[4]; leaks.hostname = m[5];
  });

// git format-patch / send-email hash+epoch variant
P("git-format-patch-hash",
  /^<((?:[0-9a-f]{40})|cover)\.(\d{10})\.git\.([^@]+)@([A-Za-z0-9.\-]+)>$/,
  "git format-patch / send-email (hash+epoch variant)",
  (m, leaks, notes) => {
    leaks.patch_id_or_cover = m[1]; leaks.unix_epoch = m[2];
    leaks.author_token = m[3]; leaks.hostname = m[4];
    notes.push("Leakt git-generierten Patch-Token, Epoch und Author-Token.");
  });

P("git-series",
  /^<([0-9a-f]{40})\.(\d{10})\.git-series\.([^@]+)@([A-Za-z0-9.\-]+)>$/,
  "git-series patch tool",
  (m, leaks, notes) => {
    leaks.patch_id = m[1]; leaks.unix_epoch = m[2];
    leaks.author_token = m[3]; leaks.hostname = m[4];
    notes.push("Leakt git-series Patch-Hash, Epoch und Author-Token.");
  });

P("stgit-generated",
  /^<(\d{12,15})\.(\d{3,7})\.(\d{4,20})\.stgit@([A-Za-z0-9.\-]+)>$/,
  "StGit generated patch mail",
  (m, leaks, notes) => {
    leaks.timestamp_or_epoch = m[1]; leaks.pid_or_counter = m[2];
    leaks.nonce = m[3]; leaks.hostname = m[4];
    notes.push("StGit Message-ID leakt zeitartigen Wert, Prozess/Counter, Nonce und Host.");
  });

P("gerrit-changeid-patch",
  /^<(\d{14})\.v(\d+)\.(\d+)\.(I[0-9a-f]{40})@changeid>$/,
  "Gerrit Change-Id / git-send-email patch",
  (m, leaks) => {
    leaks.timestamp = m[1]; leaks.version = m[2];
    leaks.patch_index = m[3]; leaks.change_id = m[4];
  });

P("intel-lkp",
  /^<(?:[0-9A-Fa-f]{8}|\d{12,14})\.[A-Za-z0-9+\/]{5,16}[-%]lkp@intel\.com>$/,
  "Intel kernel test robot / LKP",
  (m, leaks, notes) => {
    notes.push("LKP-Marker im Message-ID-Local-Part identifiziert Intels Kernel-Test-Robotik.");
  });

P("kernel-patchwork-bot",
  /^<(\d{12})\.(\d{4,7})\.(\d{18,20})\.(git-patchwork-notify|pr-tracker-bot)@kernel\.org>$/,
  "kernel.org Patchwork / PR tracker bot",
  (m, leaks) => {
    leaks.timestamp_ms_or_epoch = m[1]; leaks.pid = m[2];
    leaks.nonce = m[3]; leaks.bot = m[4];
  });

P("nullmailer",
  /^<(\d{10})\.(\d{6})\.(\d{7})\.nullmailer@([A-Za-z0-9.\-]+)>$/,
  "nullmailer",
  (m, leaks) => {
    leaks.unix_epoch = m[1]; leaks.pid_or_counter = m[2];
    leaks.queue_id = m[3]; leaks.hostname = m[4];
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
P("yahoo-mail-neo",
  /^<(\d{10})\.(\d{5})\.YahooMailNeo@(web\d+\.(?:biz\.)?mail\.[A-Za-z0-9.\-]+\.yahoo\.com)>$/,
  "Yahoo Mail Neo",
  (m, leaks) => {
    leaks.unix_epoch_or_timestamp = m[1];
    leaks.counter = m[2];
    leaks.mail_host = m[3];
  });

P("yahoo-mail-classic-basic",
  /^<(\d{10})\.(\d{5})\.(YahooMailClassic|YahooMailBasic)@(web\d+\.(?:biz\.)?mail\.[A-Za-z0-9.\-]+\.yahoo\.com)>$/,
  "Yahoo Mail Classic/Basic",
  (m, leaks) => {
    leaks.unix_epoch_or_timestamp = m[1];
    leaks.counter = m[2];
    leaks.variant = m[3];
    leaks.mail_host = m[4];
  });

P("yahoo-mail",
  /^<(?:\d+\.\d+\.\d+\.(?:JavaMail\.)?[A-Za-z0-9_]+@(mail|web)\d*\.[a-z]+\.yahoo\.com|\d+\.\d+\.qm@web\d+\.mail\.[A-Za-z0-9.]+\.yahoo\.com)>$/i,
  "Yahoo Mail");
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

P("outlook-express-msimn",
  /^<([A-Z]{28})\.([^@]+)@([A-Za-z0-9.\-]+)>$/,
  "Outlook Express / Microsoft Internet Mail",
  (m, leaks) => {
    leaks.opaque_token = m[1];
    leaks.account_or_user = m[2];
    leaks.hostname = m[3];
  },
  "medium");

P("outlook-internet-account",
  /^<([0-9a-f]{12})\$([0-9a-f]{8})\$([0-9a-f]{8})\$?@([^>]+)>$/,
  "Microsoft Outlook / Windows Mail (Internet Account)",
  (m, leaks) => {
    leaks.timestamp_or_counter = m[1]; leaks.token1 = m[2];
    leaks.token2 = m[3]; leaks.hostname = m[4];
  },
  "medium");

P("outlook-32hex-localhost",
  /^<([0-9A-F]{32})@([^>.]+|[^>]*\.(?:local|lan|home|localdomain))>$/,
  "Microsoft Outlook / Windows Mail (32-hex local hostname)",
  (m, leaks) => {
    leaks.opaque_hex_id = m[1];
    leaks.hostname = m[2];
  },
  "medium");

P("hotmail-phx",
  /^<([A-Z]{3}\d{2,3})-(W|F|DS|DAV|OE)([A-Z0-9]+)@phx\.gbl>$/i,
  "Windows Live Hotmail / MSN (phx.gbl)",
  (m, leaks) => {
    leaks.cluster = m[1]; leaks.message_kind = m[2]; leaks.message_token = m[3];
  });

P("hotmail-phx-smtp",
  /^<([A-Z]{3}\d?)-SMTP([A-Z0-9]{28,34})@phx\.gbl>$/i,
  "Windows Live Hotmail / MSN SMTP (phx.gbl)",
  (m, leaks) => {
    leaks.cluster = m[1]; leaks.message_token = m[2];
  });

P("hotmail-legacy-web",
  /^<(?:(?:[A-Za-z]{3}\d{1,3})-(?:F|DAV|OE)[A-Za-z0-9]+|(?:OE|F)\d+[A-Za-z0-9]+)@hotmail\.com>$/i,
  "Hotmail / MSN legacy webmail");

P("forte-agent-4ax",
  /^<[a-z0-9]{32,36}@4ax\.com>$/i,
  "Forte Agent / 4ax.com Message-ID",
  null,
  "high");

P("aol-webmail",
  /^<([0-9A-F]{15})-([0-9A-F]{2,4})-([0-9A-F]{4,5})@([A-Za-z0-9.-]*webmail-[dm]\d+\.sysops\.aol\.com)>$/i,
  "AOL webmail",
  (m, leaks) => {
    leaks.message_token = m[1]; leaks.shard = m[2];
    leaks.counter = m[3]; leaks.mail_host = m[4];
  });

P("pan-newsreader",
  /^<pan\.(\d{4})\.(\d{2})\.(\d{2})\.(\d{2})\.(\d{2})\.(\d{2})\.(\d{5,6})@([^>]+)>$/,
  "Pan newsreader",
  (m, leaks) => {
    leaks.timestamp = `${m[1]}-${m[2]}-${m[3]} ${m[4]}:${m[5]}:${m[6]}`;
    leaks.microsecond_or_counter = m[7]; leaks.hostname = m[8];
  });

P("cox-webmail-imail",
  /^<(\d{14})\.([A-Z0-9]{5})\.(\d{4,7})\.(imail|root)@([A-Za-z0-9-]*rmwml\d{2,3})>$/i,
  "Cox WebMail / IMail",
  (m, leaks) => {
    leaks.timestamp = m[1]; leaks.queue_token = m[2];
    leaks.counter = m[3]; leaks.process_user = m[4]; leaks.mail_host = m[5];
  });

P("cox-webtop",
  /^<([0-9a-f]{6,8})\.([0-9a-f]{3,8})\.([0-9a-f]{11})\.Webtop\.([0-9A-F])@cox\.net>$/i,
  "Cox Webtop webmail",
  (m, leaks) => {
    leaks.token1 = m[1]; leaks.token2 = m[2];
    leaks.token3 = m[3]; leaks.shard = m[4];
  });

// Tracker / issue-system notifications
P("atlassian-jira",
  /^<JIRA\.(\d+)\.(\d{13})\.(\d+)\.(\d{13})@(Atlassian\.JIRA|arcas)>$/,
  "Atlassian JIRA notification",
  (m, leaks) => {
    leaks.issue_id = m[1]; leaks.created_ms = m[2];
    leaks.event_id = m[3]; leaks.event_ms = m[4];
    leaks.jira_host = m[5];
  });

P("launchpad-malone",
  /^<(\d{12,15})\.(\d{3,7})\.(\d{4,20})\.(malone|malonedeb|launchpad)@([A-Za-z0-9.\-]+)>$/,
  "Launchpad / Malone notification",
  (m, leaks, notes) => {
    const host = m[5];
    leaks.timestamp_or_epoch = m[1]; leaks.pid_or_counter = m[2];
    leaks.nonce = m[3]; leaks.tool = m[4]; leaks.hostname = host;
    notes.push("Message-ID wurde von Launchpad/Malone erzeugt, nicht von einer menschlichen MUA.");
    if (host.endsWith(".canonical.com") || host.endsWith(".ubuntu.com") ||
        host.includes("launchpad") || host.endsWith(".lp.internal")) {
      return { confidence: "high" };
    }
    return { confidence: "medium" };
  },
  "medium");

P("kernel-bugzilla",
  /^<bug-(\d+)-(\d+)(?:-([A-Za-z0-9]{10}))?@https\.bugzilla\.kernel\.org\/>$/,
  "Kernel Bugzilla notification",
  (m, leaks, notes) => {
    leaks.bug_id = m[1]; leaks.recipient_or_user_id = m[2];
    if (m[3]) leaks.notification_token = m[3];
    notes.push("Message-ID wurde von bugzilla.kernel.org erzeugt, nicht von einer menschlichen MUA.");
  });

P("kernel-bugspray",
  /^<(\d{8})-b(\d+)-([0-9a-f]{12})@bugzilla\.kernel\.org>$/,
  "Kernel Bugzilla / bugspray notification",
  (m, leaks) => {
    leaks.date = m[1]; leaks.bug_id = m[2]; leaks.hash12 = m[3];
  });

P("apache-bugzilla",
  /^<bug-(\d+)-(\d+)(?:-([A-Za-z0-9]{10}))?@https?\.(?:bz|issues)\.apache\.org\/bugzilla\/>$/,
  "Apache Bugzilla notification",
  (m, leaks) => {
    leaks.bug_id = m[1]; leaks.recipient_or_user_id = m[2];
    if (m[3]) leaks.notification_token = m[3];
  });

P("freedesktop-bugzilla",
  /^<bug-(\d+)-(\d+)(?:-([A-Za-z0-9]{10}))?@http\.bugs\.freedesktop\.org\/>$/,
  "freedesktop.org Bugzilla notification",
  (m, leaks, notes) => {
    leaks.bug_id = m[1]; leaks.recipient_or_user_id = m[2];
    if (m[3]) leaks.notification_token = m[3];
    notes.push("Message-ID wurde von freedesktop.org Bugzilla erzeugt, nicht von einer menschlichen MUA.");
  });

P("apache-git-pr",
  /^<git-pr-(\d+)-([a-z0-9-]+)@git\.apache\.org>$/,
  "Apache git PR bridge",
  (m, leaks) => {
    leaks.pr_number = m[1]; leaks.project = m[2];
  });

P("apache-gitbox-pr",
  /^<((?:PR|I)_kw[A-Za-z0-9_-]+)(?:-([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))?@gitbox\.apache\.org>$/,
  "Apache GitBox / GitHub PR bridge",
  (m, leaks) => {
    leaks.github_node_id = m[1];
    if (m[2]) leaks.event_uuid = m[2];
  });

P("apache-gitbox-generated",
  /^<(\d{12})\.(\d{4,5})\.(\d{18,20})\.(asfpy|gitbox)@gitbox\.apache\.org>$/,
  "Apache GitBox generated notification",
  (m, leaks) => {
    leaks.timestamp_ms_or_epoch = m[1]; leaks.pid_or_counter = m[2];
    leaks.nonce = m[3]; leaks.tool = m[4];
  });

P("apache-gitbox-project",
  /^<([a-z0-9-]+)\.(\d+)\.([A-Za-z0-9_-]+)\.gitbox@gitbox\.apache\.org>$/,
  "Apache GitBox project PR bridge",
  (m, leaks) => {
    leaks.project = m[1]; leaks.pr_number = m[2]; leaks.github_node_id = m[3];
  });

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
  /^<mailman\.(\d+)\.(\d{10})\.(\d+)\.([A-Za-z0-9._+-]+)@([A-Za-z0-9.\-]+)>$/,
  "Mailman (MLM-generated)",
  (m, leaks) => {
    leaks.sequence = m[1]; leaks.unix_epoch = m[2];
    leaks.pid_or_counter = m[3]; leaks.list_name = m[4];
    leaks.list_host = m[5];
  });

P("groups-io-yocto",
  /^<((?:MADEUP\.)?[A-Za-z0-9]{3,6}\.\d{16,19}(?:\.[A-Za-z0-9]{4})?|MADEUP\.[0-9A-F]{16}\.\d{3,6})@lists\.yoctoproject\.org>$/,
  "groups.io generated list/web Message-ID",
  (m, leaks) => {
    leaks.groups_io_token = m[1];
    leaks.list_host = "lists.yoctoproject.org";
  },
  "medium");

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
  /^<(?:\d+|\d{12,13}-\d+)\.post@[^>]*nabble\.com>$/,
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
  let raw = getHeader(headers, "Message-ID").trim();
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
