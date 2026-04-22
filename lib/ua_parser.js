/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// User-Agent / X-Mailer parser. Ported from tools/ua_parser.py.
// Returns {family, version, os?, variant?} or null.

"use strict";


(() => {
const { getHeader, finding, CONF } = globalThis.OSINTUtil;

// Order matters: more specific patterns first.
const UA_RULES = [
  // Thunderbird family
  { rx: /\bThunderbird\/([\d.]+)/, family: "Mozilla Thunderbird" },
  { rx: /\bMozilla Thunderbird\s+([\d.]+)/, family: "Mozilla Thunderbird" },
  { rx: /\bMozilla Thunderbird\b/, family: "Mozilla Thunderbird" },
  { rx: /\bLightning\/([\d.]+)/, family: "Mozilla Thunderbird (Lightning cal)" },
  { rx: /\bSeaMonkey\/([\d.]+)/, family: "SeaMonkey" },
  { rx: /\bBetterbird\/([\d.]+)/, family: "Betterbird" },
  { rx: /\bIceDove\/([\d.]+)/, family: "IceDove (Debian Thunderbird fork)" },
  { rx: /\bPostbox\/([\d.]+)/, family: "Postbox" },

  // Apple Mail via X-Mailer
  { rx: /Apple Mail \(([\d.]+)\)/, family: "Apple Mail", verGroup: 1 },
  { rx: /iPhone Mail \(([\w\d]+)\)/, family: "iPhone Mail", verGroup: 1 },
  { rx: /iPad Mail \(([\w\d]+)\)/, family: "iPad Mail", verGroup: 1 },

  // Outlook / Office
  { rx: /Microsoft Outlook Express ([\d.]+)/, family: "Outlook Express" },
  { rx: /Microsoft(?: Office)? Outlook ([\d.]+)/, family: "Microsoft Outlook" },
  { rx: /Microsoft Outlook, Build ([\d.]+)/, family: "Microsoft Outlook (Desktop)" },
  { rx: /Microsoft Outlook (16|15|14)\.[\d.]+/, family: "Microsoft Outlook", verGroup: 1 },
  { rx: /Microsoft-MacOutlook\/([\d.]+)/, family: "Outlook for Mac" },

  // Mutt family — NeoMutt BEFORE Mutt (substring would otherwise swallow it).
  { rx: /\bNeoMutt\/([\d.a-z\-]+)/, family: "NeoMutt" },
  { rx: /\bMutt\/([\w.+\-]+)(?:\s*\(([^)]+)\))?/, family: "mutt" },

  // Claws / Sylpheed
  { rx: /Claws Mail ([\d.]+)/, family: "Claws Mail" },
  { rx: /Sylpheed\s+([\d.]+)/, family: "Sylpheed" },

  // Evolution
  { rx: /Evolution ([\d.]+)/, family: "GNOME Evolution" },

  // KMail / Kontact
  { rx: /KMail\/([\d.]+)/, family: "KDE KMail" },

  // Webmail / modern clients
  { rx: /Roundcube Webmail\/([\d.]+)/, family: "Roundcube Webmail" },
  { rx: /SquirrelMail\s+([\d.]+)/, family: "SquirrelMail" },
  { rx: /SOGoMail\s+([\d.]+)/, family: "SOGo Mail" },
  { rx: /Horde Application Framework ([\d.]+)/, family: "Horde" },
  { rx: /IMP[^\/]*\/h?(\d[\w.]*)/, family: "Horde/IMP", verGroup: 1 },

  // CLI / automation
  { rx: /git-send-email([\d.]*)/, family: "git-send-email" },
  { rx: /^b4\s+([\d.]+)/, family: "b4 (kernel patch tool)" },
  { rx: /curl\/([\d.]+)/, family: "curl (scripted)" },
  { rx: /mailx /, family: "mailx (BSD heirloom)" },
  { rx: /PHP\/?([\d.]*)/, family: "PHP mail() (script)" },

  // Mobile / K-9 (must come BEFORE Apple Mail since some K-9 versions
  // include "Android Mail"-ish tokens)
  { rx: /K-9 Mail\/([\d.]+)/, family: "K-9 Mail (Android)" },
  { rx: /FairEmail\/([\d.]+)/, family: "FairEmail (Android)" },

  // Others
  { rx: /GyazMail-v([\d.]+)/, family: "GyazMail (macOS)" },
  { rx: /The Bat!\s*\(v?([\d.]+)\)/, family: "The Bat!" },
  { rx: /Pegasus Mail\/([\d.]+)/, family: "Pegasus Mail" },
  { rx: /Alpine\s+([\d.a-z]+)/, family: "Alpine" },
  { rx: /Pine ([\d.]+)/, family: "Pine" },
  { rx: /BlackBerry([^\s;]+)/i, family: "BlackBerry" },

  // Exchange itself puts its version into X-MimeOLE sometimes
  { rx: /Produced By Microsoft Exchange V([\d.]+)/, family: "Microsoft Exchange (server-generated)" },

  // Fallback: very generic
  { rx: /Mozilla\/5\.0.*rv:[\d.]+.*Gecko/, family: "Gecko-based (Thunderbird?)",
    fallback: true },
];

function parseUA(rawUA) {
  if (!rawUA) return null;
  for (const rule of UA_RULES) {
    if (rule.fallback) continue;
    const m = rawUA.match(rule.rx);
    if (m) {
      const ver = m[rule.verGroup || 1] || "";
      return {
        family: rule.family,
        version: ver,
        raw: rawUA.substring(0, 200),
      };
    }
  }
  // Try fallbacks
  for (const rule of UA_RULES) {
    if (!rule.fallback) continue;
    if (rule.rx.test(rawUA)) {
      return { family: rule.family, version: "", raw: rawUA.substring(0, 200) };
    }
  }
  return null;
}

// MIME-Version often carries a parenthetical MUA hint on Apple / some
// legacy clients, e.g.:
//   "MIME-Version: 1.0 (Apple Message framework v1085)"
// The version after "v" or "framework" is the Mail.app build number —
// same value that Apple also puts in User-Agent as "Apple Mail (2.1085)".
function parseMimeVersion(headers) {
  const raw = getHeader(headers, "MIME-Version");
  if (!raw) return null;
  const m = raw.match(/\(([^)]+)\)/);
  if (!m) return null;
  const inside = m[1];
  const appleM = inside.match(/Apple Message framework v([\d.]+)/i);
  if (appleM) {
    return { family: "Apple Mail (framework)", version: appleM[1], raw: inside };
  }
  // Unknown parenthetical — surface the raw string so unknown clients
  // can still contribute a weak MUA hint for the Message-ID aggregator.
  return { family: inside.trim().slice(0, 60), version: "", raw: inside };
}

function detectUserAgent(headers) {
  const out = [];
  const ua = getHeader(headers, "User-Agent")
          || getHeader(headers, "X-Mailer")
          || getHeader(headers, "X-MimeOLE")
          || getHeader(headers, "X-Newsreader");
  if (ua) {
    const parsed = parseUA(ua);
    if (!parsed) {
      out.push(finding("user_agent", "unparsed_selfreport", ua.substring(0, 120),
                       CONF.MEDIUM, {
        leaks: { raw: ua.substring(0, 200) },
        notes: ["UA/X-Mailer string recognised but no pattern matched."]
      }));
    } else {
      out.push(finding("user_agent", "client_selfreport",
                       parsed.family + (parsed.version ? " " + parsed.version : ""),
                       CONF.HIGH, {
        leaks: { family: parsed.family, version: parsed.version, raw: parsed.raw },
      }));
    }
  }

  // Secondary MUA hint from MIME-Version parenthetical.
  const mv = parseMimeVersion(headers);
  if (mv) {
    out.push(finding("user_agent", "mime_version_hint",
                     mv.family + (mv.version ? " " + mv.version : ""),
                     CONF.MEDIUM, {
      leaks: { family: mv.family, version: mv.version, raw: mv.raw,
               src: "MIME-Version parenthetical" },
    }));
  }

  return out;
}

globalThis.OSINTDetect = globalThis.OSINTDetect || {};
globalThis.OSINTDetect.userAgent = detectUserAgent;
globalThis.OSINTDetect._parseUA = parseUA;   // exposed for body-signature cross-check

})();
