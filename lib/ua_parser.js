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
  // Thunderbird family. Capture "Beta" / "Daily" / "Earlybird" channel
  // suffixes when present so they survive into the label as a version-
  // like marker (downstream heuristics + reporting see it as versionful).
  // Capture beta/RC suffix on the version (e.g. "Thunderbird/2.0b2",
  // "Thunderbird/3.1b2", "Thunderbird/3.0.3pre"). [\w.]+ keeps letters
  // and digits so the suffix survives.
  { rx: /\bThunderbird\/([\w.]+(?:\s*(?:Beta|Daily|Earlybird))?)/, family: "Mozilla Thunderbird" },
  { rx: /\bMozilla Thunderbird\s+([\w.]+(?:\s*(?:Beta|Daily|Earlybird))?)/, family: "Mozilla Thunderbird" },
  { rx: /\bMozilla Thunderbird\s+(Beta|Daily|Earlybird)\b/, family: "Mozilla Thunderbird" },
  { rx: /\bMozilla Thunderbird\b/, family: "Mozilla Thunderbird" },
  // "Thunderbird 1.5.0.7 (Windows/20060909)"-style — no Mozilla prefix,
  // no slash, but version follows after a space. Older self-reports.
  { rx: /\bThunderbird\s+([\w.]+(?:\s*(?:Beta|Daily|Earlybird))?)/, family: "Mozilla Thunderbird" },
  { rx: /\bThunderbird\s+(Beta|Daily|Earlybird)\b/, family: "Mozilla Thunderbird" },
  { rx: /\bThunderbird\b/, family: "Mozilla Thunderbird" },
  // "Shredder" is the upstream codename Mozilla uses for Thunderbird Beta
  // channel builds; it appears in real-world UAs ("... Shredder/3.0.3pre").
  { rx: /\bShredder\/([\w.]+)/, family: "Mozilla Thunderbird (Shredder beta)" },
  { rx: /\bSeaMonkey\/([\d.]+)/, family: "SeaMonkey" },
  { rx: /\bBetterbird\/([\d.]+)/, family: "Betterbird" },
  // Case-insensitive: real corpus has both "IceDove/" and "Icedove/" capitalisations.
  { rx: /\bIcedove\/([\d.]+)/i, family: "IceDove (Debian Thunderbird fork)" },
  // Postbox markets the desktop client as "PostboxApp/<ver>" in the UA.
  { rx: /\bPostbox(?:App)?\/([\d.]+)/, family: "Postbox" },
  // Lightning is the calendar add-on; it ALWAYS appears alongside a host
  // MUA (Thunderbird / Icedove / Shredder). Position this rule AFTER all
  // those so Lightning is only the chosen label when no host MUA matched —
  // otherwise we'd report "Lightning 1.0" for a clearly-Icedove mail.
  { rx: /\bLightning\/([\w.]+)/, family: "Mozilla Thunderbird (Lightning cal)" },

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

  // Mutt family — NeoMutt BEFORE Mutt (substring would otherwise swallow
  // it). Capture the optional parenthetical "1.7.1"-style version too
  // since real-world UAs read "NeoMutt/20180716 (1.7.1)" — we want the
  // semver, not just the date build.
  { rx: /\bNeoMutt\/([\d.a-z\-]+)\s*\(([\d.]+)\)/, family: "NeoMutt",
    verBuild: m => `${m[2]} (${m[1]})` },
  { rx: /\bNeoMutt\/([\d.a-z\-]+)/, family: "NeoMutt" },
  { rx: /\bMutt\/([\w.+\-]+)(?:\s*\(([^)]+)\))?/, family: "mutt" },

  // Claws / Sylpheed
  { rx: /Claws Mail ([\d.]+)/, family: "Claws Mail" },
  { rx: /Sylpheed\s+([\d.]+)/, family: "Sylpheed" },

  // Evolution. Distros (Debian, Ubuntu) tag their builds with suffixes
  // like "3.2.3-0ubuntu6", "3.12.9-1+b1" — capture them so the patch level
  // survives instead of getting silently truncated to the upstream version.
  { rx: /Evolution ([\d.]+(?:[\-+][\w.+]*)?)/, family: "GNOME Evolution" },

  // KMail / Kontact
  { rx: /KMail\/([\d.]+)/, family: "KDE KMail" },

  // Emacs mailers
  { rx: /Wanderlust\/([\d.]+)/, family: "Wanderlust" },
  { rx: /Mew(?: version)?\s*([\d.]*)/, family: "Mew" },
  // Gnus runs inside Emacs; UA reads "Gnus/<gnus> ... Emacs/<emacs>". Both
  // versions are useful (different release cadence). Combine into a single
  // version string so neither is silently dropped.
  { rx: /Gnus\/([\d.]+).*?Emacs\/([\d.]+)/, family: "Gnus/Emacs",
    verBuild: m => `Gnus ${m[1]} / Emacs ${m[2]}` },
  { rx: /mu4e\s+([\d.]+)/, family: "mu4e" },
  { rx: /VM(?:\s+|\/)([\d.]+)/, family: "VM / Emacs" },
  { rx: /MH-E\s+([\d.]+)/i, family: "MH-E / Emacs" },

  // Webmail / modern clients
  // Roundcube ships beta/RC builds with a "-beta", "-stable", "-rc" suffix
  // on the version. Capture the suffix.
  { rx: /Roundcube Webmail\/([\d.]+(?:-[\w.+]+)?)/, family: "Roundcube Webmail" },
  { rx: /SquirrelMail\s+([\d.]+)/, family: "SquirrelMail" },
  { rx: /SOGoMail\s+([\d.]+)/, family: "SOGo Mail" },
  { rx: /Open-Xchange Mailer v?([\d.]+(?:-[A-Za-z0-9]+)?)/, family: "Open-Xchange" },
  { rx: /Horde Application Framework ([\d.]+)/, family: "Horde" },
  { rx: /IMP[^\/]*\/h?(\d[\w.]*)/, family: "Horde/IMP", verGroup: 1 },
  // YahooMail UAs typically have BOTH a frontend version (RC/Classic/Basic)
  // and a backend WebService version, e.g.:
  //   "YahooMailRC/1277.43 YahooMailWebService/0.7.289.10"
  //   "YahooMailClassic/7.0.14 YahooMailWebService/0.7.347.3"
  //   "YahooMailClassic/6.0.19_56 YahooMailWebService/0.8.111_27"
  // Both are useful: RC is the user-facing app, WebService the backing API.
  // The "_NN" suffix is Yahoo's build counter — preserve it via [\w.]+.
  // Combine both versions via verBuild so neither is dropped.
  { rx: /YahooMail(?:RC|Classic|Basic)\/([\w.]+)\s+YahooMailWebService\/([\w.]+)/,
    family: "Yahoo Mail",
    verBuild: m => `${m[1]} (WebService ${m[2]})` },
  { rx: /YahooMailWebService\/([\w.]+)/, family: "Yahoo Mail" },
  { rx: /YahooMailNeo\b/, family: "Yahoo Mail Neo" },
  { rx: /YahooMail(?:Classic|Basic|RC)\/([\w.]+)/, family: "Yahoo Mail" },
  { rx: /YahooMail(?:Classic|Basic)\b/, family: "Yahoo Mail" },

  // CLI / automation
  { rx: /aerc\/([\d.]+)/, family: "aerc" },
  { rx: /alot\/([\d.]+)/, family: "alot" },
  { rx: /stgit(?:\s+|\/)([\d.]+)/, family: "StGit" },
  { rx: /git-send-email(?:\s+|\/)?([\d.]*)/, family: "git-send-email" },
  { rx: /^b4\s+([\d.]+)/, family: "b4 (kernel patch tool)" },
  { rx: /curl\/([\d.]+)/, family: "curl (scripted)" },
  { rx: /Heirloom mailx\s+([\d.]+)/, family: "Heirloom mailx" },
  { rx: /mailx /, family: "mailx (BSD heirloom)" },
  // PHPMailer is a separate library; its full version (e.g. "6.0.3") sits
  // *after* "PHP" in the UA string, so the generic /PHP\/?([\d.]*)/ below
  // would otherwise match "PHP" with an empty version and silently drop
  // "Mailer 6.0.3". Keep PHPMailer rule above the generic PHP rule.
  { rx: /\bPHPMailer\s+([\d.]+(?:[\-\.][A-Za-z0-9]+)?)/, family: "PHPMailer (PHP library)" },
  { rx: /PHP\/?([\d.]*)/, family: "PHP mail() (script)" },

  // Mobile / K-9 (must come BEFORE Apple Mail since some K-9 versions
  // include "Android Mail"-ish tokens)
  { rx: /K-9 Mail\/([\d.]+)/, family: "K-9 Mail (Android)" },
  { rx: /FairEmail\/([\d.]+)/, family: "FairEmail (Android)" },

  // Others
  { rx: /GyazMail-v([\d.]+)/, family: "GyazMail (macOS)" },
  { rx: /The Bat!\s*\(v?([\d.]+)\)/, family: "The Bat!" },
  { rx: /Forte Agent(?:\/|\s+)([\d.]+)/, family: "Forte Agent" },
  { rx: /Becky! Internet Mail(?: version)?\s*([\d.]+)/, family: "Becky! Internet Mail" },
  { rx: /Opera Mail\/([\d.]+)/, family: "Opera Mail" },
  { rx: /Pegasus Mail\/([\d.]+)/, family: "Pegasus Mail" },
  { rx: /Alpine\s+([\d.a-z]+)/, family: "Alpine" },
  { rx: /Pine ([\d.]+)/, family: "Pine" },
  // Coremail: real UAs read e.g. "Coremail Webmail Server Version 2023.4-cmXT
  // build 20250911 …", "Coremail Webmail Server Version XT5.0.10 build …",
  // or "Coremail Webmail Server Version SP_ntes V3.5 build …". Prefer the
  // dotted-semver V<digits>.<digits> when it's present; otherwise capture
  // whatever token comes right after "Version".
  { rx: /Coremail(?:[\w \t]*?Version)\s+\S+\s+(V[\d.]+)/, family: "Coremail",
    verBuild: m => m[1] },
  { rx: /Coremail(?:[\w \t]*?Version)\s+([\w.\-+]+)/, family: "Coremail" },
  { rx: /Coremail(?: Webmail)?\/?([\d.]*)/, family: "Coremail" },
  { rx: /AquaMail\/?([\d.]*)/, family: "AquaMail" },
  { rx: /BlackBerry([^\s;]+)/i, family: "BlackBerry" },

  // Exchange itself puts its version into X-MimeOLE sometimes
  { rx: /Produced By Microsoft Exchange V([\d.]+)/, family: "Microsoft Exchange (server-generated)" },

  // Fallback: very generic. Capture the rv:X.Y version so downstream
  // coverage isn't reported as "no version" — Mozilla rv: is the closest
  // thing to a meaningful version when no Thunderbird/Icedove/etc. token
  // is present in the UA.
  { rx: /Mozilla\/5\.0.*rv:([\d.]+).*Gecko/, family: "Gecko-based (Thunderbird?)",
    fallback: true },
];

function parseUA(rawUA) {
  if (!rawUA) return null;
  for (const rule of UA_RULES) {
    if (rule.fallback) continue;
    const m = rawUA.match(rule.rx);
    if (m) {
      // verBuild: callback gets the match array, returns the version
      //           string. Used for rules that join two capture groups
      //           (e.g. "20180716 (1.7.1)") or pick the first non-empty.
      // verGroup: legacy single-group index (default 1).
      let ver;
      if (typeof rule.verBuild === "function") {
        ver = rule.verBuild(m) || "";
      } else {
        ver = m[rule.verGroup || 1] || "";
      }
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
    const m = rawUA.match(rule.rx);
    if (m) {
      let ver;
      if (typeof rule.verBuild === "function") ver = rule.verBuild(m) || "";
      else                                     ver = m[rule.verGroup || 1] || "";
      return { family: rule.family, version: ver, raw: rawUA.substring(0, 200) };
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
