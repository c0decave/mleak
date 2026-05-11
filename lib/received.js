/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Received-Chain-Analyse: Hops zählen, interne Hostnames / private IPs leaken,
// Chronologie-Anomalien erkennen. Ported from det_received + integrity.

"use strict";


(() => {
const { getAllHeader, finding, CONF, INTERNAL_TLDS, isPrivateIP,
        looksInternalDomain } = globalThis.OSINTUtil;
const MAX_RELAY_VALUES = 64;
const MAX_RELAY_FIELD = 240;

function shortValue(value, max = MAX_RELAY_FIELD) {
  const s = String(value == null ? "" : value);
  return s.length > max ? s.slice(0, max) + "...[truncated]" : s;
}

function normalizeIpLiteral(value) {
  const literal = String(value || "").trim().replace(/^IPv6:/i, "").slice(0, 120);
  const zone = literal.indexOf("%");
  const bare = zone >= 0 ? literal.slice(0, zone) : literal;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(bare)) return literal;
  return bare.includes(":") && /^[0-9A-Fa-f:.]+$/.test(bare) ? literal : "";
}

function bracketIpLiteral(value) {
  const m = String(value || "").match(/^\[(?:IPv6:)?([0-9A-Za-z:.%_\-]+)\]$/i);
  return m ? normalizeIpLiteral(m[1]) : "";
}

function parentheticalIpLiteral(value) {
  const m = String(value || "").match(/\[(?:IPv6:)?([0-9A-Za-z:.%_\-]+)\]/i);
  return m ? normalizeIpLiteral(m[1]) : "";
}

function looksLikeIpLiteralHost(value) {
  const raw = String(value || "").trim();
  if (bracketIpLiteral(raw)) return true;
  const host = raw.replace(/[<>]/g, "");
  return Boolean(normalizeIpLiteral(host));
}

// Parse one Received header into {from_host, from_ip, by_host, id, proto,
// with_proto, date}
function parseReceived(line) {
  line = String(line || "").slice(0, 8192);
  const out = { raw: line };

  // from <host> (<host2> [<ip>])
  const mFrom = line.match(/from\s+([^\s;()]+)(?:\s+\(([^)]+)\))?/i);
  if (mFrom) {
    out.from_host = shortValue(mFrom[1]);
    const hi = mFrom[2];
    if (hi) {
      const mIp = parentheticalIpLiteral(hi);
      if (mIp) out.from_ip = mIp;
      // Only capture a parenthetical hostname when it's immediately
      // followed by " [ip]" — that's the canonical "host [IP]" pattern.
      // Otherwise we'd mistake MTA product tags like "(Postfix)" or
      // "(Qmail 1.03)" for internal hostnames.
      const mHost = hi.match(/^([A-Za-z0-9._\-]+)\s+\[/);
      if (mHost) out.from_host_parenthetical = shortValue(mHost[1]);
    }
    // HELO-claimed bare IP: "from [192.168.1.6]" or "from [fe80::…]".
    // Treat the bracketed literal as an IP, not a hostname.
    const mFromIp = bracketIpLiteral(out.from_host);
    if (mFromIp) {
      out.from_ip = out.from_ip || mFromIp;
      out.from_host = null;
    }
  }

  // by <host> (optional parenthetical with HELO-name / resolved IP)
  // Example: "by mrs-cscorp.1and1.com (mrscorp004 [172.19.128.197])" —
  // the parenthetical carries a second internal hostname + a private IP
  // we want to surface as leaks.
  const mBy = line.match(/\bby\s+([^\s;()]+)(?:\s+\(([^)]+)\))?/i);
  if (mBy) {
    out.by_host = shortValue(mBy[1]);
    const hi = mBy[2];
    if (hi) {
      const mIp = parentheticalIpLiteral(hi);
      if (mIp) out.by_ip = mIp;
      // Only capture a parenthetical hostname when it's immediately
      // followed by " [ip]" — that's the canonical "host [IP]" pattern.
      // Otherwise we'd mistake MTA product tags like "(Postfix)" or
      // "(Qmail 1.03)" for internal hostnames.
      const mHost = hi.match(/^([A-Za-z0-9._\-]+)\s+\[/);
      if (mHost) out.by_host_parenthetical = shortValue(mHost[1]);
    }
    const mByIp = bracketIpLiteral(out.by_host);
    if (mByIp) {
      out.by_ip = out.by_ip || mByIp;
      out.by_host = null;
    }
  }

  // with <proto>
  const mWith = line.match(/with\s+([A-Za-z0-9\-]+)/i);
  if (mWith) out.with_proto = shortValue(mWith[1], 80);

  // id <x>
  const mId = line.match(/id\s+([^\s;]+)/i);
  if (mId) out.id = shortValue(mId[1], 120);

  // Date is after the last ";"
  const semi = line.lastIndexOf(";");
  if (semi >= 0) {
    const tail = line.slice(semi + 1).trim();
    out.date = shortValue(tail, 300);
  }
  return out;
}

function detectReceivedChain(headers) {
  const out = [];
  const hops = getAllHeader(headers, "Received");
  if (hops.length === 0) return out;

  // Top-down — hops are written in reverse chronological order in the wire.
  const parsed = hops.map(parseReceived);
  out.push(finding("received_chain", "hop_count", String(parsed.length),
                   CONF.HIGH, { leaks: { hops: parsed.length } }));

  // Internal hostnames / private IPs — tracked WITH hop context so the UI
  // can show which relay rewrote them in. Each entry is {host|ip, from, by}
  // where `from` is the claiming sender's hostname and `by` is the
  // receiving server that recorded it.
  const internalHostHops = [];
  const privateIpHops = [];
  for (const hop of parsed) {
    // Every hostname field the hop exposes — both the canonical names
    // (from_host / by_host) and the parentheticals (HELO / PTR-style
    // hints the receiving server wrote down). Single-label names and
    // .local/.corp/.internal/.lan-style suffixes are flagged.
    for (const h of [hop.from_host, hop.from_host_parenthetical,
                     hop.by_host, hop.by_host_parenthetical]) {
      if (!h) continue;
      if (looksLikeIpLiteralHost(h)) continue;
      const host = shortValue(h.replace(/[\[\]<>]/g, ""));
      if (looksInternalDomain(host) || /\.(local|home|internal|corp|lan)$/i.test(host)) {
        internalHostHops.push({
          host,
          from: hop.from_host || hop.from_host_parenthetical || null,
          by:   hop.by_host || null,
        });
      }
    }
    // Private IPs can appear in either the from-parenthetical (sender
    // side) or the by-parenthetical (receiver's internal routing host).
    for (const [ip, origin] of [
      [hop.from_ip, "from"],
      [hop.by_ip,   "by"],
    ]) {
      if (ip && isPrivateIP(ip)) {
        privateIpHops.push({
          ip,
          from: hop.from_host || hop.from_host_parenthetical || null,
          by:   hop.by_host || null,
          origin,
        });
      }
    }
  }

  const dedupeBy = (arr, keyFn) => {
    const seen = new Set(); const out = [];
    for (const x of arr) {
      const k = keyFn(x);
      if (seen.has(k)) continue;
      seen.add(k); out.push(x);
    }
    return out;
  };

  const uniqInternal = dedupeBy(internalHostHops,
                                h => `${h.host}|${h.from || ""}|${h.by || ""}`);
  const uniqPrivIp   = dedupeBy(privateIpHops,
                                h => `${h.ip}|${h.from || ""}|${h.by || ""}`);

  if (uniqInternal.length) {
    const hostValues = Array.from(new Set(uniqInternal.map(h => h.host)))
      .slice(0, MAX_RELAY_VALUES);
    out.push(finding("received_chain", "internal_hostname_leak",
                     hostValues.slice(0, 5).join(", "),
                     CONF.HIGH, {
      leaks: {
        internal_hostnames: hostValues,
        hops: uniqInternal.slice(0, 8),
      },
      notes: ["Corporate/lab hostname exposed via relay rewrite — " +
              "classic OSINT target."]
    }));
  }
  if (uniqPrivIp.length) {
    const ipValues = Array.from(new Set(uniqPrivIp.map(h => h.ip)))
      .slice(0, MAX_RELAY_VALUES);
    out.push(finding("received_chain", "private_ip_leak",
                     ipValues.slice(0, 5).join(", "),
                     CONF.HIGH, {
      leaks: {
        private_ips: ipValues,
        hops: uniqPrivIp.slice(0, 8),
      },
      notes: ["RFC1918 address in Received — internal LAN range visible."]
    }));
  }

  // Per-hop relay information — one entry per Received header, in wire
  // (= reverse-chronological) order. UI applies the user-selected
  // direction (originFirst / receiverFirst) at render time.
  //
  // Bug fix history:
  //   - We used to dedup `by_host` here, but two consecutive hops through
  //     the same MX (e.g. 1&1's mxeue011 → mxeue011 in their internal
  //     fan-out) would silently disappear, leaving "3 hops" displayed as 2.
  //   - We used to drop `by_ip` / `from_ip` from the surfaced data, so
  //     external (public) IPs never made it to the popup even when the
  //     hostname was shown. Now every hop carries its IP context.
  const internalHostSet = new Set(internalHostHops.map(h => h.host));
  const richHops = parsed.map(hop => ({
    by_host: hop.by_host || null,
    by_ip:   hop.by_ip || null,
    from_host: hop.from_host || null,
    from_ip:   hop.from_ip || null,
  }));
  // Origin = the very bottom hop's "from" side: the original sender's
  // self-claim, not yet rewritten by any relay. Important context that
  // hop_count alone doesn't surface.
  const bottom = parsed[parsed.length - 1] || null;
  const origin = bottom ? {
    host: bottom.from_host || bottom.from_host_parenthetical || null,
    ip:   bottom.from_ip || null,
  } : null;
  const externalHosts = [];
  const seenRelay = new Set();
  for (const hop of parsed) {
    if (!hop.by_host) continue;
    if (internalHostSet.has(hop.by_host)) continue;
    if (seenRelay.has(hop.by_host)) continue;
    seenRelay.add(hop.by_host);
    externalHosts.push(shortValue(hop.by_host));
  }
  if (richHops.length) {
    // `relays` keeps the legacy hostnames-only summary string for any
    // consumer that only wants a one-line fingerprint. `hops` is the new
    // rich array; consumers that render IPs use it.
    out.push(finding("received_chain", "relay_path",
                     externalHosts.slice(0, 4).join(" → "),
                     CONF.MEDIUM, { leaks: {
                       relays: externalHosts.slice(0, 8),
                       hops:   richHops.slice(0, MAX_RELAY_VALUES),
                       origin: origin && (origin.host || origin.ip) ? origin : null,
                     } }));
  }

  // Chronologie: parse dates, check if they are monotonic (expected: hop[0]
  // is newest = highest timestamp, hop[last] is oldest = lowest).
  //
  // Date.parse() is intentionally lenient — `Date.parse("2020")` returns
  // a valid epoch (Jan 1 2020), `Date.parse("+0000")` returns Jan 1 2000.
  // A broken MTA that writes a truncated Date stanza (just a year, just a
  // TZ offset, …) would otherwise create a false chronology anomaly when
  // the rest of the chain has present-day dates. We require the stanza to
  // look at least like a RFC-2822 day/month/year/time tuple before we
  // hand it to Date.parse, and we sanity-bound the resulting epoch to
  // 1990-01-01 .. now+7d. Real Received chains satisfy both.
  const RFC2822_LIKE = /\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\b[^,]*\s+\d{4}\s+\d{1,2}:\d{2}/i;
  const NOW = Date.now();
  const MIN_PLAUSIBLE = Date.parse("1990-01-01T00:00:00Z");
  const MAX_PLAUSIBLE = NOW + 7 * 86_400_000;
  const timestamps = parsed.map(p => {
    if (!p.date) return null;
    if (!RFC2822_LIKE.test(p.date)) return null;
    const t = Date.parse(p.date);
    if (!Number.isFinite(t)) return null;
    if (t < MIN_PLAUSIBLE || t > MAX_PLAUSIBLE) return null;
    return t;
  });
  let invertedPairs = 0;
  for (let i = 0; i < timestamps.length - 1; i++) {
    const a = timestamps[i], b = timestamps[i + 1];
    if (a == null || b == null) continue;
    // hop[i] should be >= hop[i+1] (newer at top). >60s drift = suspicious.
    if (a + 60_000 < b) invertedPairs++;
  }
  if (invertedPairs > 0) {
    out.push(finding("received_chain", "chronology_anomaly",
                     `${invertedPairs} inverted hop(s)`,
                     CONF.MEDIUM, {
      leaks: { inverted_pairs: invertedPairs },
      notes: ["Received-Zeitstempel nicht monoton — möglicher Relay-Clock-Drift " +
              "oder Chain-Manipulation."]
    }));
  }

  return out;
}

globalThis.OSINTDetect = globalThis.OSINTDetect || {};
globalThis.OSINTDetect.received = detectReceivedChain;

})();
