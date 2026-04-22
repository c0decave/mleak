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

// Parse one Received header into {from_host, from_ip, by_host, id, proto,
// with_proto, date}
function parseReceived(line) {
  const out = { raw: line };

  // from <host> (<host2> [<ip>])
  const mFrom = line.match(/from\s+([^\s;()]+)(?:\s+\(([^)]+)\))?/i);
  if (mFrom) {
    out.from_host = mFrom[1];
    const hi = mFrom[2];
    if (hi) {
      const mIp = hi.match(/\[([0-9a-fA-F:.]+)\]/);
      if (mIp) out.from_ip = mIp[1];
      // Only capture a parenthetical hostname when it's immediately
      // followed by " [ip]" — that's the canonical "host [IP]" pattern.
      // Otherwise we'd mistake MTA product tags like "(Postfix)" or
      // "(Qmail 1.03)" for internal hostnames.
      const mHost = hi.match(/^([A-Za-z0-9._\-]+)\s+\[/);
      if (mHost) out.from_host_parenthetical = mHost[1];
    }
    // HELO-claimed bare IP: "from [192.168.1.6]" or "from [fe80::…]".
    // Treat the bracketed literal as an IP, not a hostname.
    const mFromIp = out.from_host.match(/^\[([0-9a-fA-F:.]+)\]$/);
    if (mFromIp) {
      out.from_ip = out.from_ip || mFromIp[1];
      out.from_host = null;
    }
  }

  // by <host> (optional parenthetical with HELO-name / resolved IP)
  // Example: "by mrs-cscorp.1and1.com (mrscorp004 [172.19.128.197])" —
  // the parenthetical carries a second internal hostname + a private IP
  // we want to surface as leaks.
  const mBy = line.match(/\bby\s+([^\s;()]+)(?:\s+\(([^)]+)\))?/i);
  if (mBy) {
    out.by_host = mBy[1];
    const hi = mBy[2];
    if (hi) {
      const mIp = hi.match(/\[([0-9a-fA-F:.]+)\]/);
      if (mIp) out.by_ip = mIp[1];
      // Only capture a parenthetical hostname when it's immediately
      // followed by " [ip]" — that's the canonical "host [IP]" pattern.
      // Otherwise we'd mistake MTA product tags like "(Postfix)" or
      // "(Qmail 1.03)" for internal hostnames.
      const mHost = hi.match(/^([A-Za-z0-9._\-]+)\s+\[/);
      if (mHost) out.by_host_parenthetical = mHost[1];
    }
  }

  // with <proto>
  const mWith = line.match(/with\s+([A-Za-z0-9\-]+)/i);
  if (mWith) out.with_proto = mWith[1];

  // id <x>
  const mId = line.match(/id\s+([^\s;]+)/i);
  if (mId) out.id = mId[1];

  // Date is after the last ";"
  const semi = line.lastIndexOf(";");
  if (semi >= 0) {
    const tail = line.slice(semi + 1).trim();
    out.date = tail;
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
      const host = h.replace(/[\[\]<>]/g, "");
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
    const hostValues = Array.from(new Set(uniqInternal.map(h => h.host)));
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
    const ipValues = Array.from(new Set(uniqPrivIp.map(h => h.ip)));
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

  // Unique external hostnames — short relay fingerprint. Dedup preserving
  // order so repeated hops through the same relay don't pad the path.
  const internalHostSet = new Set(internalHostHops.map(h => h.host));
  const externalHosts = [];
  const seenRelay = new Set();
  for (const hop of parsed) {
    if (!hop.by_host) continue;
    if (internalHostSet.has(hop.by_host)) continue;
    if (seenRelay.has(hop.by_host)) continue;
    seenRelay.add(hop.by_host);
    externalHosts.push(hop.by_host);
  }
  if (externalHosts.length) {
    out.push(finding("received_chain", "relay_path",
                     externalHosts.slice(0, 4).join(" → "),
                     CONF.MEDIUM, { leaks: { relays: externalHosts.slice(0, 8) } }));
  }

  // Chronologie: parse dates, check if they are monotonic (expected: hop[0]
  // is newest = highest timestamp, hop[last] is oldest = lowest)
  const timestamps = parsed.map(p => {
    if (!p.date) return null;
    const t = Date.parse(p.date);
    return Number.isFinite(t) ? t : null;
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
