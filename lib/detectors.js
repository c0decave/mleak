/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Detector orchestrator + result aggregation for the popup UI.

"use strict";

// Route detector failures through dlog so the opt-in debug log captures
// them alongside the background's own status lines, instead of only
// appearing in the extension's JS console (which most users never open).
const _dlog = (globalThis.OSINTDebug && globalThis.OSINTDebug.dlog)
            || ((level, where, ...a) => console.warn(`[${where}]`, ...a));
const MAX_FINDINGS_PER_DETECTOR = 128;
const MAX_RAW_FINDINGS = 512;

function _run(name, fn) {
  try {
    const result = fn() || [];
    if (!Array.isArray(result)) return [];
    if (result.length <= MAX_FINDINGS_PER_DETECTOR) return result;
    _dlog("warn", "detect", `${name} returned ${result.length} findings; capped`);
    return result.slice(0, MAX_FINDINGS_PER_DETECTOR);
  }
  catch (e) {
    _dlog("warn", "detect", `${name} threw:`, e && e.message || e,
          e && e.stack ? "\n" + e.stack : "");
    return [];
  }
}

// Verdict keys we accept from Authentication-Results findings. Anything
// outside this set is dropped — even though the upstream detector already
// allowlists them, a future regression there must not be able to leak an
// inherited `Object.prototype` member into the summary via crafted keys.
const _AUTH_VERDICT_KEYS = new Set([
  "dkim", "spf", "dmarc", "arc", "bimi", "server",
]);

function mergeAuthVerdicts(authFindings) {
  const merged = Object.create(null);
  for (const f of authFindings) {
    const leaks = f && f.leaks ? f.leaks : null;
    if (!leaks) continue;
    for (const k of _AUTH_VERDICT_KEYS) {
      if (!Object.prototype.hasOwnProperty.call(leaks, k)) continue;
      const v = leaks[k];
      if (v == null || v === "") continue;
      // Keep the first visible verdict for each test. Authentication-Results
      // are prepended by relays, so the first local verdict is usually the
      // one the mailbox provider trusted; later headers can still fill gaps.
      if (!merged[k]) merged[k] = v;
    }
  }
  return Object.keys(merged).length ? { ...merged } : null;
}

async function analyzeMessage(message) {
  // message = { headers: {lowercase: [strings]}, parts: [...] }
  message = message && typeof message === "object" ? message : {};
  const headers = message.headers && typeof message.headers === "object"
    ? message.headers
    : {};
  const out = [];

  const d = globalThis.OSINTDetect || {};
  out.push(..._run("messageId",     () => d.messageId     ? d.messageId(headers)     : []));
  out.push(..._run("userAgent",     () => d.userAgent     ? d.userAgent(headers)     : []));
  out.push(..._run("serverHeaders", () => d.serverHeaders ? d.serverHeaders(headers) : []));
  out.push(..._run("received",      () => d.received      ? d.received(headers)      : []));
  out.push(..._run("dkim",          () => d.dkim          ? d.dkim(headers)          : []));
  out.push(..._run("authResults",   () => d.authResults   ? d.authResults(headers)   : []));
  out.push(..._run("integrity",     () => d.integrity     ? d.integrity(headers)     : []));
  out.push(..._run("headerOrder",   () => d.headerOrder   ? d.headerOrder(headers)   : []));
  out.push(..._run("mimeBoundary",  () => d.mimeBoundary  ? d.mimeBoundary(message)  : []));
  out.push(..._run("mailingList",   () => d.mailingList   ? d.mailingList(headers)   : []));
  out.push(..._run("senderIp",      () => d.senderIp      ? d.senderIp(headers)      : []));
  out.push(..._run("crypto",        () => d.crypto        ? d.crypto(message)        : []));
  out.push(..._run("body",          () => d.body          ? d.body(message)          : []));

  return aggregate(out, headers);
}

// Turn the raw findings array into a structured panel the UI can render.
function aggregate(findings, headers) {
  const mua = findings.find(f => f.detector === "user_agent"
                                 && f.kind === "client_selfreport");
  const unparsedMua = findings.find(f => f.detector === "user_agent"
                                          && f.kind === "unparsed_selfreport");
  const midFinding = findings.find(f => f.detector === "message_id"
                                       && f.kind === "client_fingerprint");
  const bodyMua = findings.filter(f => f.detector === "body_osint"
                                       && (f.kind === "html_generator" ||
                                           f.kind === "html_signature"));
  // UA detector emits a secondary MIME-Version-parenthetical hint
  // (e.g. "Apple Message framework v1085"). Treated as an additional MUA
  // signal with weaker confidence.
  const mimeVersionHint = findings.find(f => f.detector === "user_agent"
                                            && f.kind === "mime_version_hint");
  const cryptoFindings = findings.filter(f => f.detector === "crypto");
  const serverStacks = findings.filter(f => f.detector === "server_headers"
                                            && f.kind.endsWith("_stack"));
  const tenantId = findings.find(f => f.kind === "msft_tenant_id");
  const delivered = findings.find(f => f.kind === "delivered_to");
  const returnPath = findings.find(f => f.kind === "return_path");
  const hopCount = findings.find(f => f.kind === "hop_count");
  const relayPath = findings.find(f => f.kind === "relay_path");
  const internalLeak = findings.find(f => f.kind === "internal_hostname_leak");
  const privIpLeak = findings.find(f => f.kind === "private_ip_leak");
  const chronology = findings.find(f => f.kind === "chronology_anomaly");
  const authVerdictFindings = findings.filter(f => f.detector === "auth_results");
  const authVerdicts = mergeAuthVerdicts(authVerdictFindings);
  const dkimSigs = findings.filter(f => f.detector === "dkim" && f.kind === "signature");
  const integrityFindings = findings.filter(f => f.detector === "integrity");
  const uaConsistencyFindings = findings.filter(f => f.detector === "ua_consistency");
  const headerOrder = findings.find(f => f.detector === "header_order"
                                         && f.kind === "order_fingerprint");
  const mimeBoundaryFindings = findings.filter(f => f.detector === "mime_boundary");
  const mailingListFindings = findings.filter(f => f.detector === "mailing_list");
  const senderIpFindings = findings.filter(f => f.detector === "sender_ip");
  const mimeStruct = findings.find(f => f.kind === "mime_structure");

  // Date / TZ
  const dateRaw = globalThis.OSINTUtil.getHeader(headers, "Date");
  let tzMinutes = null;
  let parsedDate = null;
  if (dateRaw) {
    const tzMatches = Array.from(dateRaw.matchAll(/([+\-])(\d{2})(\d{2})\b/g));
    const mTz = tzMatches.length ? tzMatches[tzMatches.length - 1] : null;
    if (mTz) tzMinutes = (mTz[1] === "-" ? -1 : 1) *
                         (parseInt(mTz[2], 10) * 60 + parseInt(mTz[3], 10));
    const ms = Date.parse(dateRaw);
    if (Number.isFinite(ms)) {
      parsedDate = new Date(ms).toISOString();
    }
  }

  // Consolidate MUA guess across signals
  const muaSignals = [];
  if (mua) muaSignals.push({ src: "UA-Header", label: mua.value, conf: mua.confidence });
  if (unparsedMua) {
    muaSignals.push({
      src: "UA-Header",
      label: unparsedMua.value,
      conf: unparsedMua.confidence,
    });
  }
  if (midFinding && midFinding.value !== "unknown") {
    muaSignals.push({ src: "Message-ID", label: midFinding.value, conf: midFinding.confidence });
  }
  for (const b of bodyMua) {
    muaSignals.push({ src: "HTML-Body", label: b.value, conf: b.confidence });
  }
  for (const b of mimeBoundaryFindings) {
    if (b.kind !== "client_fingerprint") continue;
    muaSignals.push({ src: "MIME boundary", label: b.value, conf: b.confidence });
  }
  if (mimeVersionHint) {
    muaSignals.push({ src: "MIME-Version",
                      label: mimeVersionHint.value,
                      conf:  mimeVersionHint.confidence });
  }
  // Crypto detections (Enigmail / Tuta / ProtonMail / boundary hints)
  // also identify the MUA. Surface them as additional signals so the
  // popup cross-shows them next to UA/MID/Body results.
  for (const c of cryptoFindings) {
    if (c.kind === "enigmail_version" || c.kind === "enigmail_boundary" ||
        c.kind === "tutanota" || c.kind === "protonmail_header" ||
        c.kind === "boundary_mua_hint") {
      muaSignals.push({ src: "Crypto", label: c.value, conf: c.confidence });
    }
  }

  return {
    summary: {
      mua_signals: muaSignals,
      server_stacks: serverStacks.map(s => s.value),
      tenant_id: tenantId ? tenantId.value : null,
      delivered_to: delivered ? delivered.value : null,
      return_path: returnPath ? returnPath.value : null,
      hop_count: hopCount ? Number(hopCount.value) : null,
      relay_path: relayPath ? relayPath.value : null,
      // Rich per-hop array `{by_host, by_ip, from_host, from_ip}` in wire
      // (= receiver-first) order. UI flips the order based on the
      // `relayPathDirection` setting. Falls back to the legacy
      // hostnames-only `relays` string list if the rich payload isn't
      // present (older background.js versions).
      relay_hops: relayPath && relayPath.leaks
        ? (relayPath.leaks.hops || relayPath.leaks.relays || null)
        : null,
      relay_origin: relayPath && relayPath.leaks ? relayPath.leaks.origin : null,
      internal_hostname_leak: internalLeak ? internalLeak.value : null,
      internal_hostname_hops:
        internalLeak && internalLeak.leaks ? internalLeak.leaks.hops : null,
      private_ip_leak: privIpLeak ? privIpLeak.value : null,
      private_ip_hops:
        privIpLeak && privIpLeak.leaks ? privIpLeak.leaks.hops : null,
      chronology_anomaly: chronology ? chronology.value : null,
      auth_verdicts: authVerdicts,
      dkim_signatures: dkimSigs.map(s => s.leaks),
      crypto: cryptoFindings.map(f => ({
        kind: f.kind, value: f.value, leaks: f.leaks, notes: f.notes,
      })),
      integrity_flags: integrityFindings.concat(uaConsistencyFindings).map(f => ({
        kind: f.kind, value: f.value, leaks: f.leaks, notes: f.notes
      })),
      header_order: headerOrder ? {
        value: headerOrder.value,
        order: headerOrder.leaks ? headerOrder.leaks.order : [],
      } : null,
      mime_boundaries: mimeBoundaryFindings.map(f => ({
        kind: f.kind, value: f.value, confidence: f.confidence,
        leaks: f.leaks, notes: f.notes,
      })),
      mailing_lists: mailingListFindings.map(f => ({
        kind: f.kind, value: f.value, confidence: f.confidence,
        leaks: f.leaks, notes: f.notes,
      })),
      sender_ips: senderIpFindings.map(f => ({
        kind: f.kind, value: f.value, confidence: f.confidence,
        leaks: f.leaks, notes: f.notes,
      })),
      mime_structure: mimeStruct ? mimeStruct.value : null,
      date: { raw: dateRaw, parsed: parsedDate, tz_offset_minutes: tzMinutes },
      leaks: {
        mid: midFinding ? midFinding.leaks : null,
        m365_datacenter: midFinding && midFinding.leaks
                         ? midFinding.leaks.datacenter_hint : null,
        hostname_leak: midFinding && midFinding.leaks
                       ? (midFinding.leaks.internal_hostname ||
                          midFinding.leaks.personal_hostname_leak ||
                          (midFinding.leaks.hostname_leak ? midFinding.leaks.hostname : null))
                       : null,
      },
    },
    raw_findings: findings.slice(0, MAX_RAW_FINDINGS),
    raw_findings_truncated: findings.length > MAX_RAW_FINDINGS,
  };
}

globalThis.OSINTAnalyze = analyzeMessage;
