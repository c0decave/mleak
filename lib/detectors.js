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

function _run(name, fn) {
  try { return fn() || []; }
  catch (e) {
    _dlog("warn", "detect", `${name} threw:`, e && e.message || e,
          e && e.stack ? "\n" + e.stack : "");
    return [];
  }
}

async function analyzeMessage(message) {
  // message = { headers: {lowercase: [strings]}, parts: [...] }
  const headers = message.headers || {};
  const out = [];

  const d = globalThis.OSINTDetect || {};
  out.push(..._run("messageId",     () => d.messageId     ? d.messageId(headers)     : []));
  out.push(..._run("userAgent",     () => d.userAgent     ? d.userAgent(headers)     : []));
  out.push(..._run("serverHeaders", () => d.serverHeaders ? d.serverHeaders(headers) : []));
  out.push(..._run("received",      () => d.received      ? d.received(headers)      : []));
  out.push(..._run("dkim",          () => d.dkim          ? d.dkim(headers)          : []));
  out.push(..._run("authResults",   () => d.authResults   ? d.authResults(headers)   : []));
  out.push(..._run("integrity",     () => d.integrity     ? d.integrity(headers)     : []));
  out.push(..._run("crypto",        () => d.crypto        ? d.crypto(message)        : []));
  out.push(..._run("body",          () => d.body          ? d.body(message)          : []));

  return aggregate(out, headers);
}

// Turn the raw findings array into a structured panel the UI can render.
function aggregate(findings, headers) {
  const mua = findings.find(f => f.detector === "user_agent"
                                 && f.kind === "client_selfreport");
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
  const authVerdicts = findings.find(f => f.detector === "auth_results");
  const dkimSigs = findings.filter(f => f.detector === "dkim" && f.kind === "signature");
  const integrityFindings = findings.filter(f => f.detector === "integrity");
  const mimeStruct = findings.find(f => f.kind === "mime_structure");

  // Date / TZ
  const dateRaw = (headers["date"] || [""])[0] || "";
  let tzMinutes = null;
  let parsedDate = null;
  if (dateRaw) {
    const ms = Date.parse(dateRaw);
    if (Number.isFinite(ms)) {
      parsedDate = new Date(ms).toISOString();
      const mTz = dateRaw.match(/([+\-])(\d{2})(\d{2})\b\s*$/);
      if (mTz) tzMinutes = (mTz[1] === "-" ? -1 : 1) *
                           (parseInt(mTz[2], 10) * 60 + parseInt(mTz[3], 10));
    }
  }

  // Consolidate MUA guess across signals
  const muaSignals = [];
  if (mua) muaSignals.push({ src: "UA-Header", label: mua.value, conf: mua.confidence });
  if (midFinding && midFinding.value !== "unknown") {
    muaSignals.push({ src: "Message-ID", label: midFinding.value, conf: midFinding.confidence });
  }
  for (const b of bodyMua) {
    muaSignals.push({ src: "HTML-Body", label: b.value, conf: b.confidence });
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
      relay_hops: relayPath && relayPath.leaks ? relayPath.leaks.relays : null,
      internal_hostname_leak: internalLeak ? internalLeak.value : null,
      internal_hostname_hops:
        internalLeak && internalLeak.leaks ? internalLeak.leaks.hops : null,
      private_ip_leak: privIpLeak ? privIpLeak.value : null,
      private_ip_hops:
        privIpLeak && privIpLeak.leaks ? privIpLeak.leaks.hops : null,
      chronology_anomaly: chronology ? chronology.value : null,
      auth_verdicts: authVerdicts ? authVerdicts.leaks : null,
      dkim_signatures: dkimSigs.map(s => s.leaks),
      crypto: cryptoFindings.map(f => ({
        kind: f.kind, value: f.value, leaks: f.leaks, notes: f.notes,
      })),
      integrity_flags: integrityFindings.map(f => ({
        kind: f.kind, value: f.value, notes: f.notes
      })),
      mime_structure: mimeStruct ? mimeStruct.value : null,
      date: { raw: dateRaw, parsed: parsedDate, tz_offset_minutes: tzMinutes },
      leaks: {
        mid: midFinding ? midFinding.leaks : null,
        m365_datacenter: midFinding && midFinding.leaks
                         ? midFinding.leaks.datacenter_hint : null,
        hostname_leak: midFinding && midFinding.leaks
                       ? (midFinding.leaks.internal_hostname ||
                          (midFinding.leaks.hostname_leak ? midFinding.leaks.hostname : null))
                       : null,
      },
    },
    raw_findings: findings,
  };
}

globalThis.OSINTAnalyze = analyzeMessage;
