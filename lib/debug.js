/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Ring-buffer debug log. OFF by default — user-opt-in only.
//
// When enabled (settings.debugLog === true), every dlog() call persists a
// { ts, level, where, msg } entry to storage.local under key _debug_log,
// capped at MAX_ENTRIES. The log viewer (debug/log.html) reads the same
// key and renders it for the user to inspect / copy / send to support.
//
// When disabled, dlog() is a cheap no-op — no storage write happens, so
// an ordinary install incurs zero persistence overhead.
//
// dlog() also always mirrors to console.log/warn/error so a developer
// running TB with a debug console attached still sees the output live.

"use strict";

(() => {

const MAX_ENTRIES = 500;
const KEY = "_debug_log";

let enabled = false;
let writeInFlight = Promise.resolve();

// Read the current setting at boot. Re-reads whenever the user flips it.
async function refresh() {
  try {
    const s = await messenger.storage.local.get({ debugLog: false });
    enabled = !!s.debugLog;
  } catch (_) { enabled = false; }
}
refresh();
if (messenger.storage && messenger.storage.onChanged) {
  messenger.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (changes.debugLog) enabled = !!changes.debugLog.newValue;
  });
}

function fmt(args) {
  return args.map(a => {
    if (a == null) return String(a);
    if (typeof a === "string") return a;
    try { return JSON.stringify(a); } catch (_) { return String(a); }
  }).join(" ");
}

async function append(entry) {
  // Serialize writes so rapid-fire dlog calls don't race on storage.
  writeInFlight = writeInFlight.then(async () => {
    try {
      const cur = await messenger.storage.local.get({ [KEY]: [] });
      const buf = Array.isArray(cur[KEY]) ? cur[KEY] : [];
      buf.push(entry);
      if (buf.length > MAX_ENTRIES) {
        buf.splice(0, buf.length - MAX_ENTRIES);
      }
      await messenger.storage.local.set({ [KEY]: buf });
    } catch (_) { /* storage quota hit or extension shutting down */ }
  });
  return writeInFlight;
}

function dlog(level, where, ...args) {
  // Always mirror to console — cheap, useful when the devtools are open.
  const line = `[mleak:${where}] ${fmt(args)}`;
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);

  if (!enabled) return;
  append({
    ts:    new Date().toISOString(),
    level: level,
    where: where,
    msg:   fmt(args),
  });
}

async function readAll() {
  const cur = await messenger.storage.local.get({ [KEY]: [] });
  return Array.isArray(cur[KEY]) ? cur[KEY] : [];
}

async function clear() {
  await messenger.storage.local.set({ [KEY]: [] });
}

globalThis.OSINTDebug = { dlog, readAll, clear, MAX_ENTRIES };

})();
