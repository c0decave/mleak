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
const MAX_LOG_FIELD_LEN = 1000;
const MAX_LOG_ARGS = 8;
const KEY = "_debug_log";
const LEVELS = new Set(["error", "warn", "info", "debug"]);

let enabled = false;
let writeInFlight = Promise.resolve();

// Read the current setting at boot. Re-reads whenever the user flips it.
async function refresh() {
  try {
    const s = await messenger.storage.local.get({ debugLog: false });
    enabled = s.debugLog === true;
  } catch (_) { enabled = false; }
}
refresh();
if (messenger.storage && messenger.storage.onChanged) {
  messenger.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    if (changes.debugLog) enabled = changes.debugLog.newValue === true;
  });
}

function cap(s, max = MAX_LOG_FIELD_LEN) {
  s = String(s == null ? "" : s);
  return s.length > max ? s.slice(0, max) + "...[truncated]" : s;
}

function normalizeLevel(level) {
  return LEVELS.has(level) ? level : "info";
}

function sanitizeWhere(where) {
  return cap(where || "?", 40).replace(/[^A-Za-z0-9_.:-]/g, "_");
}

function sanitizeEntry(entry) {
  const e = entry && typeof entry === "object" ? entry : {};
  return {
    ts:    cap(e.ts || new Date().toISOString(), 40),
    level: normalizeLevel(e.level),
    where: sanitizeWhere(e.where),
    msg:   cap(e.msg),
  };
}

function sanitizeBuffer(value) {
  if (!Array.isArray(value)) return [];
  return value.slice(-MAX_ENTRIES).map(sanitizeEntry);
}

function shallowObject(a) {
  const out = {};
  let n = 0;
  for (const [k, v] of Object.entries(a || {})) {
    if (n >= 12) { out["..."] = "truncated"; break; }
    if (v == null || ["string", "number", "boolean"].includes(typeof v)) {
      out[k] = typeof v === "string" ? cap(v, 160) : v;
    } else {
      out[k] = `[${Array.isArray(v) ? "Array" : "Object"}]`;
    }
    n++;
  }
  return out;
}

function fmt(args) {
  return args.slice(0, MAX_LOG_ARGS).map(a => {
    if (a == null) return String(a);
    if (typeof a === "string") return cap(a);
    if (typeof a === "number" || typeof a === "boolean") return String(a);
    if (a instanceof Error) return cap(a.message || String(a));
    if (Array.isArray(a)) {
      return cap(JSON.stringify(a.slice(0, 16).map(v =>
        typeof v === "string" ? cap(v, 160) :
        (v == null || typeof v === "number" || typeof v === "boolean") ? v :
        `[${Array.isArray(v) ? "Array" : "Object"}]`)));
    }
    try { return cap(JSON.stringify(shallowObject(a))); }
    catch (_) { return cap(String(a)); }
  }).join(" ");
}

async function append(entry) {
  // Serialize writes so rapid-fire dlog calls don't race on storage.
  writeInFlight = writeInFlight.then(async () => {
    try {
      const cur = await messenger.storage.local.get({ [KEY]: [] });
      const buf = sanitizeBuffer(cur[KEY]);
      buf.push(sanitizeEntry(entry));
      if (buf.length > MAX_ENTRIES) {
        buf.splice(0, buf.length - MAX_ENTRIES);
      }
      await messenger.storage.local.set({ [KEY]: buf });
    } catch (_) { /* storage quota hit or extension shutting down */ }
  });
  return writeInFlight;
}

function dlog(level, where, ...args) {
  level = normalizeLevel(level);
  where = sanitizeWhere(where);
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
  return sanitizeBuffer(cur[KEY]);
}

async function clear() {
  await messenger.storage.local.set({ [KEY]: [] });
}

globalThis.OSINTDebug = { dlog, readAll, clear, MAX_ENTRIES };

})();
