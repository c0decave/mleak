/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
"use strict";

const { readAll, clear } = globalThis.OSINTDebug;
const t = (k, s) => globalThis.OSINTi18n?.t?.(k, s) ?? k;
const MAX_VIEW_ENTRIES = 500;
const MAX_VIEW_FIELD = 1200;

function normalizeTheme(theme) {
  const allowed = globalThis.OSINTSettings?.STRING_ENUMS?.theme;
  return allowed && allowed.has(theme) ? theme : "auto";
}

function applyThemeValue(theme) {
  document.documentElement.dataset.theme = normalizeTheme(theme);
}

async function applyTheme() {
  try {
    const s = await globalThis.OSINTSettings.getAll();
    applyThemeValue(s.theme);
  } catch (_) {
    applyThemeValue("auto");
  }
}

try {
  globalThis.OSINTSettings.subscribe(changes => {
    if (changes.theme) applyThemeValue(changes.theme.newValue);
  });
} catch (_) { /* settings unavailable; keep data-theme=auto */ }

function toText(entries) {
  entries = normalizeEntries(entries);
  return entries.map(e =>
    `${e.ts}  [${normalizeLevel(e.level).padEnd(5)}]  ${e.where}  ${e.msg}`
  ).join("\n");
}

function normalizeLevel(level) {
  return level === "error" || level === "warn" ||
         level === "info" || level === "debug" ? level : "info";
}

function cap(value, max = MAX_VIEW_FIELD) {
  const s = String(value == null ? "" : value);
  return s.length > max ? s.slice(0, max) + "...[truncated]" : s;
}

function normalizeEntry(entry) {
  const e = entry && typeof entry === "object" ? entry : {};
  return {
    ts: cap(e.ts || "", 40),
    level: normalizeLevel(e.level),
    where: cap(e.where || "?", 80),
    msg: cap(e.msg),
  };
}

function normalizeEntries(entries) {
  return Array.isArray(entries)
    ? entries.slice(-MAX_VIEW_ENTRIES).map(normalizeEntry)
    : [];
}

function render(entries) {
  entries = normalizeEntries(entries);
  const pre = document.getElementById("log");
  const status = document.getElementById("status");
  const meta = document.getElementById("meta");

  pre.replaceChildren();
  if (!entries.length) {
    status.hidden = false;
    status.textContent = t("logEmpty");
    meta.textContent = `0 ${t("logEntries")}`;
    return;
  }
  status.hidden = true;
  meta.textContent = `${entries.length} ${t("logEntries")} · ${entries[0].ts.slice(0,19)} → ${entries[entries.length-1].ts.slice(0,19)}`;

  for (const e of entries) {
    const level = normalizeLevel(e.level);
    const line = document.createElement("span");
    line.className = "lvl-" + level;
    line.textContent =
      `${e.ts}  [${level.padEnd(5)}]  ${e.where}  ${e.msg}\n`;
    pre.append(line);
  }
}

async function refresh() {
  try {
    const entries = await readAll();
    render(entries);
  } catch (e) {
    flash(t("logCopyFailed") + (e && e.message || e), true);
  }
}

async function doCopy() {
  try {
    const entries = await readAll();
    await navigator.clipboard.writeText(toText(entries));
    flash(t("logCopied", [String(entries.length)]));
  } catch (e) {
    flash(t("logCopyFailed") + (e && e.message || e), true);
  }
}

async function doDownload() {
  try {
    const entries = await readAll();
    const blob = new Blob([toText(entries)], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `mleak-debug-${new Date().toISOString().slice(0,19).replace(/[:T]/g, "-")}.log`;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 500);
  } catch (e) {
    flash(t("logCopyFailed") + (e && e.message || e), true);
  }
}

async function doClear() {
  if (!confirm(t("logConfirmClear"))) return;
  try {
    await clear();
    await refresh();
    flash(t("logCleared"));
  } catch (e) {
    flash(t("logCopyFailed") + (e && e.message || e), true);
  }
}

function flash(msg, isErr) {
  const m = document.getElementById("meta");
  const orig = m.textContent;
  m.textContent = msg;
  if (isErr) m.style.color = "var(--err)";
  setTimeout(() => { m.textContent = orig; m.style.color = ""; }, 1500);
}

document.addEventListener("DOMContentLoaded", () => {
  applyTheme();
  document.getElementById("btn-refresh").addEventListener("click", refresh);
  document.getElementById("btn-copy").addEventListener("click", doCopy);
  document.getElementById("btn-download").addEventListener("click", doDownload);
  document.getElementById("btn-clear").addEventListener("click", doClear);
  refresh();
});
