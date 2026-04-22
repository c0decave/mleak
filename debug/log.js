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

function toText(entries) {
  return entries.map(e =>
    `${e.ts}  [${(e.level || "info").padEnd(5)}]  ${e.where}  ${e.msg}`
  ).join("\n");
}

function render(entries) {
  const pre = document.getElementById("log");
  const status = document.getElementById("status");
  const meta = document.getElementById("meta");

  pre.replaceChildren();
  if (!entries.length) {
    status.textContent = t("logEmpty");
    meta.textContent = `0 ${t("logEntries")}`;
    return;
  }
  status.hidden = true;
  meta.textContent = `${entries.length} ${t("logEntries")} · ${entries[0].ts.slice(0,19)} → ${entries[entries.length-1].ts.slice(0,19)}`;

  for (const e of entries) {
    const line = document.createElement("span");
    line.className = "lvl-" + (e.level || "info");
    line.textContent =
      `${e.ts}  [${(e.level || "info").padEnd(5)}]  ${e.where}  ${e.msg}\n`;
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
  document.getElementById("btn-refresh").addEventListener("click", refresh);
  document.getElementById("btn-copy").addEventListener("click", doCopy);
  document.getElementById("btn-download").addEventListener("click", doDownload);
  document.getElementById("btn-clear").addEventListener("click", doClear);
  refresh();
});
