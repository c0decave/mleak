/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
"use strict";

// Defaults come from lib/settings.js (single source of truth). The html
// loads settings.js before this script, so OSINTSettings.DEFAULTS is ready.
const DEFAULTS = globalThis.OSINTSettings.DEFAULTS;

const FIELDS = {
  theme:       "opt-theme",
  width:       "opt-width",
  density:     "opt-density",
  defaultView: "opt-default-view",
  cacheSize:   "opt-cache-size",
  // inlineMode intentionally omitted — the inline-mode UI is gated off
  // while the onMessageDisplayed-based injection path is still flaky on
  // certain Thunderbird layouts. The background-side lifecycle code
  // stays in place but is never triggered; storage.inlineMode is a dead
  // key now. Re-enable by re-adding inlineMode here + the settings card.
  debugLog:    "opt-debug-log",
  // Card-visibility toggles — backed by <input type="checkbox">, handled
  // below via el.checked instead of el.value.
  showMua:       "opt-show-mua",
  showStack:     "opt-show-stack",
  showLeaks:     "opt-show-leaks",
  showAuth:      "opt-show-auth",
  showIntegrity: "opt-show-integrity",
  showDate:      "opt-show-date",
  showMime:      "opt-show-mime",
};

const CHECKBOX_KEYS = new Set([
  "showMua", "showStack", "showLeaks", "showAuth",
  "showIntegrity", "showDate", "showMime",
]);

async function load() {
  const stored = await messenger.storage.local.get(DEFAULTS);
  for (const [key, id] of Object.entries(FIELDS)) {
    const el = document.getElementById(id);
    if (!el) continue;
    const v = stored[key] ?? DEFAULTS[key];
    if (CHECKBOX_KEYS.has(key)) {
      el.checked = !!v;
    } else {
      // Selects store their value as strings regardless of the underlying
      // type (boolean for inlineMode/debugLog, number for width/cacheSize).
      el.value = String(v);
    }
  }
}

let saveTimer = null;
function scheduleSave() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(save, 120);
}

async function save() {
  const patch = {};
  for (const [key, id] of Object.entries(FIELDS)) {
    const el = document.getElementById(id);
    if (!el) continue;
    let v;
    if (CHECKBOX_KEYS.has(key)) {
      v = !!el.checked;
    } else {
      v = el.value;
      if (key === "width" || key === "cacheSize") v = Number(v);
      else if (key === "inlineMode" || key === "debugLog") v = (v === "true");
    }
    patch[key] = v;
  }
  await messenger.storage.local.set(patch);
  flashSaved();
}

let flashFadeTimer = null;
let flashHideTimer = null;

function flash(text) {
  const el = document.getElementById("saved");
  el.textContent = text;
  el.hidden = false;
  el.style.opacity = "1";
  if (flashFadeTimer) clearTimeout(flashFadeTimer);
  if (flashHideTimer) clearTimeout(flashHideTimer);
  flashFadeTimer = setTimeout(() => { el.style.opacity = "0"; }, 900);
  flashHideTimer = setTimeout(() => {
    el.hidden = true;
    el.style.opacity = "";
  }, 1400);
}

function flashSaved()   { flash(globalThis.OSINTi18n?.t?.("optSaved")        ?? "✓ saved"); }
function flashCleared() { flash(globalThis.OSINTi18n?.t?.("optCacheCleared") ?? "✓ cleared"); }

async function reset() {
  await messenger.storage.local.set(DEFAULTS);
  await load();
  flashSaved();
}

async function clearCache() {
  // The background page holds the in-memory ANALYSIS_CACHE. Ask it nicely.
  try {
    await messenger.runtime.sendMessage({ type: "clearCache" });
  } catch (e) { /* background may be suspended; storage flag is enough */ }
  flashCleared();
}

document.addEventListener("DOMContentLoaded", () => {
  // Cache-size options carry the count as an attribute so we can render
  // "64 mails" in whichever locale is active, using messages.json
  // placeholder substitution ($N$).
  const t = globalThis.OSINTi18n && globalThis.OSINTi18n.t;
  if (t) {
    for (const opt of document.querySelectorAll("[data-i18n-cache]")) {
      opt.textContent = t("optCacheMails", [opt.dataset.i18nCache]);
    }
  }

  // Version string for the About card — pulled from the manifest. The
  // surrounding template is innerHTML-rendered (it needs <strong> and
  // <code>), so $V$ must not carry HTML. Rather than hand-escape — bearer
  // and friends flag that as an anti-pattern — we format-validate: the
  // manifest version is semver, so a strict allowlist on its characters
  // is both stronger and simpler than an escape. Anything that doesn't
  // look like a version degrades to "?" instead of rendering.
  try {
    const vRaw = messenger.runtime.getManifest().version;
    const v = /^[\w.+\-]{1,32}$/.test(vRaw) ? vRaw : "?";
    const versionEl = document.querySelector('[data-i18n-html="optAboutVersion"]');
    if (versionEl && t) {
      versionEl.innerHTML = t("optAboutVersion", [v]);
    }
  } catch (_) { /* manifest read failed — hint falls back to placeholder */ }

  load();
  for (const id of Object.values(FIELDS)) {
    const el = document.getElementById(id);
    if (el) el.addEventListener("change", scheduleSave);
  }
  document.getElementById("opt-clear-cache").addEventListener("click", clearCache);
  document.getElementById("opt-reset").addEventListener("click", reset);
  document.getElementById("opt-open-log").addEventListener("click", () => {
    messenger.tabs.create({ url: messenger.runtime.getURL("debug/log.html") });
  });
});
