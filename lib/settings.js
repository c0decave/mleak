/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Shared settings store. Mirrors DEFAULTS in options/options.js.

"use strict";

(() => {

const DEFAULTS = Object.freeze({
  theme: "auto",
  width: 600,
  density: "normal",
  defaultView: "cards",
  cacheSize: 64,
  inlineMode: false,      // true = show panel inline under subject, icon toggles
  debugLog: false,        // true = persist log entries to storage for support
  // Per-card visibility. User can hide cards they don't care about; defaults
  // to everything on so a fresh install shows the full picture.
  showMua: true,
  showStack: true,
  showLeaks: true,
  showAuth: true,
  showIntegrity: true,
  showDate: true,
  showMime: true,
});

// Sanitize a single stored value against its default. Number-typed defaults
// must get a finite, positive number back; booleans must get a true/false.
// Anything else (wrong type, NaN, -Inf, garbage strings) falls back to the
// default. Keeps the rest of the code from having to re-validate.
function sanitize(out) {
  for (const [k, def] of Object.entries(DEFAULTS)) {
    const v = out[k];
    if (typeof def === "number") {
      if (typeof v !== "number" || !Number.isFinite(v) || v < 0) out[k] = def;
    } else if (typeof def === "boolean") {
      if (typeof v !== "boolean") out[k] = def;
    }
  }
  return out;
}

async function getAll() {
  const stored = await messenger.storage.local.get(DEFAULTS);
  return sanitize({ ...DEFAULTS, ...stored });
}

function subscribe(fn) {
  messenger.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;
    fn(changes);
  });
}

globalThis.OSINTSettings = { DEFAULTS, getAll, subscribe };

})();
