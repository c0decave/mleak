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
  displayMode: "popup",   // popup | bodyInline | headerInline
  // Whether the bodyInline panel mounts in detail mode (full breakdown:
  // per-hop relays, per-test auth verdicts, DKIM sigs, crypto, integrity,
  // date, MIME) by default. Off by default — the compact one-line summary
  // is enough for most reads; the per-panel `Details` button lets a user
  // expand a single mail without flipping this flag.
  inlineDetails: false,
  // Direction the relay path is rendered in.
  //   originFirst   = "the path the mail took to me" (sender → receiver)
  //                   — natural for forensic reading
  //   receiverFirst = wire order, mirrors the Received: header layout top-down
  //                   (newest first) — useful when cross-referencing raw source
  // Data in storage stays canonical (wire order); the renderer flips.
  relayPathDirection: "originFirst",
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

const STRING_ENUMS = Object.freeze({
  theme: new Set(["auto", "dark", "light"]),
  density: new Set(["compact", "normal", "comfy"]),
  defaultView: new Set(["cards", "raw"]),
  displayMode: new Set(["popup", "bodyInline", "headerInline"]),
  relayPathDirection: new Set(["originFirst", "receiverFirst"]),
});

const NUMBER_ENUMS = Object.freeze({
  width: new Set([440, 500, 600, 720]),
  cacheSize: new Set([0, 16, 64, 256]),
});

// Sanitize a single stored value against its default. Number-typed defaults
// must get a finite allowlisted number back; booleans must get a true/false;
// string selects must stay inside their declared enum.
// Anything else (wrong type, NaN, -Inf, garbage strings) falls back to the
// default. Keeps the rest of the code from having to re-validate.
function sanitize(out) {
  for (const [k, def] of Object.entries(DEFAULTS)) {
    const v = out[k];
    if (typeof def === "number") {
      const allowed = NUMBER_ENUMS[k];
      if (typeof v !== "number" || !Number.isFinite(v) ||
          (allowed && !allowed.has(v)) || (!allowed && v < 0)) {
        out[k] = def;
      }
    } else if (typeof def === "boolean") {
      if (typeof v !== "boolean") out[k] = def;
    } else if (typeof def === "string") {
      const allowed = STRING_ENUMS[k];
      if (typeof v !== "string" || (allowed && !allowed.has(v))) out[k] = def;
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

globalThis.OSINTSettings = {
  DEFAULTS, STRING_ENUMS, NUMBER_ENUMS, sanitize, getAll, subscribe,
};

})();
