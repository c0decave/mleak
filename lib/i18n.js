/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Tiny i18n helper. Loaded in every HTML surface (popup / options / log).
// Applies messages from `_locales/<lang>/messages.json` based on the TB UI
// language. Four DOM opt-ins:
//
//   <span data-i18n="cardMua"></span>              -> textContent
//   <p    data-i18n-html="optInlineHint"></p>      -> innerHTML (trusted: bundled)
//   <button data-i18n-title="popupToggleRaw" …>    -> title attribute
//   <html data-i18n-title="optPageTitle" …>        -> document.title
//
// Runtime JS can also call OSINTi18n.t("key", ["arg1"]).

"use strict";

(() => {

function t(key, substitutions) {
  try {
    // messenger is available in all extension surfaces; fall back to
    // browser.* for robustness (shouldn't be needed in TB).
    const api = (typeof messenger !== "undefined" ? messenger : browser);
    const m = api.i18n.getMessage(key, substitutions);
    return m || key;
  } catch (_) {
    return key;
  }
}

// Defence in depth: innerHTML is only rendered for keys on this allowlist.
// Every other data-i18n-html attribute value falls back to textContent.
// The locale content itself is trusted (bundled inside the XPI), but if
// apply() is ever invoked against a DOM we don't fully own — e.g. the
// message-display frame whose body is attacker-controlled email HTML —
// the allowlist prevents a forged `data-i18n-html="<img src=x onerror=…>"`
// attribute from landing as active markup.
const SAFE_HTML_KEYS = Object.freeze(new Set([
  "optInlineHint",
  "optDebugHint",
  "optButtonPositionHint",
  "optAboutContribute",
  "optAboutVersion",
  "logFooter",
]));

function apply(root) {
  root = root || document;
  for (const el of root.querySelectorAll("[data-i18n]")) {
    el.textContent = t(el.dataset.i18n);
  }
  for (const el of root.querySelectorAll("[data-i18n-html]")) {
    const key = el.dataset.i18nHtml;
    if (!SAFE_HTML_KEYS.has(key)) {
      // Unknown key — don't trust the fallback string as HTML.
      el.textContent = t(key);
      continue;
    }
    // Allowlisted key + bundled _locales source — safe to render.
    el.innerHTML = t(key);
  }
  for (const el of root.querySelectorAll("[data-i18n-title]")) {
    const key = el.dataset.i18nTitle;
    if (el === document.documentElement) document.title = t(key);
    else el.title = t(key);
  }
  for (const el of root.querySelectorAll("[data-i18n-placeholder]")) {
    el.placeholder = t(el.dataset.i18nPlaceholder);
  }
  // <html data-i18n-title="…"> also works (selector above matches it).
}

globalThis.OSINTi18n = { t, apply };

// Run as soon as the DOM is ready. HTML files should load i18n.js in <head>
// (or at least before their own script) so strings render on first paint.
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => apply());
} else {
  apply();
}

})();
