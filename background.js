/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Background script — runs in a persistent extension context.
//
// Responsibilities:
//   - expose analyze(messageId) to popup + inline script (via runtime.onMessage)
//   - cache the last analyzed result so the popup/inline render instantly
//   - manage inline-mode: register/unregister a messageDisplayScript that
//     injects a compact panel above the mail body, and swap the toolbar
//     icon's behavior between "open popup" and "toggle inline panel"

"use strict";

// Detector modules are loaded via manifest.background.scripts; they register
// themselves on globalThis.OSINTDetect / OSINTAnalyze at import time.

const { dlog } = globalThis.OSINTDebug;

// ---- Cache ----------------------------------------------------------------

const ANALYSIS_CACHE = new Map();
// Tracks in-flight analyses so two concurrent callers for the same message
// (e.g. popup + inline panel opening at the same instant) share a single
// getFull+analyze round trip.
const PENDING = new Map();
let cacheMax = 64;

function cacheSet(id, value) {
  if (cacheMax <= 0) return;
  while (ANALYSIS_CACHE.size >= cacheMax) {
    const firstKey = ANALYSIS_CACHE.keys().next().value;
    ANALYSIS_CACHE.delete(firstKey);
  }
  ANALYSIS_CACHE.set(id, value);
}

async function analyzeByMessageId(id) {
  if (cacheMax > 0 && ANALYSIS_CACHE.has(id)) return ANALYSIS_CACHE.get(id);
  if (PENDING.has(id)) return PENDING.get(id);
  const p = (async () => {
    try {
      const full = await messenger.messages.getFull(id);
      const result = await globalThis.OSINTAnalyze(full);
      cacheSet(id, result);
      return result;
    } catch (e) {
      dlog("error", "bg", "analyze failed", e && e.message || e);
      return { error: String(e && e.message || e) };
    } finally {
      PENDING.delete(id);
    }
  })();
  PENDING.set(id, p);
  return p;
}

// ---- Inline-mode lifecycle -----------------------------------------------
//
// Earlier versions used messageDisplayScripts.register() and relied on that
// API to auto-inject into every subsequently-loaded mail frame. In practice
// that interacted poorly with the "catch up currently-open mails" path
// (tabs.executeScript silently fails on some TB mail-tab layouts), leaving
// a fraction of users with "inline mode does nothing" on the first mail
// they looked at.
//
// The current approach is simpler and logs everything:
//   1. hook messageDisplay.onMessageDisplayed while inline is enabled
//   2. inject inline.js + inline.css via tabs.executeScript on every event
//   3. the inline.js IIFE is idempotent (globalThis.__mleakInlineInited),
//      so a re-inject is cheap and the "show" push forces a re-mount
//      against the current mail

// True while inline mode is on. Swap to control the icon-click path.
let inlineActive = false;
// The onMessageDisplayed listener we add on enable and remove on disable.
// Kept in a module-level ref so disable can detach it.
let onDisplayedHandler = null;
// Serialises enable/disable so rapid toggles can't race.
let inlineTransition = Promise.resolve();

// Every tab where we've currently got the inline panel showing. Needed so
// we can hide the panel when inline mode is turned off.
const INLINE_ACTIVE_TABS = new Set();

// Drop tracked tabs that have been closed so the set can't grow unbounded
// across a long-running session.
messenger.tabs.onRemoved.addListener((tabId) => {
  INLINE_ACTIVE_TABS.delete(tabId);
});

// Inject inline.js + inline.css into a single tab and nudge it to mount
// the panel for whatever message is currently showing there.
async function injectIntoTab(tabId) {
  try {
    await messenger.tabs.executeScript(tabId, { file: "inline/inline.js" });
    await messenger.tabs.insertCSS(tabId, { file: "inline/inline.css" });
    dlog("info", "bg", "inline script injected into tab", tabId);
  } catch (e) {
    dlog("warn", "bg", "executeScript/insertCSS failed on tab", tabId, "—",
         e && e.message || e);
    // Don't bail — the script may already be there from a previous inject,
    // and the sendMessage below will still nudge a re-mount.
  }
  try {
    await messenger.tabs.sendMessage(tabId, {
      type: "mleak:panel", action: "show" });
    INLINE_ACTIVE_TABS.add(tabId);
    dlog("info", "bg", "panel show sent to tab", tabId);
  } catch (e) {
    dlog("warn", "bg", "sendMessage show failed on tab", tabId, "—",
         e && e.message || e);
  }
}

async function enableInline() {
  if (inlineActive) return;
  inlineActive = true;
  dlog("info", "bg", "enableInline: start");

  onDisplayedHandler = (tab) => { injectIntoTab(tab.id); };
  messenger.messageDisplay.onMessageDisplayed.addListener(onDisplayedHandler);

  try {
    await messenger.messageDisplayAction.setPopup({ popup: "" });
    dlog("info", "bg", "popup cleared — icon click now toggles inline");
  } catch (e) {
    dlog("warn", "bg", "setPopup('') failed:", e && e.message || e);
  }

  // Catch up every mail tab that's already open. Using the same inject
  // path as the onDisplayed listener so behaviour is identical.
  try {
    const tabs = await messenger.tabs.query({});
    let injected = 0;
    for (const tab of tabs) {
      let displayed = null;
      try {
        displayed = await messenger.messageDisplay.getDisplayedMessage(tab.id);
      } catch (_) { continue; }    // not a mail tab
      if (!displayed) continue;
      await injectIntoTab(tab.id);
      injected++;
    }
    dlog("info", "bg", "enableInline: caught up", injected, "mail tab(s)");
  } catch (e) {
    dlog("warn", "bg", "tab enumeration failed:", e && e.message || e);
  }
}

async function disableInline() {
  if (!inlineActive) return;
  inlineActive = false;
  dlog("info", "bg", "disableInline: start");

  if (onDisplayedHandler) {
    messenger.messageDisplay.onMessageDisplayed.removeListener(onDisplayedHandler);
    onDisplayedHandler = null;
  }

  for (const tabId of INLINE_ACTIVE_TABS) {
    try {
      await messenger.tabs.sendMessage(tabId, {
        type: "mleak:panel", action: "hide" });
    } catch (_) { /* frame gone or no listener; fine */ }
  }
  INLINE_ACTIVE_TABS.clear();

  try {
    await messenger.messageDisplayAction.setPopup({ popup: "popup/popup.html" });
    dlog("info", "bg", "popup restored");
  } catch (e) {
    dlog("warn", "bg", "setPopup restore failed:", e && e.message || e);
  }
  dlog("info", "bg", "disableInline: done");
}

function applyInlineState(isOn) {
  // Chain onto the previous transition so we don't run enable and disable
  // concurrently on rapid toggles.
  inlineTransition = inlineTransition.then(
    () => isOn ? enableInline() : disableInline(),
    () => isOn ? enableInline() : disableInline(),
  );
  return inlineTransition;
}

// ---- Settings wiring ------------------------------------------------------

(async () => {
  try {
    const s = await globalThis.OSINTSettings.getAll();
    cacheMax = s.cacheSize;
    // Inline-mode startup path intentionally disabled: the options UI no
    // longer exposes the toggle (see options.js FIELDS comment). Storage
    // may still carry inlineMode=true from a prior install; ignore it.
    // To re-enable, flip `applyInlineState(!!s.inlineMode)` back on here
    // AND restore the `changes.inlineMode` handler in the subscribe
    // block below AND the "Display mode" card in options.html.
  } catch (e) {
    dlog("error", "bg", "startup settings load failed:", e && e.message || e);
  }
})();

globalThis.OSINTSettings.subscribe(changes => {
  try {
    if (changes.cacheSize) {
      cacheMax = changes.cacheSize.newValue ?? 64;
      while (ANALYSIS_CACHE.size > cacheMax) {
        const firstKey = ANALYSIS_CACHE.keys().next().value;
        ANALYSIS_CACHE.delete(firstKey);
      }
    }
    // changes.inlineMode handler intentionally removed — see IIFE comment.
  } catch (e) {
    dlog("error", "bg", "settings onChange handler threw:", e && e.message || e);
  }
});

// ---- Message plumbing -----------------------------------------------------

messenger.runtime.onMessage.addListener(async (msg, sender) => {
  // Shape validation. Today only our own scripts can reach this handler
  // (we don't expose onMessageExternal and don't declare
  // `externally_connectable`), but defence-in-depth against future
  // refactors: assert everything we touch before we touch it.
  if (!msg || typeof msg.type !== "string") return;

  if (msg.type === "debug:log") {
    // Forwarded log line from an inline-script or options page.
    const level = typeof msg.level === "string" ? msg.level : "info";
    const where = typeof msg.where === "string" ? msg.where : "?";
    const args  = Array.isArray(msg.args) ? msg.args : [];
    dlog(level, where, ...args);
    return { ok: true };
  }
  if (msg.type === "clearCache") {
    ANALYSIS_CACHE.clear();
    return { ok: true };
  }
  if (msg.type === "analyze") {
    if (typeof msg.messageId !== "number") {
      return { error: "invalid messageId" };
    }
    return analyzeByMessageId(msg.messageId);
  }
  if (msg.type === "current") {
    // Prefer the sender's tab — the inline-script's "current" means the
    // mail rendered in its own frame, not whatever's globally active.
    // Popup has no sender.tab, so it falls back to the active tab.
    let tabId = sender && sender.tab ? sender.tab.id : null;
    if (tabId == null) {
      const tabs = await messenger.tabs.query({
        active: true, currentWindow: true });
      if (!tabs.length) return { error: "no active tab" };
      tabId = tabs[0].id;
    }
    try {
      const displayed =
        await messenger.messageDisplay.getDisplayedMessage(tabId);
      if (!displayed) return { error: "no message displayed" };
      const result = await analyzeByMessageId(displayed.id);
      // Remember this tab is using the inline panel (helps cleanup when
      // the user turns inline mode off later).
      if (inlineActive) INLINE_ACTIVE_TABS.add(tabId);
      return { messageId: displayed.id, ...result };
    } catch (e) {
      return { error: String(e && e.message || e) };
    }
  }
});

// When inline mode is active, the toolbar icon has an empty popup and
// clicking it fires this event — tell the inline script to toggle.
messenger.messageDisplayAction.onClicked.addListener(async (tab) => {
  if (!inlineActive) return;  // inline mode is off; default popup handles it
  try {
    await messenger.tabs.sendMessage(tab.id, {
      type: "mleak:panel", action: "toggle",
    });
  } catch (e) {
    dlog("warn", "bg", "toggle sendMessage failed on tab", tab.id, "—",
         e && e.message || e);
  }
});
