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
  if (!validMessageId(id)) return { error: "invalid messageId" };
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

// ---- Body-inline lifecycle -----------------------------------------------
//
// The durable path is programmatic messageDisplayScripts registration: it
// injects inline.js into newly-opened message display frames without relying
// on per-tab executeScript. We still keep executeScript as a best-effort
// catch-up for mails that were already open when the setting was enabled.

// True while bodyInline display mode is on. Swap to control the icon-click path.
let bodyInlineActive = false;
// The onMessageDisplayed listener we add on enable and remove on disable.
// Kept in a module-level ref so disable can detach it.
let onDisplayedHandler = null;
// Serialises enable/disable so rapid toggles can't race.
let bodyInlineTransition = Promise.resolve();
// RegisteredMessageDisplayScript handle returned by messageDisplayScripts.register().
let registeredBodyInlineScript = null;
const DEBUG_LEVELS = new Set(["error", "warn", "info", "debug"]);

// Every tab where we've currently got the inline panel showing. Needed so
// we can hide the panel when bodyInline mode is turned off.
const INLINE_ACTIVE_TABS = new Set();

// Drop tracked tabs that have been closed so the set can't grow unbounded
// across a long-running session.
messenger.tabs.onRemoved.addListener((tabId) => {
  INLINE_ACTIVE_TABS.delete(tabId);
});

function normalizeDisplayMode(mode) {
  const allowed = globalThis.OSINTSettings.STRING_ENUMS.displayMode;
  return allowed.has(mode) ? mode : "popup";
}

function validMessageId(id) {
  return Number.isSafeInteger(id) && id >= 0;
}

function validTabId(id) {
  return Number.isSafeInteger(id) && id >= 0;
}

function shortString(value, max = 1000) {
  const s = String(value == null ? "" : value);
  return s.length > max ? s.slice(0, max) + "...[truncated]" : s;
}

function sanitizeDebugArgs(args) {
  if (!Array.isArray(args)) return [];
  return args.slice(0, 8).map(a => {
    if (a == null || typeof a === "number" || typeof a === "boolean") return a;
    if (typeof a === "string") return shortString(a);
    if (a && typeof a === "object" && typeof a.message === "string") {
      return shortString(a.message);
    }
    return `[${Array.isArray(a) ? "Array" : "Object"}]`;
  });
}

async function registerBodyInlineScript() {
  if (registeredBodyInlineScript) return;
  if (!messenger.messageDisplayScripts ||
      typeof messenger.messageDisplayScripts.register !== "function") {
    dlog("warn", "bg", "messageDisplayScripts.register unavailable; using executeScript fallback only");
    return;
  }
  try {
    registeredBodyInlineScript = await messenger.messageDisplayScripts.register({
      js: [{ file: "inline/inline.js" }],
      css: [{ file: "inline/inline.css" }],
    });
    dlog("info", "bg", "bodyInline messageDisplayScript registered");
  } catch (e) {
    dlog("warn", "bg", "messageDisplayScripts.register failed:", e && e.message || e);
  }
}

async function unregisterBodyInlineScript() {
  if (!registeredBodyInlineScript) return;
  try {
    await registeredBodyInlineScript.unregister();
    dlog("info", "bg", "bodyInline messageDisplayScript unregistered");
  } catch (e) {
    dlog("warn", "bg", "messageDisplayScript unregister failed:", e && e.message || e);
  } finally {
    registeredBodyInlineScript = null;
  }
}

async function sendPanelShow(tabId, missingLevel = "warn") {
  if (!validTabId(tabId)) return false;
  try {
    await messenger.tabs.sendMessage(tabId, {
      type: "mleak:panel", action: "show" });
    INLINE_ACTIVE_TABS.add(tabId);
    dlog("info", "bg", "panel show sent to tab", tabId);
    return true;
  } catch (e) {
    dlog(missingLevel, "bg", "sendMessage show failed on tab", tabId, "—",
         e && e.message || e);
    return false;
  }
}

// Inject inline.js + inline.css into a single tab and nudge it to mount
// the panel for whatever message is currently showing there.
async function injectIntoTab(tabId) {
  if (!validTabId(tabId)) return;
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
  await sendPanelShow(tabId, "warn");
}

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function showOrInjectIntoTab(tabId, opts = {}) {
  if (!validTabId(tabId)) return;
  const allowInject = opts.allowInject !== false;
  if (await sendPanelShow(tabId, "info")) return;
  // When messageDisplayScripts.register is active, a freshly displayed
  // message can fire onMessageDisplayed just before inline.js has finished
  // wiring runtime.onMessage. Give the registered script a short chance to
  // come online before falling back to explicit executeScript/insertCSS.
  if (registeredBodyInlineScript) {
    await delay(250);
    if (await sendPanelShow(tabId, "info")) return;
  }
  if (!allowInject) return;
  await injectIntoTab(tabId);
}

async function enableBodyInline() {
  if (bodyInlineActive) return;
  bodyInlineActive = true;
  dlog("info", "bg", "enableBodyInline: start");

  await registerBodyInlineScript();

  onDisplayedHandler = (tab) => {
    showOrInjectIntoTab(tab.id, {
      allowInject: !registeredBodyInlineScript,
    });
  };
  messenger.messageDisplay.onMessageDisplayed.addListener(onDisplayedHandler);

  try {
    await messenger.messageDisplayAction.setPopup({ popup: "" });
    dlog("info", "bg", "popup cleared — icon click now toggles bodyInline panel");
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
      await showOrInjectIntoTab(tab.id);
      injected++;
    }
    dlog("info", "bg", "enableBodyInline: caught up", injected, "mail tab(s)");
  } catch (e) {
    dlog("warn", "bg", "tab enumeration failed:", e && e.message || e);
  }
}

async function disableBodyInline() {
  if (!bodyInlineActive) return;
  bodyInlineActive = false;
  dlog("info", "bg", "disableBodyInline: start");

  if (onDisplayedHandler) {
    messenger.messageDisplay.onMessageDisplayed.removeListener(onDisplayedHandler);
    onDisplayedHandler = null;
  }

  await unregisterBodyInlineScript();

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
  dlog("info", "bg", "disableBodyInline: done");
}

function applyBodyInlineState(isOn) {
  // Chain onto the previous transition so we don't run enable and disable
  // concurrently on rapid toggles.
  bodyInlineTransition = bodyInlineTransition.then(
    () => isOn ? enableBodyInline() : disableBodyInline(),
    () => isOn ? enableBodyInline() : disableBodyInline(),
  );
  return bodyInlineTransition;
}

function applyDisplayMode(mode) {
  const displayMode = normalizeDisplayMode(mode);
  if (displayMode === "headerInline") {
    dlog("warn", "bg", "headerInline display mode is reserved for a future experiment; popup/body inline only in this build");
  }
  return applyBodyInlineState(displayMode === "bodyInline");
}

// ---- Settings wiring ------------------------------------------------------

(async () => {
  try {
    const s = await globalThis.OSINTSettings.getAll();
    cacheMax = s.cacheSize;
    await applyDisplayMode(s.displayMode);
  } catch (e) {
    dlog("error", "bg", "startup settings load failed:", e && e.message || e);
  }
})();

globalThis.OSINTSettings.subscribe(changes => {
  try {
    if (changes.cacheSize) {
      const settings = globalThis.OSINTSettings.sanitize({
        ...globalThis.OSINTSettings.DEFAULTS,
        cacheSize: changes.cacheSize.newValue,
      });
      cacheMax = settings.cacheSize;
      while (ANALYSIS_CACHE.size > cacheMax) {
        const firstKey = ANALYSIS_CACHE.keys().next().value;
        ANALYSIS_CACHE.delete(firstKey);
      }
    }
    if (changes.displayMode) {
      applyDisplayMode(changes.displayMode.newValue);
    }
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
    const level = DEBUG_LEVELS.has(msg.level) ? msg.level : "info";
    const where = shortString(
      typeof msg.where === "string" ? msg.where : "?",
      40).replace(/[^A-Za-z0-9_.:-]/g, "_");
    const args  = sanitizeDebugArgs(msg.args);
    dlog(level, where, ...args);
    return { ok: true };
  }
  if (msg.type === "clearCache") {
    ANALYSIS_CACHE.clear();
    return { ok: true };
  }
  if (msg.type === "analyze") {
    if (!validMessageId(msg.messageId)) {
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
      if (!validMessageId(displayed.id)) return { error: "invalid messageId" };
      const result = await analyzeByMessageId(displayed.id);
      // Remember this tab is using the inline panel (helps cleanup when
      // the user turns bodyInline mode off later).
      if (bodyInlineActive) INLINE_ACTIVE_TABS.add(tabId);
      return { messageId: displayed.id, ...result };
    } catch (e) {
      return { error: String(e && e.message || e) };
    }
  }
});

// When bodyInline mode is active, the toolbar icon has an empty popup and
// clicking it fires this event — tell the inline script to toggle.
messenger.messageDisplayAction.onClicked.addListener(async (tab) => {
  if (!bodyInlineActive) return;  // popup mode is offloaded to default popup
  if (!tab || !validTabId(tab.id)) return;
  try {
    await messenger.tabs.sendMessage(tab.id, {
      type: "mleak:panel", action: "toggle",
    });
  } catch (e) {
    dlog("warn", "bg", "toggle sendMessage failed on tab", tab.id, "—",
         e && e.message || e);
  }
});
