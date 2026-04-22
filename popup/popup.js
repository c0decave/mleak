/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
"use strict";

// Fall back to the key name if i18n failed to load — keeps the popup
// rendering (with English-ish labels) instead of crashing silently.
const t = (k, s) => globalThis.OSINTi18n?.t?.(k, s) ?? k;

// Applies theme + popup-width + density from stored settings. Root element
// carries the data-* attributes; popup.css has selector variants keyed off
// them so changes take effect without a reload of the detector code.
async function applySettings() {
  const s = await (globalThis.OSINTSettings
                   ? globalThis.OSINTSettings.getAll()
                   : { theme: "auto", width: 500,
                       density: "normal", defaultView: "cards" });
  const root = document.documentElement;
  root.dataset.theme   = s.theme;
  root.dataset.density = s.density;
  root.style.setProperty("--popup-width", s.width + "px");
  document.body.style.width = s.width + "px";
  return s;
}

(async function main() {
  const loading = document.getElementById("loading");
  const content = document.getElementById("content");
  const errorBox = document.getElementById("error");
  const rawBox = document.getElementById("raw");
  const toggle = document.getElementById("toggle-raw");

  const settings = await applySettings();

  let lastResult = null;

  function showRaw() {
    rawBox.textContent = JSON.stringify(lastResult, null, 2);
    rawBox.hidden = false;
    content.hidden = true;
  }
  function showCards() {
    rawBox.hidden = true;
    content.hidden = false;
  }

  toggle.addEventListener("click", () => {
    if (!lastResult) return;
    if (rawBox.hidden) showRaw(); else showCards();
  });

  let result;
  try {
    result = await messenger.runtime.sendMessage({ type: "current" });
  } catch (e) {
    showError(t("bgNotResponding") + e.message);
    return;
  }
  if (!result) {
    showError(t("noResponse"));
    return;
  }
  if (result.error) {
    showError(result.error);
    return;
  }
  lastResult = result;
  loading.hidden = true;
  render(result.summary || result, settings);
  if (settings.defaultView === "raw") showRaw(); else showCards();

  function showError(msg) {
    loading.hidden = true;
    errorBox.textContent = msg;
    errorBox.hidden = false;
  }
})();


// ---------- rendering -----------------------------------------------------

// Cards to hide entirely when the user turned them off in settings. Keyed
// by the section's HTML id; the setting key mirrors the shape `show<Id>`.
const CARD_SETTING = {
  "mua":       "showMua",
  "stack":     "showStack",
  "leaks":     "showLeaks",
  "auth":      "showAuth",
  "integrity": "showIntegrity",
  "date":      "showDate",
  "mime":      "showMime",
};

function render(s, settings) {
  settings = settings || {};
  for (const [id, key] of Object.entries(CARD_SETTING)) {
    const el = document.getElementById(id);
    if (!el) continue;
    // Default-on: if the setting is missing entirely, show the card.
    el.hidden = settings[key] === false;
  }
  if (settings.showMua       !== false) renderMua(s);
  if (settings.showStack     !== false) renderStack(s);
  if (settings.showLeaks     !== false) renderLeaks(s);
  if (settings.showAuth      !== false) renderAuth(s);
  if (settings.showIntegrity !== false) renderIntegrity(s);
  if (settings.showDate      !== false) renderDate(s);
  if (settings.showMime      !== false) renderMime(s);
}

function kvRow(container, key, value, cls = "") {
  const k = document.createElement("div"); k.className = "k"; k.textContent = key;
  const v = document.createElement("div"); v.className = "v " + cls;
  if (typeof value === "string") v.textContent = value;
  else v.appendChild(value);
  container.append(k, v);
}

function empty(el, text) {
  if (text == null) text = t("noData");
  el.replaceChildren();
  const div = document.createElement("div");
  div.className = "empty";
  div.textContent = text;
  el.appendChild(div);
}

function badge(conf) {
  const b = document.createElement("span");
  b.className = "badge " + (conf || "medium");
  b.textContent = conf || "med";
  return b;
}

function renderMua(s) {
  const el = document.getElementById("mua-body");
  el.replaceChildren();
  const sig = s.mua_signals || [];
  if (!sig.length) { empty(el, t("emptyMua")); return; }

  for (const m of sig) {
    const wrap = document.createElement("div");
    wrap.appendChild(badge(m.conf));
    const lbl = document.createElement("span");
    lbl.className = "mono"; lbl.textContent = m.label;
    wrap.appendChild(lbl);
    const src = document.createElement("span");
    src.className = "src"; src.textContent = " ← " + m.src;
    wrap.appendChild(src);
    kvRow(el, " ", wrap);
  }
}

function renderStack(s) {
  const el = document.getElementById("stack-body");
  el.replaceChildren();
  const stacks = s.server_stacks || [];
  if (stacks.length === 0 && !s.tenant_id && !s.delivered_to) {
    empty(el, t("emptyStack"));
    return;
  }
  if (stacks.length) {
    kvRow(el, "Stacks", stacks.join(" + "), "mono");
  }
  if (s.tenant_id) {
    kvRow(el, "M365 Tenant", s.tenant_id, "mono warn");
  }
  if (s.leaks && s.leaks.m365_datacenter) {
    kvRow(el, "DC Region", s.leaks.m365_datacenter, "mono");
  }
  if (s.delivered_to) {
    kvRow(el, "Delivered-To", s.delivered_to, "mono");
  }
  if (s.return_path) {
    kvRow(el, "Return-Path", s.return_path, "mono dim");
  }
  if (s.hop_count != null) {
    // Hop count on its own line, then each relay on a separate line below
    // — vertical layout so long relay chains stay readable at 600 px.
    const wrap = document.createElement("div");
    const count = document.createElement("div");
    count.className = "mono dim";
    count.textContent = `${s.hop_count} hops`;
    wrap.appendChild(count);
    const hops = Array.isArray(s.relay_hops) ? s.relay_hops : null;
    if (hops && hops.length) {
      for (let i = 0; i < hops.length; i++) {
        const line = document.createElement("div");
        line.className = "mono dim relay-hop";
        line.textContent = (i === 0 ? "· " : "→ ") + hops[i];
        wrap.appendChild(line);
      }
    } else if (s.relay_path) {
      const line = document.createElement("div");
      line.className = "mono dim";
      line.textContent = "· " + s.relay_path;
      wrap.appendChild(line);
    }
    kvRow(el, "Relay path", wrap);
  }
}

// Render one "Value — at <by_host> (from <from_host>)" row. When we have
// hop context, callers use this instead of a bare value row so the user
// can see which relay rewrote the leak in.
function leakRow(container, label, value, hop, cls) {
  const wrap = document.createElement("span");
  const main = document.createElement("span");
  main.className = "mono";
  main.textContent = value;
  wrap.appendChild(main);
  if (hop && (hop.by || hop.from)) {
    const ctx = document.createElement("span");
    ctx.className = "src";
    const parts = [];
    if (hop.by)   parts.push("at "   + hop.by);
    if (hop.from && hop.from !== hop.by) parts.push("from " + hop.from);
    ctx.textContent = "  " + parts.join(" · ");
    wrap.appendChild(ctx);
  }
  kvRow(container, label, wrap, cls);
}

function renderLeaks(s) {
  const el = document.getElementById("leaks-body");
  el.replaceChildren();
  let any = false;

  // Internal hostnames: one row per (hostname, relay) pair. Falls back to
  // the plain summary string if the detector didn't return hop context.
  if (Array.isArray(s.internal_hostname_hops) && s.internal_hostname_hops.length) {
    for (const h of s.internal_hostname_hops) {
      leakRow(el, "Internal Host", h.host, h, "bad");
    }
    any = true;
  } else if (s.internal_hostname_leak) {
    kvRow(el, "Internal Host", s.internal_hostname_leak, "mono bad");
    any = true;
  }

  if (Array.isArray(s.private_ip_hops) && s.private_ip_hops.length) {
    for (const h of s.private_ip_hops) {
      leakRow(el, "Private IP", h.ip, h, "bad");
    }
    any = true;
  } else if (s.private_ip_leak) {
    kvRow(el, "Private IP", s.private_ip_leak, "mono bad");
    any = true;
  }

  if (s.leaks && s.leaks.hostname_leak) {
    kvRow(el, "Device Hostname", s.leaks.hostname_leak, "mono warn");
    any = true;
  }
  if (s.leaks && s.leaks.mid) {
    const mid = s.leaks.mid;
    if (mid.datacenter_hint) {
      kvRow(el, "M365 DC", `${mid.datacenter_code} (${mid.datacenter_hint})`, "mono");
      any = true;
    }
    if (mid.internal_hostname && !s.internal_hostname_leak) {
      kvRow(el, "Exchange Host", mid.internal_hostname, "mono warn");
      any = true;
    }
  }
  if (!any) empty(el, t("emptyLeaks"));
}

function renderAuth(s) {
  const el = document.getElementById("auth-body");
  el.replaceChildren();
  const verdicts = s.auth_verdicts;
  if (verdicts && Object.keys(verdicts).length) {
    for (const test of ["spf", "dkim", "dmarc", "arc", "bimi"]) {
      const r = verdicts[test];
      if (!r) continue;
      const cls = (r === "pass" || r === "bestguesspass") ? "mono" :
                  (r === "fail" ? "mono bad" : "mono warn");
      kvRow(el, test.toUpperCase(), r, cls);
    }
    if (verdicts.server) kvRow(el, "Server", verdicts.server, "mono dim");
  }
  const sigs = s.dkim_signatures || [];
  if (sigs.length) {
    for (const sig of sigs) {
      const label = `${sig.domain || "?"}/${sig.selector || "?"}`;
      const span = document.createElement("span");
      span.className = "mono";
      span.textContent = label;
      if (sig.vendor_hint) {
        const h = document.createElement("span");
        h.className = "src"; h.textContent = " (" + sig.vendor_hint + ")";
        span.appendChild(h);
      }
      kvRow(el, "DKIM", span);
    }
  }
  // Crypto findings (PGP / S-MIME / Enigmail / Autocrypt / gateway) live
  // under authentication broadly — sign/encrypt is the message-level
  // counterpart of SPF/DKIM/DMARC at the envelope level.
  const crypto = Array.isArray(s.crypto) ? s.crypto : [];
  const CRYPTO_LABEL = {
    enigmail_version:  "Enigmail",
    enigmail_boundary: "Enigmail",
    boundary_mua_hint: "MIME hint",
    mime_crypto:       "Crypto",
    autocrypt:         "Autocrypt",
    autocrypt_gossip:  "Autocrypt-Gossip",
    openpgp_hint:      "OpenPGP",
    pgp_universal:     "PGP Universal",
    tutanota:          "Tutanota",
    protonmail_header: "ProtonMail",
  };
  for (const c of crypto) {
    // The MUA-card already surfaces Enigmail / Tutanota / ProtonMail via
    // the muaSignals aggregation in detectors.js — don't duplicate those
    // here. Show everything else under Auth.
    if (c.kind === "enigmail_version" || c.kind === "enigmail_boundary" ||
        c.kind === "tutanota" || c.kind === "protonmail_header" ||
        c.kind === "boundary_mua_hint") continue;
    kvRow(el, CRYPTO_LABEL[c.kind] || c.kind, c.value, "mono");
  }

  if (!verdicts && !sigs.length && !crypto.length) empty(el, t("emptyAuth"));
}

function renderIntegrity(s) {
  const el = document.getElementById("integrity-body");
  el.replaceChildren();
  const flags = s.integrity_flags || [];
  if (!flags.length) {
    kvRow(el, t("statusLabel"), t("noAnomaly"), "mono");
    return;
  }
  for (const f of flags) {
    kvRow(el, f.kind.replace(/_/g, " "), f.value, "mono warn");
  }
}

function renderDate(s) {
  const el = document.getElementById("date-body");
  el.replaceChildren();
  const d = s.date || {};
  if (!d.raw) { empty(el, t("emptyDate")); return; }
  kvRow(el, "Raw", d.raw, "mono dim");
  if (d.parsed) {
    // 2026-04-21T08:15:30.123Z  →  2026-04-21 08:15:30 UTC
    const pretty = d.parsed.replace("T", " ").replace(/\.\d{3}Z$/, "").replace(/Z$/, "") + " UTC";
    kvRow(el, "UTC", pretty, "mono");
  }
  if (d.tz_offset_minutes != null) {
    const mins = d.tz_offset_minutes;
    const sign = mins >= 0 ? "+" : "-";
    const abs = Math.abs(mins);
    const tz = `UTC${sign}${String(Math.floor(abs/60)).padStart(2,"0")}:${String(abs%60).padStart(2,"0")}`;
    kvRow(el, "Timezone", tz, "mono");
  }
}

function renderMime(s) {
  const el = document.getElementById("mime-body");
  el.textContent = s.mime_structure || "–";
}
