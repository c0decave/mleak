/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * SPDX-License-Identifier: MPL-2.0
 */
// Mailing-list / MLM detector. Uses List-* standards plus implementation
// markers emitted by common mailing-list managers.

"use strict";

(() => {
const { getHeader, finding, CONF } = globalThis.OSINTUtil;

const MLM_MARKERS = [
  ["X-Mailman-Version", "Mailman"],
  ["X-Mailman-Rule-Hits", "Mailman 3 / HyperKitty"],
  ["X-BeenThere", "Mailman"],
  ["X-List-Administrivia", "Mailman"],
  ["X-List-Received-Date", "Mailman archive"],
  ["X-Sympa-To", "Sympa"],
  ["X-Sympa-From", "Sympa"],
  ["X-Sequence", "LISTSERV / ezmlm"],
  ["X-List", "ezmlm / qmail"],
  ["X-Mailing-List", "Mailing list"],
  ["Mailing-List", "Mailing list"],
  ["X-Google-Group-Id", "Google Groups"],
  ["X-Listserver", "LISTSERV"],
  ["X-LSV-ListID", "LISTSERV"],
  ["X-Majordomo-Version", "Majordomo"],
  ["List-Software", "Mailing list software"],
];

function shortValue(value, max = 300) {
  const s = String(value == null ? "" : value);
  return s.length > max ? s.slice(0, max) + "...[truncated]" : s;
}

function markerLabel(header, value, fallback) {
  const low = String(value || "").toLowerCase();
  if (header === "Mailing-List" && low.includes("ezmlm")) return "ezmlm (qmail)";
  if (header === "X-Mailing-List" && low.includes("google.com")) return "Google Groups";
  if (low.includes("mailman")) return "Mailman";
  if (low.includes("sympa")) return "Sympa";
  if (low.includes("listserv")) return "LISTSERV";
  if (low.includes("ezmlm")) return "ezmlm (qmail)";
  return fallback;
}

function detectMailingList(headers) {
  const markers = [];
  for (const [header, fallback] of MLM_MARKERS) {
    const value = getHeader(headers, header);
    if (!value) continue;
    markers.push({
      header,
      label: markerLabel(header, value, fallback),
      value: shortValue(value, 200),
    });
  }

  const listId = getHeader(headers, "List-Id");
  const listPost = getHeader(headers, "List-Post");
  const listUnsub = getHeader(headers, "List-Unsubscribe");
  const precedence = getHeader(headers, "Precedence");

  if (!markers.length && !listId && !listPost && !listUnsub) return [];

  const label = markers.length ? markers[0].label : "unknown MLM";
  const out = [finding("mailing_list", "mlm_software",
                       label, markers.length ? CONF.HIGH : CONF.MEDIUM, {
    leaks: {
      list_id: shortValue(listId) || null,
      list_post: shortValue(listPost) || null,
      list_unsubscribe: shortValue(listUnsub) || null,
      precedence: shortValue(precedence) || null,
      markers,
    },
    notes: ["Mailing-list context can explain From/Sender/Reply-To rewrites."]
  })];

  return out;
}

globalThis.OSINTDetect = globalThis.OSINTDetect || {};
globalThis.OSINTDetect.mailingList = detectMailingList;

})();
