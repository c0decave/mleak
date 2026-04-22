#!/usr/bin/env bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# SPDX-License-Identifier: MPL-2.0
# Pack the extension into a .xpi (= .zip) at repo-root/dist/.
# Thunderbird loads unsigned XPIs only via "temporary add-on" or with a
# whitelisted signing policy. For production use AMO or a self-hosted update URL.

set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out_dir="$here/dist"
mkdir -p "$out_dir"

name="$(python3 -c "import json,sys; print(json.load(open('$here/manifest.json'))['short_name'].lower().replace(' ','-'))")"
ver="$(python3 -c "import json; print(json.load(open('$here/manifest.json'))['version'])")"
xpi="$out_dir/${name}-${ver}.xpi"

rm -f "$xpi"
cd "$here"

# Use zip if available, otherwise fall back to python stdlib zipfile.
if command -v zip >/dev/null; then
    zip -qr "$xpi" \
        manifest.json \
        background.js \
        lib \
        popup \
        options \
        inline \
        debug \
        icons \
        _locales \
        README.md \
        README_DE.md \
        README_EN.md \
        README_ES.md \
        README_ZH.md \
        README_HI.md \
        README_PT.md \
        README_PL.md \
        LICENSE
else
    python3 - "$xpi" "$here" <<'PY'
import os, sys, zipfile
out, base = sys.argv[1], sys.argv[2]
include = ["manifest.json", "background.js",
           "README.md", "README_DE.md", "README_EN.md", "README_ES.md",
           "README_ZH.md", "README_HI.md", "README_PT.md", "README_PL.md",
           "LICENSE"]
dirs = ["lib", "popup", "options", "inline", "debug", "icons", "_locales"]
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
    for f in include:
        zf.write(os.path.join(base, f), f)
    for d in dirs:
        for root, _, files in os.walk(os.path.join(base, d)):
            for fn in files:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, base)
                zf.write(full, rel)
print("built:", out)
PY
fi

echo "$xpi"
ls -la "$xpi"
python3 -c "import zipfile,sys; z=zipfile.ZipFile(sys.argv[1]); print(f'{len(z.namelist())} entries'); [print(f'  {n}') for n in z.namelist()]" "$xpi"
