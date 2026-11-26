#!/usr/bin/env bash
# Składa paczkę do wgrania przez FTP: dist/domena/ = zawartość katalogu domeny na hostingu
# (DirectAdmin: /home/admin/domains/<domena>/). public/ -> public_html/, kod obok, poza webrootem.
# Nie zawiera config.php ani bazy; config tworzy: BOREDLINKS_CONFIG=dist/domena/config.php php bin/setup.php
set -euo pipefail
cd "$(dirname "$0")/.."

out=dist/domena
rm -rf dist
mkdir -p "$out/public_html" "$out/bin"
cp -R public/. "$out/public_html/"
cp -R src pages lang "$out/"
cp bin/setup.php bin/cleanup.php "$out/bin/"
find dist -name .DS_Store -delete
echo "Paczka: $out"
(cd "$out" && find . -type f | sort)
