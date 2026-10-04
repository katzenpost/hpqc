#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
deb=golang-github-katzenpost-hpqc-dev
a=$(sha256sum "$root"/dist/${deb}_*.deb | cut -d' ' -f1)

rm -rf /tmp/rb
cp -a "$root" /tmp/rb
cd /tmp/rb
rm -rf dist
packaging/debian/build.sh
b=$(sha256sum /tmp/rb/dist/${deb}_*.deb | cut -d' ' -f1)

printf 'first  %s\nsecond %s\n' "$a" "$b"
test "$a" = "$b"
