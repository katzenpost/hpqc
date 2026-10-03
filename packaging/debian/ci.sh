#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
debs=${DEBS_DIR:-/tmp/debs}
mkdir -p "$debs"
cd "$root"

apt update
apt install -y --no-install-recommends \
    build-essential debhelper dh-golang dpkg-dev golang-any ca-certificates

packaging/debian/build.sh
cp dist/golang-*.deb "$debs"/

apt install -y "$debs"/golang-*.deb
packaging/debian/test.sh
packaging/debian/assert-reproducible.sh
