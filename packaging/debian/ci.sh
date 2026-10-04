#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
debs=${DEBS_DIR:-/tmp/debs}
mkdir -p "$debs"
cd "$root"

need_tools=
for tool in dpkg-buildpackage dh go; do
    command -v "$tool" >/dev/null || need_tools=1
done
test -f /usr/share/perl5/Debian/Debhelper/Buildsystem/golang.pm \
    || need_tools=1
if [ -n "$need_tools" ]; then
    apt update
    apt install -y --no-install-recommends \
        build-essential debhelper dh-golang dpkg-dev golang-any \
        ca-certificates
fi

packaging/debian/build.sh
cp dist/golang-*.deb "$debs"/

apt update
apt install -y "$debs"/golang-*.deb
packaging/debian/test.sh
packaging/debian/assert-reproducible.sh
