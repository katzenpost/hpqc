#!/bin/sh
set -eu

cd "$(dirname "$0")/../.."
dpkg-buildpackage -b -uc -us "$@"
mkdir -p dist
mv ../golang-github-katzenpost-hpqc-dev_*.deb dist/
sha256sum dist/golang-github-katzenpost-hpqc-dev_*.deb
