#!/bin/sh
set -eu

root=/usr/share/gocode/src/github.com/katzenpost/hpqc
test -d "$root"
test -f "$root/go.mod"
test -d "$root/kem"
test -d "$root/nike"
test -d "$root/sign"
test -d "$root/bacap"
