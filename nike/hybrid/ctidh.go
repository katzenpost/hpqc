// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !wasm

package hybrid

import (
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh1024"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh2048"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh511"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh512"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/nike/x448"
	"github.com/katzenpost/hpqc/rand"
)

var CTIDH511X25519 nike.Scheme = &Scheme{
	name:   "CTIDH511-X25519",
	first:  ctidh511.Scheme(),
	second: x25519.Scheme(rand.Reader),
}

var CTIDH512X25519 nike.Scheme = &Scheme{
	name:   "CTIDH512-X25519",
	first:  ctidh512.Scheme(),
	second: x25519.Scheme(rand.Reader),
}

var CTIDH512X448 nike.Scheme = &Scheme{
	name:   "CTIDH512-X448",
	second: ctidh512.Scheme(),
	first:  x448.Scheme(rand.Reader),
}

// CTIDH1024X25519 is the legacy hybrid scheme: its name disagrees with
// its wire layout (X25519 first, then CTIDH1024). It is preserved here
// for binary compatibility with deployed code and persisted state. New
// code should use X25519CTIDH1024 (below), which has the same wire
// layout but a name that matches.
var CTIDH1024X25519 nike.Scheme = &Scheme{
	name:   "CTIDH1024-X25519",
	first:  x25519.Scheme(rand.Reader),
	second: ctidh1024.Scheme(),
}

// X25519CTIDH1024 is binary-compatible with CTIDH1024X25519 but its
// name truthfully reflects the wire layout (X25519 first, then
// CTIDH1024). New consumers should prefer this name.
var X25519CTIDH1024 nike.Scheme = &Scheme{
	name:   "X25519-CTIDH1024",
	first:  x25519.Scheme(rand.Reader),
	second: ctidh1024.Scheme(),
}

var CTIDH1024X448 nike.Scheme = &Scheme{
	name:   "CTIDH1024-X448",
	first:  ctidh1024.Scheme(),
	second: x448.Scheme(rand.Reader),
}

var CTIDH2048X448 nike.Scheme = &Scheme{
	name:   "CTIDH2048-X448",
	first:  ctidh2048.Scheme(),
	second: x448.Scheme(rand.Reader),
}
