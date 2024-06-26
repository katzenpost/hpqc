// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package hybrid

import (
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh1024"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh2048"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh511"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh512"
	"github.com/katzenpost/hpqc/nike/x25519"
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

var CTIDH1024X25519 nike.Scheme = &Scheme{
	name:   "CTIDH1024-X25519",
	first:  ctidh1024.Scheme(),
	second: x25519.Scheme(rand.Reader),
}

var CTIDH2048X25519 nike.Scheme = &Scheme{
	name:   "CTIDH2048-X25519",
	first:  ctidh2048.Scheme(),
	second: x25519.Scheme(rand.Reader),
}
