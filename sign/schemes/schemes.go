// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package schemes

import (
	"strings"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/sign/hybrid"
	"github.com/katzenpost/hpqc/sign/sphincsplus"
)

var allSchemes = [...]sign.Scheme{
	ed25519.Scheme(),
	sphincsplus.Scheme(),
	hybrid.New("Ed25519 Sphincs+", ed25519.Scheme(), sphincsplus.Scheme()),
}

var allSchemeNames map[string]sign.Scheme

func init() {
	allSchemeNames = make(map[string]sign.Scheme)
	for _, scheme := range allSchemes {
		allSchemeNames[strings.ToLower(scheme.Name())] = scheme
	}
}

// ByName returns the NIKE scheme by string name.
func ByName(name string) sign.Scheme {
	ret := allSchemeNames[strings.ToLower(name)]
	return ret
}

// All returns all NIKE schemes supported.
func All() []sign.Scheme {
	a := allSchemes
	return a[:]
}
