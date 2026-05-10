// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package schemes

import (
	"strings"

	"github.com/katzenpost/circl/sign/ed448"
	"github.com/katzenpost/circl/sign/eddilithium2"
	"github.com/katzenpost/circl/sign/eddilithium3"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/circlsign"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/sign/falcon"
	"github.com/katzenpost/hpqc/sign/hybrid"
	"github.com/katzenpost/hpqc/sign/mldsa"
	"github.com/katzenpost/hpqc/sign/sphincsplus"
)

var potentialSchemes = [...]sign.Scheme{
	// post quantum
	sphincsplus.Scheme(),
	falcon.SchemePadded512(),
	falcon.SchemePadded1024(),

	// post quantum hybrids
	hybrid.Ed25519Sphincs,
	hybrid.Ed25519SphincsLegacy,
	hybrid.Ed448Sphincs,
}

var allSchemes = []sign.Scheme{
	// classical
	ed25519.Scheme(),
	circlsign.FromCircl(ed448.Scheme()),

	// post quantum
	mldsa.Scheme44(),
	mldsa.Scheme65(),
	mldsa.Scheme87(),

	// hybrid post quantum
	circlsign.FromCircl(eddilithium2.Scheme()),
	circlsign.FromCircl(eddilithium3.Scheme()),
	hybrid.MLDSA44Ed25519,
	hybrid.MLDSA65Ed25519,
	hybrid.MLDSA87Ed25519,
}

var allSchemeNames map[string]sign.Scheme

func init() {
	allSchemeNames = make(map[string]sign.Scheme)

	for _, scheme := range potentialSchemes {
		if scheme != nil {
			allSchemes = append(allSchemes, scheme)
		}
	}
	for _, scheme := range allSchemes {
		allSchemeNames[strings.ToLower(scheme.Name())] = scheme
	}
}

// ByName returns the NIKE scheme by string name.
func ByName(name string) sign.Scheme {
	ret := allSchemeNames[strings.ToLower(name)]
	return ret
}

// All returns all signature schemes supported.
func All() []sign.Scheme {
	a := allSchemes
	return a[:]
}
