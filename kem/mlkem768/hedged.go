// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package mlkem768

import (
	"crypto/rand"

	"filippo.io/mlkem768"

	"github.com/katzenpost/hpqc/kem"
)

// MLKEMHedged768 shares key generation, decapsulation and every wire format
// with MLKEM768; only encapsulation is its own.
var schHedged kem.Scheme = &scheme{name: "MLKEMHedged768", hedged: true}

// SchemeHedged returns the hedged ML-KEM-768 KEM interface.
func SchemeHedged() kem.Scheme { return schHedged }

func encapsulateHedged(ek []byte) (ct, ss []byte, err error) {
	var m [32]byte
	if _, err := rand.Read(m[:]); err != nil {
		return nil, nil, err
	}
	return encapsulateHedgedDerand(ek, m[:])
}

func encapsulateHedgedDerand(ek, m []byte) (ct, ss []byte, err error) {
	return encapsInternal(ek, m)
}

// encapsInternal is FIPS 203 ML-KEM.Encaps_internal (Algorithm 17).
func encapsInternal(ek, m []byte) (ct, ss []byte, err error) {
	return mlkem768.EncapsulateDerand(ek, m)
}
