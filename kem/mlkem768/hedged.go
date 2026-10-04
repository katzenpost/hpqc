// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package mlkem768

import (
	"crypto/rand"
	"crypto/sha3"

	"filippo.io/mlkem768"

	"github.com/katzenpost/hpqc/kem"
)

// MLKEMHedged768 restores round-3 Kyber's m ← H(m) pre-hash, which FIPS 203
// dropped: the sampled message is hashed with SHA3-256 before it derives the
// coins or becomes the encrypted plaintext, hedging against a weak or
// structured RNG. Only encapsulation differs from MLKEM768; key generation,
// decapsulation and every wire format are shared. It is not FIPS 203: for a
// given m its encapsulation output differs, though key generation and the
// post-hash encapsulation core still match the NIST ACVP vectors.
//
// This matches CryptWalker's formally verified encaps768Hedged
// (CryptWalker/KEM/MLKEMHedged/MLKEMHedged768.lean).
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
	mh := sha3.Sum256(m)
	return encapsInternal(ek, mh[:])
}

// encapsInternal is FIPS 203 ML-KEM.Encaps_internal (Algorithm 17).
func encapsInternal(ek, m []byte) (ct, ss []byte, err error) {
	return mlkem768.EncapsulateDerand(ek, m)
}
