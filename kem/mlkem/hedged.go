// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package mlkem

import (
	"crypto/rand"
	"crypto/sha3"
)

// encapsulate is FIPS 203 ML-KEM.Encaps (Algorithm 20): Encaps_internal on a
// fresh random m.
func (s *scheme) encapsulate(ek []byte) (ct, ss []byte, err error) {
	var m [32]byte
	if _, err := rand.Read(m[:]); err != nil {
		return nil, nil, err
	}
	return s.encapsulateDerand(ek, m[:])
}

// encapsulateDerand is Encaps_internal(ek, m), or for the hedged schemes
// Encaps_internal(ek, SHA3-256(m)): round-3 Kyber's pre-hash, which FIPS 203
// dropped, hedging against a weak or structured RNG. This matches
// Cryptlib's verified encapsHedged (Cryptlib/Primitives/KEM/MLKEMHedged).
func (s *scheme) encapsulateDerand(ek, m []byte) (ct, ss []byte, err error) {
	if s.hedged {
		mh := sha3.Sum256(m)
		m = mh[:]
	}
	return s.params.encaps(ek, m)
}
