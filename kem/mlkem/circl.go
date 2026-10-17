// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package mlkem

import (
	"github.com/katzenpost/circl/kem/mlkem/mlkem1024"
	"github.com/katzenpost/circl/kem/mlkem/mlkem512"
)

// The FIPS 203 algorithms come from circl; this package only arranges them.

var params512 = &params{
	name:           "MLKEM512",
	hedgedName:     "MLKEMHedged512",
	publicKeySize:  mlkem512.PublicKeySize,
	ciphertextSize: mlkem512.CiphertextSize,
	keyGen: func(seed []byte) ([]byte, func(ct []byte) []byte) {
		pk, sk := mlkem512.NewKeyFromSeed(seed)
		ek := make([]byte, mlkem512.PublicKeySize)
		pk.Pack(ek)
		return ek, func(ct []byte) []byte {
			ss := make([]byte, mlkem512.SharedKeySize)
			sk.DecapsulateTo(ss, ct)
			return ss
		}
	},
	encaps: func(ek, m []byte) ([]byte, []byte, error) {
		var pk mlkem512.PublicKey
		if err := pk.Unpack(ek); err != nil {
			return nil, nil, err
		}
		ct := make([]byte, mlkem512.CiphertextSize)
		ss := make([]byte, mlkem512.SharedKeySize)
		pk.EncapsulateTo(ct, ss, m)
		return ct, ss, nil
	},
}

var params1024 = &params{
	name:           "MLKEM1024",
	hedgedName:     "MLKEMHedged1024",
	publicKeySize:  mlkem1024.PublicKeySize,
	ciphertextSize: mlkem1024.CiphertextSize,
	keyGen: func(seed []byte) ([]byte, func(ct []byte) []byte) {
		pk, sk := mlkem1024.NewKeyFromSeed(seed)
		ek := make([]byte, mlkem1024.PublicKeySize)
		pk.Pack(ek)
		return ek, func(ct []byte) []byte {
			ss := make([]byte, mlkem1024.SharedKeySize)
			sk.DecapsulateTo(ss, ct)
			return ss
		}
	},
	encaps: func(ek, m []byte) ([]byte, []byte, error) {
		var pk mlkem1024.PublicKey
		if err := pk.Unpack(ek); err != nil {
			return nil, nil, err
		}
		ct := make([]byte, mlkem1024.CiphertextSize)
		ss := make([]byte, mlkem1024.SharedKeySize)
		pk.EncapsulateTo(ct, ss, m)
		return ct, ss, nil
	},
}
