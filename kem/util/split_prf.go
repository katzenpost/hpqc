// SPDX-FileCopyrightText: Copyright (C) 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package util

import (
	"github.com/go-faster/xor"
	"golang.org/x/crypto/blake2b"
)

// SplitPRF can be used with any number of KEMs
// and it implement split PRF KEM combiner as:
//
//	cct := cct1 || cct2 || cct3 || ...
//	return H(ss1 || cct) XOR H(ss2 || cct) XOR H(ss3 || cct)
//
// in order to retain IND-CCA2 security
// as described in KEM Combiners  https://eprint.iacr.org/2018/024.pdf
// by Federico Giacon, Felix Heuer, and Bertram Poettering
func SplitPRF(ss, cct [][]byte) []byte {

	if len(ss) != len(cct) {
		panic("mismatched slices")
	}

	cctcat := []byte{}
	for i := 0; i < len(cct); i++ {
		if cct[i] == nil {
			panic("ciphertext cannot be nil")
		}
		if len(cct[i]) == 0 {
			panic("ciphertext cannot be zero length")
		}
		cctcat = append(cctcat, cct[i]...)
	}

	hashes := make([][]byte, len(ss))
	for i := 0; i < len(ss); i++ {
		h, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		if ss[i] == nil {
			panic("shared secret cannot be nil")
		}
		if len(ss[i]) == 0 {
			panic("shared secret cannot be zero length")
		}
		_, err = h.Write(ss[i])
		if err != nil {
			panic(err)
		}
		_, err = h.Write(cctcat)
		if err != nil {
			panic(err)
		}
		hashes[i] = h.Sum(nil)
	}

	acc := hashes[0]
	for i := 1; i < len(ss); i++ {
		out := make([]byte, 32)
		xor.Bytes(out, acc, hashes[i])
		acc = out
	}
	return acc
}

