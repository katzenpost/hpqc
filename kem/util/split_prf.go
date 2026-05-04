// SPDX-FileCopyrightText: Copyright (C) 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package util

import (
	"errors"

	"github.com/go-faster/xor"
	"golang.org/x/crypto/blake2b"
)

var (
	// ErrMismatchedSlices indicates that the shared-secret and ciphertext
	// slices given to SplitPRF have differing lengths.
	ErrMismatchedSlices = errors.New("mismatched slices")

	// ErrEmptyInput indicates an empty shared secret or ciphertext was
	// supplied to SplitPRF.
	ErrEmptyInput = errors.New("input cannot be nil or empty")
)

// SplitPRF can be used with any number of KEMs and implements the split
// PRF KEM combiner as:
//
//	cct := cct1 || cct2 || cct3 || ...
//	return H(ss1 || cct) XOR H(ss2 || cct) XOR H(ss3 || cct)
//
// in order to retain IND-CCA2 security as described in KEM Combiners
// (https://eprint.iacr.org/2018/024.pdf) by Federico Giacon, Felix Heuer,
// and Bertram Poettering.
func SplitPRF(ss, cct [][]byte) ([]byte, error) {
	if len(ss) == 0 {
		return nil, ErrEmptyInput
	}
	if len(ss) != len(cct) {
		return nil, ErrMismatchedSlices
	}

	cctcat := []byte{}
	for _, c := range cct {
		if len(c) == 0 {
			return nil, ErrEmptyInput
		}
		cctcat = append(cctcat, c...)
	}

	hashes := make([][]byte, len(ss))
	for i, s := range ss {
		if len(s) == 0 {
			return nil, ErrEmptyInput
		}
		h, err := blake2b.New256(nil)
		if err != nil {
			return nil, err
		}
		if _, err := h.Write(s); err != nil {
			return nil, err
		}
		if _, err := h.Write(cctcat); err != nil {
			return nil, err
		}
		hashes[i] = h.Sum(nil)
	}

	acc := hashes[0]
	for i := 1; i < len(hashes); i++ {
		out := make([]byte, blake2b.Size256)
		xor.Bytes(out, acc, hashes[i])
		acc = out
	}
	return acc, nil
}

// PairSplitPRF is a split PRF that operates on only two KEMs.
func PairSplitPRF(ss1, ss2, cct1, cct2 []byte) ([]byte, error) {
	return SplitPRF([][]byte{ss1, ss2}, [][]byte{cct1, cct2})
}
