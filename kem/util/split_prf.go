// SPDX-FileCopyrightText: Copyright (C) 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package util

import (
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/blake2b"

	coreUtil "github.com/katzenpost/hpqc/util"
)

const (
	// splitPRFLabel is a domain-separation tag prepended to every hash
	// input so that this construction cannot collide with any other use
	// of BLAKE2b in the system.
	splitPRFLabel = "splitprf-v1"

	// OutputSize is the length in bytes of the value SplitPRF returns.
	OutputSize = blake2b.Size256
)

var (
	// ErrNoInputs is returned when SplitPRF is called with zero inputs.
	ErrNoInputs = errors.New("split prf: no inputs supplied")

	// ErrEmptyComponent is returned when any inner shared secret or
	// ciphertext slice is nil or zero-length.
	ErrEmptyComponent = errors.New("split prf: input component cannot be nil or empty")

	// ErrMismatchedSlices is returned when len(ss) != len(cct).
	ErrMismatchedSlices = errors.New("split prf: shared-secret and ciphertext slice lengths differ")
)

// SplitPRF implements a domain-separated split-PRF KEM combiner over
// any number of KEMs:
//
//	for each i in 1..n:
//	    hash_i := BLAKE2b-256(
//	        label ||
//	        u32be(len(ss_i))    || ss_i ||
//	        u32be(n)            ||
//	        u32be(len(cct_1))   || cct_1 ||
//	        ...                 ||
//	        u32be(len(cct_n))   || cct_n
//	    )
//	return hash_1 XOR hash_2 XOR ... XOR hash_n
//
// The length-prefixed encoding makes the transcript unambiguous even
// when sub-KEMs have variable-size shared secrets or ciphertexts. The
// construction retains IND-CCA2 security as long as at least one
// sub-KEM is IND-CCA2 secure. See KEM Combiners
// (https://eprint.iacr.org/2018/024.pdf) by Federico Giacon, Felix
// Heuer, and Bertram Poettering.
func SplitPRF(ss, cct [][]byte) ([]byte, error) {
	if len(ss) == 0 || len(cct) == 0 {
		return nil, ErrNoInputs
	}
	if len(ss) != len(cct) {
		return nil, ErrMismatchedSlices
	}

	cctSize := 4
	for i := range ss {
		if len(ss[i]) == 0 || len(cct[i]) == 0 {
			return nil, ErrEmptyComponent
		}
		cctSize += 4 + len(cct[i])
	}

	cctTranscript := make([]byte, 0, cctSize)
	cctTranscript = appendU32BE(cctTranscript, uint32(len(ss)))
	for _, c := range cct {
		cctTranscript = appendU32BE(cctTranscript, uint32(len(c)))
		cctTranscript = append(cctTranscript, c...)
	}

	hashes := make([][]byte, len(ss))
	defer func() {
		for _, h := range hashes {
			coreUtil.ExplicitBzero(h)
		}
	}()

	var lenBuf [4]byte
	for i, s := range ss {
		h := mustNewBlake2b256()
		mustWrite(h, []byte(splitPRFLabel))
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(s)))
		mustWrite(h, lenBuf[:])
		mustWrite(h, s)
		mustWrite(h, cctTranscript)
		hashes[i] = h.Sum(nil)
	}

	out := make([]byte, OutputSize)
	for _, hsh := range hashes {
		for j := 0; j < OutputSize; j++ {
			out[j] ^= hsh[j]
		}
	}
	return out, nil
}

func appendU32BE(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

// mustNewBlake2b256 returns a fresh BLAKE2b-256 hasher. The constructor
// only fails on excessive key length, and we pass a nil key, so any
// error here is a bug in the underlying library.
func mustNewBlake2b256() hash.Hash {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

// mustWrite writes p to h. hash.Hash.Write is contracted never to
// return an error; if one does it is a bug.
func mustWrite(h hash.Hash, p []byte) {
	if _, err := h.Write(p); err != nil {
		panic(err)
	}
}
