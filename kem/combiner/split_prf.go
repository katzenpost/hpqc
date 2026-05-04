// SPDX-FileCopyrightText: Copyright (C) 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package combiner

import (
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/blake2b"

	coreUtil "github.com/katzenpost/hpqc/util"
)

const (
	// splitPRFLabel is a domain-separation tag for this PRF construction.
	splitPRFLabel = "splitprf-v1"

	// SplitPRFOutputSize is the length in bytes of the value SplitPRF
	// returns.
	SplitPRFOutputSize = blake2b.Size256
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

// SplitPRF implements the standard-model PRF-then-XOR core function
// of Giacon, Heuer & Poettering (Lemma 8 of "KEM Combiners",
// https://eprint.iacr.org/2018/024.pdf), instantiated with BLAKE2b-256
// in keyed mode as the per-component PRF F:
//
//	key_i  := BLAKE2b-256(unkeyed)(ss_i)
//	hash_i := BLAKE2b-256(
//	             key = key_i,
//	             msg = "splitprf-v1" || u32be(n) ||
//	                   u32be(len(cct_1)) || cct_1 ||
//	                   ...                ||
//	                   u32be(len(cct_n)) || cct_n
//	         )
//	return hash_1 XOR hash_2 XOR ... XOR hash_n
//
// The pre-hash key derivation handles BLAKE2b's 64-byte keyed-mode
// cap so the construction accepts shared secrets of any length.
//
// By Theorem 1 of the paper the resulting combined KEM retains
// IND-CCA2 security as long as at least one ingredient KEM is
// IND-CCA2 secure. The length-prefixed ciphertext encoding makes the
// message portion of the transcript unambiguous regardless of sub-KEM
// ciphertext sizes.
func SplitPRF(ss, cct [][]byte) ([]byte, error) {
	if len(ss) == 0 || len(cct) == 0 {
		return nil, ErrNoInputs
	}
	if len(ss) != len(cct) {
		return nil, ErrMismatchedSlices
	}

	msgSize := len(splitPRFLabel) + 4
	for i := range ss {
		if len(ss[i]) == 0 || len(cct[i]) == 0 {
			return nil, ErrEmptyComponent
		}
		msgSize += 4 + len(cct[i])
	}

	msg := make([]byte, 0, msgSize)
	msg = append(msg, splitPRFLabel...)
	msg = appendU32BE(msg, uint32(len(ss)))
	for _, c := range cct {
		msg = appendU32BE(msg, uint32(len(c)))
		msg = append(msg, c...)
	}

	hashes := make([][]byte, len(ss))
	defer func() {
		for _, h := range hashes {
			coreUtil.ExplicitBzero(h)
		}
	}()

	for i, s := range ss {
		key := deriveKey(s)
		h := mustNewBlake2b256(key)
		coreUtil.ExplicitBzero(key)
		mustWrite(h, msg)
		hashes[i] = h.Sum(nil)
	}

	out := make([]byte, SplitPRFOutputSize)
	for _, hsh := range hashes {
		for j := 0; j < SplitPRFOutputSize; j++ {
			out[j] ^= hsh[j]
		}
	}
	return out, nil
}

// deriveKey shrinks an arbitrary-length shared secret to a 32-byte
// BLAKE2b key via an unkeyed BLAKE2b-256 hash. Required because
// BLAKE2b's keyed mode caps the key at 64 bytes and our sub-KEMs are
// not constrained to that.
func deriveKey(ss []byte) []byte {
	h := mustNewBlake2b256(nil)
	mustWrite(h, ss)
	return h.Sum(nil)
}

func appendU32BE(b []byte, v uint32) []byte {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}

// mustNewBlake2b256 returns a fresh BLAKE2b-256 hasher. The constructor
// only fails when a key longer than 64 bytes is supplied; callers
// inside this package never do, so any error is a bug.
func mustNewBlake2b256(key []byte) hash.Hash {
	h, err := blake2b.New256(key)
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
