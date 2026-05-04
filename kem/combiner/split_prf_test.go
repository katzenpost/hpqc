// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package combiner_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/katzenpost/hpqc/kem/combiner"
)

// TestSplitPRFKnownAnswers pins the output of SplitPRF for fixed
// inputs. Any change to the construction (label, length-prefix
// encoding, BLAKE2b parameters, XOR ordering) will be caught here.
func TestSplitPRFKnownAnswers(t *testing.T) {
	cases := []struct {
		name string
		ss   [][]byte
		cct  [][]byte
		want string
	}{
		{
			name: "two components",
			ss: [][]byte{
				bytes.Repeat([]byte{0x01}, 32),
				bytes.Repeat([]byte{0x02}, 32),
			},
			cct: [][]byte{
				bytes.Repeat([]byte{0xaa}, 16),
				bytes.Repeat([]byte{0xbb}, 16),
			},
			want: "f611276ccb1d77e4fd47fbad1f3bfe374f92926a52622c472aa36074bca335da",
		},
		{
			name: "three components",
			ss: [][]byte{
				bytes.Repeat([]byte{0x10}, 8),
				bytes.Repeat([]byte{0x20}, 8),
				bytes.Repeat([]byte{0x30}, 8),
			},
			cct: [][]byte{
				bytes.Repeat([]byte{0xcc}, 4),
				bytes.Repeat([]byte{0xdd}, 4),
				bytes.Repeat([]byte{0xee}, 4),
			},
			want: "e8382ea42bc98091c9fd7f0ec8e1bb860661213bd471ebb1074aef4701b076b6",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := combiner.SplitPRF(tc.ss, tc.cct)
			if err != nil {
				t.Fatalf("SplitPRF: %v", err)
			}
			want, err := hex.DecodeString(tc.want)
			if err != nil {
				t.Fatalf("hex.DecodeString: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("KAT mismatch\n got:  %x\n want: %x", got, want)
			}
		})
	}
}

func TestSplitPRFOutputSize(t *testing.T) {
	out, err := combiner.SplitPRF(
		[][]byte{{0xaa}},
		[][]byte{{0xbb}},
	)
	if err != nil {
		t.Fatalf("SplitPRF: %v", err)
	}
	if len(out) != combiner.SplitPRFOutputSize {
		t.Fatalf("output length %d != OutputSize %d", len(out), combiner.SplitPRFOutputSize)
	}
}

func TestSplitPRFDeterministic(t *testing.T) {
	ss := [][]byte{{0x01, 0x02}, {0x03, 0x04}}
	cct := [][]byte{{0x10}, {0x20}}
	a, err := combiner.SplitPRF(ss, cct)
	if err != nil {
		t.Fatalf("SplitPRF: %v", err)
	}
	b, err := combiner.SplitPRF(ss, cct)
	if err != nil {
		t.Fatalf("SplitPRF: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("SplitPRF should be deterministic for fixed inputs")
	}
}

// TestSplitPRFOrderDependent ensures that swapping component order
// produces a different output. Without this, two callers using the
// same sub-KEMs in opposite orders would derive the same shared key.
func TestSplitPRFOrderDependent(t *testing.T) {
	ssA := [][]byte{{0x01}, {0x02}}
	cctA := [][]byte{{0xaa}, {0xbb}}
	ssB := [][]byte{{0x02}, {0x01}}
	cctB := [][]byte{{0xbb}, {0xaa}}
	a, err := combiner.SplitPRF(ssA, cctA)
	if err != nil {
		t.Fatalf("SplitPRF A: %v", err)
	}
	b, err := combiner.SplitPRF(ssB, cctB)
	if err != nil {
		t.Fatalf("SplitPRF B: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("SplitPRF must be order-sensitive across components")
	}
}

// TestSplitPRFLengthPrefixIsBinding ensures the length-prefix
// encoding prevents (ss, cct) collisions where a byte from ss is
// shifted into the cct concatenation, or two different cct splits
// produce the same byte stream.
func TestSplitPRFLengthPrefixIsBinding(t *testing.T) {
	// Two ciphertext slicings that, when naively concatenated, would
	// produce the same byte stream "0x11 0x22 0x33 0x44".
	a, err := combiner.SplitPRF(
		[][]byte{{0x55}, {0x66}},
		[][]byte{{0x11, 0x22}, {0x33, 0x44}},
	)
	if err != nil {
		t.Fatalf("SplitPRF a: %v", err)
	}
	b, err := combiner.SplitPRF(
		[][]byte{{0x55}, {0x66}},
		[][]byte{{0x11}, {0x22, 0x33, 0x44}},
	)
	if err != nil {
		t.Fatalf("SplitPRF b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("length-prefix encoding failed: differing splits collided")
	}
}

func TestSplitPRFErrNoInputs(t *testing.T) {
	if _, err := combiner.SplitPRF(nil, nil); !errors.Is(err, combiner.ErrNoInputs) {
		t.Fatalf("expected ErrNoInputs, got %v", err)
	}
	if _, err := combiner.SplitPRF([][]byte{}, [][]byte{}); !errors.Is(err, combiner.ErrNoInputs) {
		t.Fatalf("expected ErrNoInputs, got %v", err)
	}
}

func TestSplitPRFErrMismatchedSlices(t *testing.T) {
	_, err := combiner.SplitPRF(
		[][]byte{{0x01}, {0x02}},
		[][]byte{{0xaa}},
	)
	if !errors.Is(err, combiner.ErrMismatchedSlices) {
		t.Fatalf("expected ErrMismatchedSlices, got %v", err)
	}
}

func TestSplitPRFErrEmptyComponent(t *testing.T) {
	cases := []struct {
		name string
		ss   [][]byte
		cct  [][]byte
	}{
		{"empty ss[0]", [][]byte{nil, {0x02}}, [][]byte{{0xaa}, {0xbb}}},
		{"empty ss[1]", [][]byte{{0x01}, {}}, [][]byte{{0xaa}, {0xbb}}},
		{"empty cct[0]", [][]byte{{0x01}, {0x02}}, [][]byte{nil, {0xbb}}},
		{"empty cct[1]", [][]byte{{0x01}, {0x02}}, [][]byte{{0xaa}, {}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := combiner.SplitPRF(tc.ss, tc.cct); !errors.Is(err, combiner.ErrEmptyComponent) {
				t.Fatalf("expected ErrEmptyComponent, got %v", err)
			}
		})
	}
}
