// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package bacap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
)

// saltOf returns a deterministic 32-byte salt filled with b, standing in for a
// VoucherSalt in these tests.
func saltOf(b byte) []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = b
	}
	return s
}

// TestMutateKDFStateLockstep is the central invariant: mutating the write cap
// and taking its read cap yields the same bytes as taking the read cap and
// mutating it. This is what lets the joiner (write side) and the inductor
// (read side) land on the same re-seeded sequence.
func TestMutateKDFStateLockstep(t *testing.T) {
	t.Parallel()

	salt := saltOf(0x11)
	wc, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)

	fromWrite, err := wc.MutateKDFState(salt).ReadCap().MarshalBinary()
	require.NoError(t, err)
	fromRead, err := wc.ReadCap().MutateKDFState(salt).MarshalBinary()
	require.NoError(t, err)

	require.Equal(t, fromWrite, fromRead,
		"mutating the write cap then deriving its read cap must equal mutating the read cap")
}

// TestMutateKDFStateDivergence shows the mutation actually moves the stream: a
// mutated cap's first box ID differs from the un-mutated cap's, and two
// different salts give two different box IDs.
func TestMutateKDFStateDivergence(t *testing.T) {
	t.Parallel()

	readCtx := []byte("pigeonhole context")
	wc, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)

	boxID := func(rc *ReadCap) []byte {
		return rc.GetMessageBoxIndex().BoxIDForContext(rc, readCtx).Bytes()
	}

	orig := boxID(wc.ReadCap())
	mutatedA := boxID(wc.ReadCap().MutateKDFState(saltOf(0x22)))
	mutatedB := boxID(wc.ReadCap().MutateKDFState(saltOf(0x33)))

	require.NotEqual(t, orig, mutatedA, "mutation must change the box ID")
	require.NotEqual(t, mutatedA, mutatedB, "distinct salts must give distinct box IDs")
}

// TestMutateKDFStateRoundTrip writes with the mutated write cap and reads with
// the mutated read cap under the ordinary context, and confirms a reader on the
// un-mutated cap cannot find the box, the confidentiality property the
// VoucherSalt provides.
func TestMutateKDFStateRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := []byte("pigeonhole context")
	salt := saltOf(0x44)
	plaintext := []byte("a message on the salt-mutated stream")

	wc, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)

	sw, err := NewStatefulWriter(wc.MutateKDFState(salt), ctx)
	require.NoError(t, err)
	boxID, ciphertext, sig, err := sw.EncryptNext(plaintext)
	require.NoError(t, err)

	var sigArr [SignatureSize]byte
	copy(sigArr[:], sig)

	sr, err := NewStatefulReader(wc.ReadCap().MutateKDFState(salt), ctx)
	require.NoError(t, err)
	recovered, err := sr.DecryptNext(ctx, boxID, ciphertext, sigArr)
	require.NoError(t, err)
	require.Equal(t, plaintext, recovered)

	// A reader on the un-mutated cap follows a different box sequence, so it
	// does not even recognise the box ID: a voucher snoop is locked out.
	snoop, err := NewStatefulReader(wc.ReadCap(), ctx)
	require.NoError(t, err)
	_, err = snoop.DecryptNext(ctx, boxID, ciphertext, sigArr)
	require.Error(t, err)
}
