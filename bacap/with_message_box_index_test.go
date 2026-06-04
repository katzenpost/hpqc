// SPDX-FileCopyrightText: © 2026 Katzenpost dev team
// SPDX-License-Identifier: AGPL-3.0-only

package bacap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
)

// TestWithMessageBoxIndex checks that re-basing a cap to a chosen index sets the
// cap's embedded index (the one the StatefulReader/Writer constructors consume),
// leaves the source cap untouched, and rejects a nil index.
func TestWithMessageBoxIndex(t *testing.T) {
	t.Parallel()

	ctx := []byte("with-index-ctx")
	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	rcap := owner.ReadCap()

	origRead := rcap.GetMessageBoxIndex()
	origWrite := owner.GetMessageBoxIndex()

	// A target a few steps ahead of the cap's start.
	target := rcap.GetMessageBoxIndex()
	for i := 0; i < 3; i++ {
		target, err = target.NextIndex()
		require.NoError(t, err)
	}

	rc2 := rcap.WithMessageBoxIndex(target)
	wc2 := owner.WithMessageBoxIndex(target)

	// The re-based caps report target as their embedded index...
	require.Equal(t, target, rc2.GetMessageBoxIndex())
	require.Equal(t, target, wc2.GetMessageBoxIndex())

	// ...the sources are unchanged...
	require.Equal(t, origRead, rcap.GetMessageBoxIndex())
	require.Equal(t, origWrite, owner.GetMessageBoxIndex())
	require.NotEqual(t, target.Idx64, origRead.Idx64)

	// ...and the embedded index is a copy, not aliased to target.
	require.NotSame(t, target, rc2.GetMessageBoxIndex())

	// A reader/writer built from the re-based caps (which read the cap's embedded
	// index) meet at target: a message written there decrypts there.
	reader, err := NewStatefulReader(rc2, ctx)
	require.NoError(t, err)
	writer, err := NewStatefulWriter(wc2, ctx)
	require.NoError(t, err)

	msg := []byte("written at the re-based position")
	boxID, ciphertext, sigraw, err := writer.EncryptNext(msg)
	require.NoError(t, err)

	expectedBoxID, err := reader.NextBoxID()
	require.NoError(t, err)
	require.Equal(t, expectedBoxID[:], boxID[:])

	sig := [SignatureSize]byte{}
	copy(sig[:], sigraw)
	plaintext, err := reader.DecryptNext(ctx, boxID, ciphertext, sig)
	require.NoError(t, err)
	require.Equal(t, msg, plaintext)
}

func TestWithMessageBoxIndexNilPanics(t *testing.T) {
	t.Parallel()

	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	require.Panics(t, func() { owner.WithMessageBoxIndex(nil) })
	require.Panics(t, func() { owner.ReadCap().WithMessageBoxIndex(nil) })
}
