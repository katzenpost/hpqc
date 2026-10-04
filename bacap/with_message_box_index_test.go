// SPDX-FileCopyrightText: © 2026 Katzenpost dev team
// SPDX-License-Identifier: AGPL-3.0-only

package bacap

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
)

// TestWithMessageBoxIndex checks that re-basing a cap to a chosen index sets the
// cap's embedded index (the one Start returns),
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

	// The re-based caps start at target: a message written there opens there.
	msg := []byte("written at the re-based position")
	boxID, ciphertext, sig, err := wc2.Start().Encrypt(ctx, msg)
	require.NoError(t, err)

	expectedBoxID, err := rc2.Start().BoxID(ctx)
	require.NoError(t, err)
	require.Equal(t, expectedBoxID.Bytes(), boxID[:])

	plaintext, err := rc2.Start().Open(ctx, boxID, ciphertext, sig)
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
