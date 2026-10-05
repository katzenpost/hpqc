// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package bacap

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

var positionCtx = []byte("pigeonhole context")

func TestPositionsRoundTrip(t *testing.T) {
	wc, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	w := wc.Start()
	r := wc.ReadCap().Start()

	for i := 0; i < 5; i++ {
		msg := []byte{byte(i), 'm'}
		box, ct, sig, err := w.Encrypt(positionCtx, msg)
		require.NoError(t, err)

		rbox, err := r.BoxID(positionCtx)
		require.NoError(t, err)
		require.Equal(t, rbox.Bytes(), box[:])
		wbox, err := w.BoxID(positionCtx)
		require.NoError(t, err)
		require.Equal(t, wbox.Bytes(), box[:])

		got, err := r.Open(positionCtx, box, ct, sig)
		require.NoError(t, err)
		require.Equal(t, msg, got)

		w, err = w.Next()
		require.NoError(t, err)
		r, err = r.Next()
		require.NoError(t, err)
		require.Equal(t, w.Index(), r.Index())
	}
}

func TestPositionOpenRejectsAnotherBox(t *testing.T) {
	wc, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	here := wc.Start()
	there, err := here.Next()
	require.NoError(t, err)

	// A tombstone for the next box: its signature verifies and there is
	// nothing to decrypt, so only the box check rejects it here.
	box, sig, err := there.Tombstone(positionCtx)
	require.NoError(t, err)
	_, err = here.ReadPosition().Open(positionCtx, box, []byte{}, sig)
	require.ErrorIs(t, err, ErrBoxMismatch)

	pt, err := there.ReadPosition().Open(positionCtx, box, []byte{}, sig)
	require.NoError(t, err)
	require.Empty(t, pt)

	var zero [BoxIDSize]byte
	_, err = here.ReadPosition().Open(positionCtx, zero, []byte{}, sig)
	require.ErrorIs(t, err, ErrEmptyBox)
}

func TestPositionAt(t *testing.T) {
	wc, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	rc := wc.ReadCap()
	start := rc.GetMessageBoxIndex()

	ahead, err := start.AdvanceIndexTo(start.Idx64 + 40)
	require.NoError(t, err)
	p, err := rc.PositionAt(ahead)
	require.NoError(t, err)
	require.Equal(t, ahead, p.Index())
	_, err = wc.PositionAt(ahead)
	require.NoError(t, err)

	other, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	foreign := *other.GetMessageBoxIndex()
	foreign.Idx64 = ahead.Idx64
	_, err = rc.PositionAt(&foreign)
	require.ErrorIs(t, err, ErrIndexNotInChannel)

	mutated, err := start.MutateKDFState([]byte("salt")).AdvanceIndexTo(ahead.Idx64)
	require.NoError(t, err)
	_, err = rc.PositionAt(mutated)
	require.ErrorIs(t, err, ErrIndexNotInChannel)

	later := rc.WithMessageBoxIndex(ahead)
	_, err = later.PositionAt(start)
	require.ErrorIs(t, err, ErrIndexNotInChannel)

	far := *start
	far.Idx64 += maxContainsWalk + 1
	_, err = rc.PositionAt(&far)
	require.ErrorIs(t, err, ErrIndexTooFar)
}

func TestPositionMarshal(t *testing.T) {
	wc, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	w, err := wc.Start().AdvanceTo(wc.GetMessageBoxIndex().Idx64 + 3)
	require.NoError(t, err)

	wb, err := w.MarshalBinary()
	require.NoError(t, err)
	w2, err := UnmarshalWritePosition(wb)
	require.NoError(t, err)
	require.Equal(t, w.Index(), w2.Index())

	rb, err := w.ReadPosition().MarshalBinary()
	require.NoError(t, err)
	r2, err := UnmarshalReadPosition(rb)
	require.NoError(t, err)
	require.Equal(t, w.Index(), r2.Index())

	// An index from another stream, written after the cap, is refused.
	other, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	otherIdx, err := other.GetMessageBoxIndex().MarshalBinary()
	require.NoError(t, err)
	copy(rb[ReadCapSize:], otherIdx)
	_, err = UnmarshalReadPosition(rb)
	require.Error(t, err)
}

// BenchmarkContains1000 walks 1000 ratchet steps, the cost Contains pays
// per thousand boxes between a cap's index and the one checked.
func BenchmarkContains1000(b *testing.B) {
	wc, err := NewWriteCap(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	rc := wc.ReadCap()
	start := rc.GetMessageBoxIndex()
	idx, err := start.AdvanceIndexTo(start.Idx64 + 1000)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := rc.Contains(idx); err != nil {
			b.Fatal(err)
		}
	}
}

// sameIndex must notice a difference in any one field.
func TestSameIndexEveryField(t *testing.T) {
	wc, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	a := *wc.GetMessageBoxIndex()
	require.True(t, sameIndex(&a, &a))

	for _, change := range []func(m *MessageBoxIndex){
		func(m *MessageBoxIndex) { m.Idx64 ^= 1 << 40 },
		func(m *MessageBoxIndex) { m.HKDFState[31] ^= 1 },
		func(m *MessageBoxIndex) { m.CurBlindingFactor[0] ^= 1 },
		func(m *MessageBoxIndex) { m.CurEncryptionKey[16] ^= 1 },
	} {
		b := a
		change(&b)
		require.False(t, sameIndex(&a, &b))
	}
}
