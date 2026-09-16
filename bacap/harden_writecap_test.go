// SPDX-License-Identifier: AGPL-3.0-only

package bacap

import (
	"crypto/rand"
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign/ed25519"
)

// A WriteCap blob whose embedded root private key has an off-curve public half
// must be rejected at deserialization rather than crash later when the first
// box id is derived (rootPublicKey.Blind). This mirrors the courier chain
// courier/server/plugin.go NewWriteCapFromBytes -> NextBoxID.
func TestNewWriteCapFromBytesRejectsOffCurveRootKeyWithoutPanic(t *testing.T) {
	good, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	blob, err := good.MarshalBinary()
	require.NoError(t, err)

	// Deterministically find an off-curve 32-byte encoding.
	var bad [32]byte
	found := false
	for i := 0; i < 256; i++ {
		bad[0] = byte(i)
		if _, e := new(edwards25519.Point).SetBytes(bad[:]); e != nil {
			found = true
			break
		}
	}
	require.True(t, found)

	// Overwrite the public half (bytes [32:64]) of the root private key.
	crafted := make([]byte, len(blob))
	copy(crafted, blob)
	copy(crafted[ed25519.PublicKeySize:ed25519.PrivateKeySize], bad[:])

	require.NotPanics(t, func() {
		_, err := NewWriteCapFromBytes(crafted)
		require.Error(t, err, "a WriteCap with an off-curve root public key must be rejected")
	})
}

// A legitimate WriteCap must still round-trip and derive a box id.
func TestWriteCapRoundTripDerivesBoxID(t *testing.T) {
	wc, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	blob, err := wc.MarshalBinary()
	require.NoError(t, err)

	rt, err := NewWriteCapFromBytes(blob)
	require.NoError(t, err)

	w, err := NewStatefulWriter(rt, []byte("harden-test-context"))
	require.NoError(t, err)
	require.NotPanics(t, func() {
		_, err := w.NextBoxID()
		require.NoError(t, err)
	})
}
