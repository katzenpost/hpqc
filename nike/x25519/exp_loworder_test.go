// SPDX-License-Identifier: AGPL-3.0-only

package x25519

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/util"
)

// A low-order peer point makes curve25519.X25519 return an error and Exp used to
// panic on it; the point is reachable from unauthenticated peer bytes via the
// wire-KEM decapsulation. Per RFC 7748 Section 6.1 a low-order point yields the
// all-zero result and the caller must detect it and abort, so Exp must not
// panic.
func TestExpLowOrderPointDoesNotPanic(t *testing.T) {
	var point [GroupElementLength]byte // all-zero: a low-order point
	var scalar [GroupElementLength]byte
	scalar[0] = 9
	var result []byte
	require.NotPanics(t, func() {
		result = Exp(point[:], scalar[:])
	}, "Exp must not panic on a low-order peer point")
	require.True(t, util.CtIsZero(result),
		"a low-order peer point must yield the all-zero secret")
}

// Blinding a low-order group member yields an all-zero result; Blind must
// return nil so the caller cannot use a degenerate blinded key.
func TestBlindLowOrderPointReturnsNil(t *testing.T) {
	s := Scheme(rand.Reader)
	low := s.NewEmptyPublicKey()
	require.NoError(t, low.FromBytes(make([]byte, PublicKeySize)))
	_, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)
	require.Nil(t, s.Blind(low, priv), "Blind of a low-order point must return nil")
}
