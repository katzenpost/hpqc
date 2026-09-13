// SPDX-License-Identifier: AGPL-3.0-only

package x448

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/util"
)

// A low-order peer point makes CIRCL x448.Shared return false and Exp used to
// panic on it; the point is reachable from unauthenticated peer bytes via the
// wire-KEM decapsulation and the Sphinx unwrap. Per RFC 7748 Section 6.1 a
// low-order point yields the all-zero result and the caller must detect it and
// abort, so Exp must not panic.
func TestDeriveSecretLowOrderPointDoesNotPanic(t *testing.T) {
	s := Scheme(rand.Reader)
	_, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)

	lowOrder := s.NewEmptyPublicKey()
	require.NoError(t, lowOrder.FromBytes(make([]byte, PublicKeySize)))

	var secret []byte
	require.NotPanics(t, func() {
		secret = s.DeriveSecret(priv, lowOrder)
	}, "DeriveSecret must not panic on a low-order peer point")
	require.True(t, util.CtIsZero(secret),
		"a low-order peer point must yield the all-zero secret")
}
