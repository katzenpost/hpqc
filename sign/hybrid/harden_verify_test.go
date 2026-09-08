// SPDX-License-Identifier: AGPL-3.0-only

package hybrid

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign/ed25519"
)

// A wrong-length signature must return false, not panic.
func TestVerifyRejectsWrongSignatureSize(t *testing.T) {
	s := hardenTestScheme()
	pub, _, err := s.GenerateKey()
	require.NoError(t, err)
	var ok bool
	require.NotPanics(t, func() {
		ok = s.Verify(pub, []byte("message"), []byte{1, 2, 3}, nil)
	}, "wrong-size signature must return false, not panic")
	require.False(t, ok)
}

// A wrong-type public key must return false, not panic.
func TestVerifyRejectsWrongPublicKeyType(t *testing.T) {
	s := hardenTestScheme()
	_, priv, err := s.GenerateKey()
	require.NoError(t, err)
	sig := s.Sign(priv, []byte("message"), nil)
	edPub, _, err := ed25519.Scheme().GenerateKey()
	require.NoError(t, err)
	var ok bool
	require.NotPanics(t, func() {
		ok = s.Verify(edPub, []byte("message"), sig, nil)
	}, "wrong-type public key must return false, not panic")
	require.False(t, ok)
}
