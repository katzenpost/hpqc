// SPDX-License-Identifier: AGPL-3.0-only

package sphincsplus

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A wrong-sized signature must return false rather than crash the reference
// C binding, which dereferences signature[0] on attacker-supplied input.
func TestVerifyRejectsWrongSizedSignatureWithoutPanic(t *testing.T) {
	s := Scheme()
	pub, _, err := s.GenerateKey()
	require.NoError(t, err)

	for _, sig := range [][]byte{nil, {}, {1, 2, 3}, make([]byte, s.SignatureSize()-1), make([]byte, s.SignatureSize()+1)} {
		sig := sig
		var ok bool
		require.NotPanics(t, func() {
			ok = s.Verify(pub, []byte("message"), sig, nil)
		}, "a %d-byte signature must return false, not panic", len(sig))
		require.False(t, ok)
	}
}

// An empty message with a correctly sized signature must also be rejected
// without reaching the C binding, which dereferences message[0].
func TestVerifyRejectsEmptyMessageWithoutPanic(t *testing.T) {
	s := Scheme()
	pub, _, err := s.GenerateKey()
	require.NoError(t, err)

	var ok bool
	require.NotPanics(t, func() {
		ok = s.Verify(pub, nil, make([]byte, s.SignatureSize()), nil)
	})
	require.False(t, ok)
}
