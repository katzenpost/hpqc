// SPDX-License-Identifier: AGPL-3.0-only

package ed25519

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// UnmarshalText must populate the receiver, not reassign a local pointer.
func TestPublicKeyUnmarshalTextPopulatesReceiver(t *testing.T) {
	pub, _, err := Scheme().GenerateKey()
	require.NoError(t, err)
	text, err := pub.(*PublicKey).MarshalText()
	require.NoError(t, err)

	var got PublicKey
	require.NoError(t, got.UnmarshalText(text))
	require.True(t, got.Equal(pub), "receiver must equal the decoded key")
}
