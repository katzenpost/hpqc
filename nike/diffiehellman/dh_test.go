package diffiehellman

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDHKeyLengths(t *testing.T) {
	s := Scheme()

	for i := 0; i < 1000; i++ {
		pubkey1, privkey1, err := s.GenerateKeyPair()
		require.NoError(t, err)

		require.Equal(t, s.PublicKeySize(), len(pubkey1.Bytes()))
		require.Equal(t, s.PrivateKeySize(), len(privkey1.Bytes()))
	}
}
