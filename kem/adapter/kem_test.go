package adapter

import (
	"testing"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

// NOTE that there is a deterministic which covers the behavior this
// NIKE to KEM adapter, located in core/crypto/kem/schemes/kem_test.go

func TestNikeToKemAdapter(t *testing.T) {
	ecdhNike := ecdh.Scheme(rand.Reader)
	s := FromNIKE(ecdhNike)

	t.Logf("hello my name is %s", s.Name())

	pubkey1, privkey1, err := s.GenerateKeyPair()
	require.NoError(t, err)

	ct, ssA, err := s.Encapsulate(pubkey1)
	require.NoError(t, err)

	ssB, err := s.Decapsulate(privkey1, ct)
	require.NoError(t, err)

	require.Equal(t, ssA, ssB)

	t.Logf("our shared key is %x", ssA)
}
