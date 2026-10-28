package diffiehellman

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/x25519"
)

// TestPaddedBinaryEncode verifies that paddedBinaryEncode always returns
// a fixed-size output even when the underlying big integer has leading
// zero bytes. See https://github.com/katzenpost/hpqc/issues/39.
func TestPaddedBinaryEncode(t *testing.T) {
	s := Scheme()
	group := s.group()

	// A small value in the group has hundreds of leading zero bytes,
	// so this directly exercises the padding path.
	small := group.NewInt(42)
	encoded := paddedBinaryEncode(small)
	require.Equal(t, groupSize+8, len(encoded))

	// Verify the value survives a round-trip through BinaryDecode.
	key := &PrivateKey{privateKey: small}
	restored := s.NewEmptyPrivateKey()
	require.NoError(t, restored.FromBytes(key.Bytes()))
	require.Equal(t, key.Bytes(), restored.Bytes())
}

// TestForeignKeys checks that keys of another NIKE are refused rather
// than panicking on a type assertion.
func TestForeignKeys(t *testing.T) {
	s := Scheme()
	pub, priv, err := s.GenerateKeyPair()
	require.NoError(t, err)
	xPub, xPriv, err := x25519.Scheme(rand.Reader).GenerateKeyPair()
	require.NoError(t, err)

	require.Nil(t, s.DeriveSecret(xPriv, pub))
	require.Nil(t, s.DeriveSecret(priv, xPub))
	require.Nil(t, s.DerivePublicKey(xPriv))
	require.Nil(t, s.Blind(xPub, priv))
	require.Nil(t, s.Blind(pub, xPriv))
	require.Nil(t, priv.(*PrivateKey).DeriveSecret(xPub))
	require.Error(t, pub.Blind(xPriv))
}
