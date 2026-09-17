// SPDX-License-Identifier: AGPL-3.0-only

package ed25519

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
)

// FromBytes must reject a public key, and a private key's public half, that is
// not a valid Edwards point, so a later Blind cannot panic on it.
func TestFromBytesRejectsOffCurvePoint(t *testing.T) {
	// Deterministically construct a 32-byte string that is not a valid Edwards
	// point encoding (about half of all encodings are off-curve).
	var bad [PublicKeySize]byte
	found := false
	for i := 0; i < 256; i++ {
		bad[0] = byte(i)
		if _, err := new(edwards25519.Point).SetBytes(bad[:]); err != nil {
			found = true
			break
		}
	}
	require.True(t, found, "could not construct an off-curve fixture")

	var pub PublicKey
	require.Error(t, pub.FromBytes(bad[:]), "off-curve public key must be rejected")

	// A 64-byte private key whose public half is off-curve must also be
	// rejected: the courier reaches this via a crafted bacap WriteCap.
	var priv [PrivateKeySize]byte
	copy(priv[PublicKeySize:], bad[:])
	var pk PrivateKey
	require.Error(t, pk.FromBytes(priv[:]), "private key with off-curve public half must be rejected")
}

// A legitimately generated key must still round-trip through FromBytes.
func TestFromBytesAcceptsValidKey(t *testing.T) {
	pubkey, privkey := NewKeyFromSeed(make([]byte, KeySeedSize))

	pb, err := pubkey.MarshalBinary()
	require.NoError(t, err)
	var rtPub PublicKey
	require.NoError(t, rtPub.FromBytes(pb))

	var rtPriv PrivateKey
	require.NoError(t, rtPriv.FromBytes(privkey.Bytes()))
}
