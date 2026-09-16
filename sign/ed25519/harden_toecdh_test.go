// SPDX-License-Identifier: AGPL-3.0-only

package ed25519

import (
	"testing"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/require"
)

// ToECDH must return an error rather than panic when the public key holds an
// off-curve encoding. FromBytes now rejects such keys, so the field is set
// directly (white-box) to reach ToECDH.
func TestToECDHOffCurveReturnsError(t *testing.T) {
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

	p := &PublicKey{}
	p.pubKey = bad[:]
	r, err := p.ToECDH()
	require.Error(t, err, "off-curve ToECDH must return an error")
	require.Nil(t, r)
}

func TestToECDHValidKeyRoundTrips(t *testing.T) {
	pubkey, _ := NewKeyFromSeed(make([]byte, KeySeedSize))
	r, err := pubkey.ToECDH()
	require.NoError(t, err)
	require.NotNil(t, r)
}
