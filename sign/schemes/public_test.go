// SPDX-License-Identifier: AGPL-3.0-only

package schemes_test

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/hybrid"
	"github.com/katzenpost/hpqc/sign/schemes"
)

func publicOrPanic(sk sign.PrivateKey) (pub crypto.PublicKey, panicked error) {
	defer func() {
		if r := recover(); r != nil {
			panicked = fmt.Errorf("Public panicked: %v", r)
		}
	}()
	return sk.Public(), nil
}

func TestPrivateKeyPublicMatchesGeneratedPublicKey(t *testing.T) {
	hybrids := 0
	for _, s := range schemes.All() {
		if _, ok := s.(*hybrid.Scheme); ok {
			hybrids++
		}
		t.Run(s.Name(), func(t *testing.T) {
			pub, priv, err := s.GenerateKey()
			require.NoError(t, err)

			got, panicked := publicOrPanic(priv)
			require.NoError(t, panicked)
			gotPub, ok := got.(sign.PublicKey)
			require.True(t, ok, "Public() is %T, not a sign.PublicKey", got)
			require.True(t, pub.Equal(gotPub))
			require.True(t, gotPub.Equal(pub))

			want, err := pub.MarshalBinary()
			require.NoError(t, err)
			have, err := gotPub.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, want, have)

			msg := []byte("crypto.Signer round trip")
			var signer crypto.Signer = priv
			sig, err := signer.Sign(rand.Reader, msg, crypto.Hash(0))
			require.NoError(t, err)
			signerPub, ok := signer.Public().(sign.PublicKey)
			require.True(t, ok)
			require.True(t, s.Verify(signerPub, msg, sig, nil))
		})
	}
	require.NotZero(t, hybrids)
}

func marshalOrPanic(pub sign.PublicKey) (b []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("MarshalBinary panicked: %v", r)
		}
	}()
	return pub.MarshalBinary()
}

func TestUnmarshaledPrivateKeyPublicMatchesGeneratedPublicKey(t *testing.T) {
	for _, s := range schemes.All() {
		t.Run(s.Name(), func(t *testing.T) {
			pub, priv, err := s.GenerateKey()
			require.NoError(t, err)
			blob, err := priv.MarshalBinary()
			require.NoError(t, err)
			loaded, err := s.UnmarshalBinaryPrivateKey(blob)
			require.NoError(t, err)

			got, panicked := publicOrPanic(loaded)
			require.NoError(t, panicked)
			if got == nil {
				t.Skipf("%s cannot derive a public key from a private key", s.Name())
			}
			gotPub, ok := got.(sign.PublicKey)
			require.True(t, ok, "Public() is %T, not a sign.PublicKey", got)

			want, err := pub.MarshalBinary()
			require.NoError(t, err)
			have, err := marshalOrPanic(gotPub)
			require.NoError(t, err)
			require.Equal(t, want, have)
			require.True(t, pub.Equal(gotPub))
		})
	}
}
