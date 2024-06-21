// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package schemes

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/util"
)

func TestNIKEUnmarshaling(t *testing.T) {
	todo := All()

	testNike := func(s nike.Scheme) {
		pubkey1, privkey1, err := s.GenerateKeyPairFromEntropy(rand.Reader)
		require.NoError(t, err)

		pubkey1Blob, err := pubkey1.MarshalBinary()
		require.NoError(t, err)

		t.Logf("pubkey1Blob is len %d", len(pubkey1Blob))

		pubkey2, err := s.UnmarshalBinaryPublicKey(pubkey1Blob)
		require.NoError(t, err)
		refBytes := pubkey1.Bytes()
		require.Equal(t, refBytes, pubkey2.Bytes())
		pubkey1.Reset()
		_, err = pubkey1.MarshalBinary()
		require.NoError(t, err)

		privkey1blob, err := privkey1.MarshalBinary()
		require.NoError(t, err)

		t.Logf("privkey1blob is len %d", len(privkey1blob))
		refBytes = privkey1.Bytes()

		privkey1.Reset()
		_, err = privkey1.MarshalBinary()
		require.NoError(t, err)

		privkey2, err := s.UnmarshalBinaryPrivateKey(privkey1blob)
		require.NoError(t, err)

		require.Equal(t, refBytes, privkey2.Bytes())
	}

	for _, scheme := range todo {
		t.Logf("testing NIKE Scheme: %s", scheme.Name())
		testNike(scheme)
		t.Log("OK")
	}
}

func TestRoundTripBytes(t *testing.T) {
	todo := All()

	testNike := func(s nike.Scheme) {
		pubkey1, privkey1, err := s.GenerateKeyPairFromEntropy(rand.Reader)
		require.NoError(t, err)
		pubkey2, privkey2, err := s.GenerateKeyPairFromEntropy(rand.Reader)
		require.NoError(t, err)
		pubkey2.FromBytes(pubkey1.Bytes())
		require.Equal(t, pubkey1.Bytes(), pubkey2.Bytes())
		privkey2.FromBytes(privkey1.Bytes())
		require.Equal(t, privkey1.Bytes(), privkey2.Bytes())
	}

	for _, scheme := range todo {
		t.Logf("testing NIKE Scheme: %s", scheme.Name())
		testNike(scheme)
		t.Log("OK")
	}
}

func TestNIKEOps(t *testing.T) {
	todo := All()

	testNike := func(s nike.Scheme) {
		// test 1
		pubkey1, privkey1, err := s.GenerateKeyPairFromEntropy(rand.Reader)
		require.NoError(t, err)

		pubkey2, privkey2, err := s.GenerateKeyPairFromEntropy(rand.Reader)
		require.NoError(t, err)

		ss1 := s.DeriveSecret(privkey1, pubkey2)
		ss2 := s.DeriveSecret(privkey2, pubkey1)

		require.Equal(t, ss1, ss2)

		// test 2
		pubkey3 := privkey1.Public()
		require.Equal(t, pubkey1.Bytes(), pubkey3.Bytes())
		blob1, err := pubkey1.MarshalBinary()
		require.NoError(t, err)
		blob2, err := pubkey3.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, blob1, blob2)

		// test 3
		pubkey4 := s.DerivePublicKey(privkey1)
		require.Equal(t, pubkey1.Bytes(), pubkey4.Bytes())

		// test 4
		require.False(t, util.CtIsZero(pubkey1.Bytes()))
		pubblob1 := pubkey4.Bytes()
		pubkey4.Reset()
		pubblob2 := pubkey4.Bytes()
		require.False(t, util.CtIsZero(pubkey1.Bytes()))
		require.NotEqual(t, pubkey1.Bytes(), pubkey4.Bytes())
		require.True(t, util.CtIsZero(pubkey4.Bytes()))
		require.NotEqual(t, pubblob1, pubblob2)

		// test 5
		privBlob1 := privkey2.Bytes()
		privkey2.Reset()
		privBlob2 := privkey2.Bytes()
		require.NotEqual(t, privBlob1, privBlob2)

		if strings.Contains(s.Name(), "NOBS") {
			return
		}

		// blinding operations test
		mixPub, mixPriv, err := s.GenerateKeyPairFromEntropy(rand.Reader)
		require.NoError(t, err)
		clientPub, clientPriv, err := s.GenerateKeyPairFromEntropy(rand.Reader)
		require.NoError(t, err)
		blindingFactor := s.GeneratePrivateKey(rand.Reader)
		pubkey1, err = s.UnmarshalBinaryPublicKey(s.DeriveSecret(clientPriv, mixPub))
		require.NoError(t, err)
		value1 := s.Blind(pubkey1, blindingFactor)
		require.NoError(t, err)
		blinded := s.Blind(clientPub, blindingFactor)
		require.NoError(t, err)
		value2 := s.DeriveSecret(mixPriv, blinded)
		require.Equal(t, value1.Bytes(), value2)
	}

	for _, scheme := range todo {
		t.Logf("testing NIKE Scheme: %s", scheme.Name())
		testNike(scheme)
		t.Log("OK")
	}
}
