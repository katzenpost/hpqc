// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package schemes

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"
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

		require.Equal(t, pubkey1.Bytes(), pubkey2.Bytes())

		privkey1blob, err := privkey1.MarshalBinary()
		require.NoError(t, err)

		t.Logf("privkey1blob is len %d", len(privkey1blob))

		privkey2, err := s.UnmarshalBinaryPrivateKey(privkey1blob)
		require.NoError(t, err)

		require.Equal(t, privkey1.Bytes(), privkey2.Bytes())
	}

	for _, scheme := range todo {
		t.Logf("testing NIKE Scheme: %s", scheme.Name())
		testNike(scheme)
		t.Log("OK")
	}
}

func TestNIKE(t *testing.T) {
	todo := All()

	testNike := func(s nike.Scheme) {
		pubkey1, privkey1, err := s.GenerateKeyPairFromEntropy(rand.Reader)
		require.NoError(t, err)

		pubkey2, privkey2, err := s.GenerateKeyPairFromEntropy(rand.Reader)
		require.NoError(t, err)

		ss1 := s.DeriveSecret(privkey1, pubkey2)
		ss2 := s.DeriveSecret(privkey2, pubkey1)

		require.Equal(t, ss1, ss2)
	}

	for _, scheme := range todo {
		t.Logf("testing KEM Scheme: %s", scheme.Name())
		testNike(scheme)
		t.Log("OK")
	}
}
