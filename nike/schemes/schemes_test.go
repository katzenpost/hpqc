// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package schemes

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"
)

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
