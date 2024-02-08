// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package tests

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
)

func TestKEMTextUnmarshal(t *testing.T) {
	todo := schemes.All()

	testkem := func(s kem.Scheme) {
		testpubkey2, _, err := s.GenerateKeyPair()
		require.NoError(t, err)

		pubkey, _, err := s.GenerateKeyPair()
		require.NoError(t, err)

		blob1, err := pubkey.MarshalText()
		require.NoError(t, err)

		err = testpubkey2.UnmarshalText(blob1)
		require.NoError(t, err)

		blob2, err := testpubkey2.MarshalText()
		require.NoError(t, err)

		require.Equal(t, blob1, blob2)
	}

	for _, scheme := range todo {
		t.Logf("testing KEM Scheme: %s", scheme.Name())
		testkem(scheme)
		t.Log("OK")
	}
}
