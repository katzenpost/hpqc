// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package hqc_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/schemes"
)

func TestHQCByName(t *testing.T) {
	for _, name := range []string{"HQC-128", "HQC-192", "HQC-256"} {
		s := schemes.ByName(name)
		require.NotNil(t, s, "scheme %s should resolve by name", name)
		require.Equal(t, name, s.Name())

		// lookup is case-insensitive in the registry
		require.NotNil(t, schemes.ByName("hqc-256"))

		pub, priv, err := s.GenerateKeyPair()
		require.NoError(t, err)

		ct, ss1, err := s.Encapsulate(pub)
		require.NoError(t, err)
		require.Equal(t, s.CiphertextSize(), len(ct))
		require.Equal(t, s.SharedKeySize(), len(ss1))

		ss2, err := s.Decapsulate(priv, ct)
		require.NoError(t, err)
		require.Equal(t, ss1, ss2)
	}
}
