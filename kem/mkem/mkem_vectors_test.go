// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package mkem

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/hybrid"
)

// TestSharedMKEMVectors loads the canonical MKEM vector file from the
// shared testvectors/ tree (reached via the testdata symlink) and
// confirms that this Go implementation decapsulates each recorded
// ciphertext under each recorded recipient private key, recovering
// the recorded plaintext. The same JSON file is consumed by the
// Python port at py/tests/kem/test_mkem_vectors.py.
//
// The vectors are produced by testvectors/cmd/generate (which calls
// Encapsulate with random ephemeral keys, msg keys, and AEAD nonces),
// so re-running the generator changes the bytes; what stays stable is
// the wire-format contract.
func TestSharedMKEMVectors(t *testing.T) {
	type vector struct {
		Name                    string   `json:"name"`
		NikeName                string   `json:"nike_name"`
		RecipientPrivateKeysHex []string `json:"recipient_private_keys_hex"`
		CiphertextHex           string   `json:"ciphertext_hex"`
		PlaintextHex            string   `json:"plaintext_hex"`
	}
	type file struct {
		FormatVersion int      `json:"format_version"`
		Primitive     string   `json:"primitive"`
		Vectors       []vector `json:"vectors"`
	}

	raw, err := os.ReadFile(filepath.Join("testdata", "mkem.json"))
	require.NoError(t, err)

	var f file
	require.NoError(t, json.Unmarshal(raw, &f))
	require.Equal(t, 1, f.FormatVersion)
	require.Equal(t, "kem_mkem", f.Primitive)
	require.NotEmpty(t, f.Vectors)

	nikeScheme := hybrid.CTIDH1024X25519
	scheme := NewScheme(nikeScheme)

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			require.Equal(t, nikeScheme.Name(), v.NikeName, "vector recorded under different NIKE")

			ctBytes, err := hex.DecodeString(v.CiphertextHex)
			require.NoError(t, err)
			expected, err := hex.DecodeString(v.PlaintextHex)
			require.NoError(t, err)

			ct, err := CiphertextFromBytes(scheme, ctBytes)
			require.NoError(t, err)
			require.Len(t, ct.DEKCiphertexts, len(v.RecipientPrivateKeysHex),
				"DEK count must match recipient count")

			for i, privHex := range v.RecipientPrivateKeysHex {
				privBytes, err := hex.DecodeString(privHex)
				require.NoError(t, err)
				priv, err := nikeScheme.UnmarshalBinaryPrivateKey(privBytes)
				require.NoError(t, err)
				got, err := scheme.Decapsulate(priv, ct)
				require.NoError(t, err, "recipient %d: decapsulate failed", i)
				require.Equal(t, expected, got, "recipient %d: plaintext mismatch", i)
			}
		})
	}
}
