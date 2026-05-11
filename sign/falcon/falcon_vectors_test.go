// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package falcon

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSharedFalconPadded512Vectors loads the canonical Falcon-padded-512
// sign/verify vectors from the shared testvectors/ tree (reached via the
// testdata symlink) and asserts that the scheme verifies them. The same
// JSON file is consumed by the Python port's pqcrypto-backed verifier;
// divergence between the two surfaces as a mismatch here or in pytest.
func TestSharedFalconPadded512Vectors(t *testing.T) {
	type vector struct {
		Name         string `json:"name"`
		PublicKeyHex string `json:"public_key_hex"`
		MessageHex   string `json:"message_hex"`
		SignatureHex string `json:"signature_hex"`
	}
	type file struct {
		FormatVersion int      `json:"format_version"`
		Primitive     string   `json:"primitive"`
		Vectors       []vector `json:"vectors"`
	}

	raw, err := os.ReadFile(filepath.Join("testdata", "falcon_padded_512.json"))
	require.NoError(t, err)

	var f file
	require.NoError(t, json.Unmarshal(raw, &f))
	require.Equal(t, 1, f.FormatVersion)
	require.Equal(t, "falcon_padded_512", f.Primitive)
	require.NotEmpty(t, f.Vectors)

	scheme := SchemePadded512()

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			pubBytes, err := hex.DecodeString(v.PublicKeyHex)
			require.NoError(t, err)
			msg, err := hex.DecodeString(v.MessageHex)
			require.NoError(t, err)
			sig, err := hex.DecodeString(v.SignatureHex)
			require.NoError(t, err)

			require.Len(t, pubBytes, scheme.PublicKeySize())
			require.Len(t, sig, scheme.SignatureSize())

			pub, err := scheme.UnmarshalBinaryPublicKey(pubBytes)
			require.NoError(t, err)
			require.True(t, scheme.Verify(pub, msg, sig, nil),
				"verify must succeed on recorded vector")

			bad := append([]byte{}, sig...)
			bad[0] ^= 0xff
			require.False(t, scheme.Verify(pub, msg, bad, nil),
				"verify must fail after flipping signature[0]")
		})
	}
}
