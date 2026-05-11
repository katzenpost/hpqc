// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package ed25519

import (
	stded25519 "crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSharedPlainEd25519Vectors loads the canonical plain-Ed25519 vectors
// from the shared testvectors/ tree (reached via the testdata symlink) and
// asserts that the standard library reproduces them. The same JSON file is
// consumed by the Python port's Ed25519Scheme.verify tests, so any
// divergence between the two sides surfaces as a mismatch here or in
// pytest.
func TestSharedPlainEd25519Vectors(t *testing.T) {
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

	raw, err := os.ReadFile(filepath.Join("testdata", "ed25519.json"))
	require.NoError(t, err)

	var f file
	require.NoError(t, json.Unmarshal(raw, &f))
	require.Equal(t, 1, f.FormatVersion)
	require.Equal(t, "ed25519", f.Primitive)
	require.NotEmpty(t, f.Vectors)

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			pub, err := hex.DecodeString(v.PublicKeyHex)
			require.NoError(t, err)
			msg, err := hex.DecodeString(v.MessageHex)
			require.NoError(t, err)
			sig, err := hex.DecodeString(v.SignatureHex)
			require.NoError(t, err)

			require.Len(t, pub, stded25519.PublicKeySize)
			require.Len(t, sig, stded25519.SignatureSize)
			require.True(t, stded25519.Verify(pub, msg, sig),
				"verify must succeed on recorded vector")

			if len(sig) > 0 {
				bad := append([]byte{}, sig...)
				bad[0] ^= 0xff
				require.False(t, stded25519.Verify(pub, msg, bad),
					"verify must fail after flipping signature[0]")
			}
		})
	}
}
