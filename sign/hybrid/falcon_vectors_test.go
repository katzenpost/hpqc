// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package hybrid

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign"
)

// TestSharedFalconHybridVectors verifies the Falcon-padded-512-Ed25519 and
// Falcon-padded-1024-Ed25519 hybrid sign/verify vectors recorded in the
// shared testvectors/ tree. The Python port consumes the same JSON files
// via symlinks under py/tests/sign/hybrid/; a divergence in the on-wire
// concatenation order or in either component scheme's encoding surfaces
// as a mismatch here or in pytest.
func TestSharedFalconHybridVectors(t *testing.T) {
	cases := []struct {
		fixture   string
		primitive string
		scheme    sign.Scheme
	}{
		{"falcon_padded_512_ed25519.json", "falcon_padded_512_ed25519", FalconPadded512Ed25519},
		{"falcon_padded_1024_ed25519.json", "falcon_padded_1024_ed25519", FalconPadded1024Ed25519},
	}
	for _, c := range cases {
		c := c
		t.Run(c.primitive, func(t *testing.T) {
			runHybridVectorFile(t, c.fixture, c.primitive, c.scheme)
		})
	}
}

func runHybridVectorFile(t *testing.T, fixture, primitive string, scheme sign.Scheme) {
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

	raw, err := os.ReadFile(filepath.Join("testdata", fixture))
	require.NoError(t, err)

	var f file
	require.NoError(t, json.Unmarshal(raw, &f))
	require.Equal(t, 1, f.FormatVersion)
	require.Equal(t, primitive, f.Primitive)
	require.NotEmpty(t, f.Vectors)

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
				"verify must fail after flipping signature[0] (Falcon half)")

			tail := append([]byte{}, sig...)
			tail[len(tail)-1] ^= 0xff
			require.False(t, scheme.Verify(pub, msg, tail, nil),
				"verify must fail after flipping signature[-1] (Ed25519 half)")
		})
	}
}
