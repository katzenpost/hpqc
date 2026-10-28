// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package box

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/hybrid"
	"github.com/katzenpost/hpqc/nike/x25519"
)

// TestSharedBoxVectors opens each recorded box with its recorded private
// key.
func TestSharedBoxVectors(t *testing.T) {
	type vector struct {
		Name                   string `json:"name"`
		NikeName               string `json:"nike_name"`
		RecipientPrivateKeyHex string `json:"recipient_private_key_hex"`
		RecipientPublicKeyHex  string `json:"recipient_public_key_hex"`
		PlaintextHex           string `json:"plaintext_hex"`
		CiphertextHex          string `json:"ciphertext_hex"`
	}
	type file struct {
		FormatVersion int      `json:"format_version"`
		Primitive     string   `json:"primitive"`
		Vectors       []vector `json:"vectors"`
	}

	raw, err := os.ReadFile(filepath.Join("testdata", "box.json"))
	require.NoError(t, err)

	var f file
	require.NoError(t, json.Unmarshal(raw, &f))
	require.Equal(t, 1, f.FormatVersion)
	require.Equal(t, "nike_box", f.Primitive)
	require.NotEmpty(t, f.Vectors)

	schemes := map[string]nike.Scheme{}
	for _, n := range []nike.Scheme{x25519.Scheme(rand.Reader), hybrid.X25519CTIDH1024} {
		schemes[n.Name()] = n
	}

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			n, ok := schemes[v.NikeName]
			require.True(t, ok, "unknown NIKE %q", v.NikeName)
			s := NewScheme(n)

			privBytes, err := hex.DecodeString(v.RecipientPrivateKeyHex)
			require.NoError(t, err)
			priv, err := n.UnmarshalBinaryPrivateKey(privBytes)
			require.NoError(t, err)
			require.Equal(t, v.RecipientPublicKeyHex, hex.EncodeToString(n.DerivePublicKey(priv).Bytes()))

			ct, err := hex.DecodeString(v.CiphertextHex)
			require.NoError(t, err)
			want, err := hex.DecodeString(v.PlaintextHex)
			require.NoError(t, err)

			got, err := s.Open(priv, ct)
			require.NoError(t, err)
			require.Equal(t, want, got)
		})
	}
}
