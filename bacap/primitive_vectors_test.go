// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package bacap

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"hash"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"github.com/agl/gcmsiv"

	"github.com/stretchr/testify/require"
)

// These tests consume the primitive-level JSON vector files used by BACAP.
// Each file is a per-file symlink under bacap/testdata/ pointing into the
// canonical testvectors/ tree at the repo root. The same files are read by
// the corresponding Python tests, so any drift between the Go primitives
// and what the generator recorded is caught here on the Go side as well.

func loadVectorFile(t *testing.T, name string, primitive string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	var envelope struct {
		FormatVersion int             `json:"format_version"`
		Primitive     string          `json:"primitive"`
		Vectors       json.RawMessage `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &envelope))
	require.Equal(t, 1, envelope.FormatVersion, "format_version mismatch")
	require.Equal(t, primitive, envelope.Primitive, "primitive name mismatch")
	require.NoError(t, json.Unmarshal(envelope.Vectors, into))
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestPrimitiveSHA512_256Vectors(t *testing.T) {
	var vectors []struct {
		Name      string `json:"name"`
		InputHex  string `json:"input_hex"`
		OutputHex string `json:"output_hex"`
	}
	loadVectorFile(t, "sha512_256.json", "sha512_256", &vectors)
	require.NotEmpty(t, vectors)

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			input := mustHex(t, v.InputHex)
			expected := mustHex(t, v.OutputHex)
			sum := sha512.Sum512_256(input)
			require.Equal(t, expected, sum[:])
		})
	}
}

func TestPrimitiveBLAKE2b512Vectors(t *testing.T) {
	var vectors []struct {
		Name      string `json:"name"`
		InputHex  string `json:"input_hex"`
		OutputHex string `json:"output_hex"`
	}
	loadVectorFile(t, "blake2b_512.json", "blake2b_512", &vectors)
	require.NotEmpty(t, vectors)

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			input := mustHex(t, v.InputHex)
			expected := mustHex(t, v.OutputHex)
			h, err := blake2b.New512(nil)
			require.NoError(t, err)
			h.Write(input)
			require.Equal(t, expected, h.Sum(nil))
		})
	}
}

func TestPrimitiveHKDFBlake2bVectors(t *testing.T) {
	var vectors []struct {
		Name      string `json:"name"`
		SecretHex string `json:"secret_hex"`
		SaltHex   string `json:"salt_hex"`
		InfoHex   string `json:"info_hex"`
		Length    int    `json:"length"`
		OkmHex    string `json:"okm_hex"`
	}
	loadVectorFile(t, "hkdf_blake2b.json", "hkdf_blake2b", &vectors)
	require.NotEmpty(t, vectors)

	hashFn := func() hash.Hash { h, _ := blake2b.New512(nil); return h }

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			secret := mustHex(t, v.SecretHex)
			salt := mustHex(t, v.SaltHex)
			info := mustHex(t, v.InfoHex)
			expected := mustHex(t, v.OkmHex)

			r := hkdf.New(hashFn, secret, salt, info)
			out := make([]byte, v.Length)
			_, err := r.Read(out)
			require.NoError(t, err)
			require.Equal(t, expected, out)
		})
	}
}

func TestPrimitiveAESGCMSIVVectors(t *testing.T) {
	var vectors []struct {
		Name          string `json:"name"`
		KeyHex        string `json:"key_hex"`
		NonceHex      string `json:"nonce_hex"`
		AADHex        string `json:"aad_hex"`
		PlaintextHex  string `json:"plaintext_hex"`
		CiphertextHex string `json:"ciphertext_hex"`
	}
	loadVectorFile(t, "aes_gcm_siv.json", "aes_gcm_siv", &vectors)
	require.NotEmpty(t, vectors)

	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			key := mustHex(t, v.KeyHex)
			nonce := mustHex(t, v.NonceHex)
			aad := mustHex(t, v.AADHex)
			plaintext := mustHex(t, v.PlaintextHex)
			expected := mustHex(t, v.CiphertextHex)

			siv, err := gcmsiv.NewGCMSIV(key)
			require.NoError(t, err)
			ct := siv.Seal(nil, nonce, plaintext, aad)
			require.Equal(t, expected, ct, "encryption mismatch")

			pt, err := siv.Open(nil, nonce, expected, aad)
			require.NoError(t, err, "decryption failed")
			// bytes.Equal treats nil and []byte{} as equal; the SIV
			// implementation returns nil for empty plaintext.
			require.True(t, bytes.Equal(plaintext, pt), "decryption mismatch")
		})
	}
}
