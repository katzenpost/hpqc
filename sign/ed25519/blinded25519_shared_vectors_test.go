// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package ed25519

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestSharedBlindedEd25519Vectors loads the canonical JSON vectors from the
// shared testvectors/ tree (reached via the testdata symlink) and asserts
// that this Go implementation reproduces them. The same JSON file is the
// single source of truth for both Go and the Python port; any divergence
// between the two surfaces as a vector mismatch on one side or the other.
//
// Each vector applies an ordered list of blind factors to a private key and
// records the resulting blinded public key and a signature over the message
// under the cumulatively blinded private key. A single-factor vector tests
// one blinding step; a multi-factor vector tests N successive blindings.
func TestSharedBlindedEd25519Vectors(t *testing.T) {
	type vector struct {
		Name             string   `json:"name"`
		Provenance       string   `json:"provenance"`
		PrivateKeyHex    string   `json:"private_key_hex"`
		MessageHex       string   `json:"message_hex"`
		BlindFactorsHex  []string `json:"blind_factors_hex"`
		BlindedPubKeyHex string   `json:"blinded_pubkey_hex"`
		BlindedSigHex    string   `json:"blinded_signature_hex"`
	}
	type file struct {
		FormatVersion int      `json:"format_version"`
		Primitive     string   `json:"primitive"`
		Vectors       []vector `json:"vectors"`
	}

	path := filepath.Join("testdata", "blinded_ed25519.json")
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "read shared vector file")

	var f file
	require.NoError(t, json.Unmarshal(raw, &f), "decode JSON")
	require.Equal(t, 1, f.FormatVersion)
	require.Equal(t, "blinded_ed25519", f.Primitive)
	require.NotEmpty(t, f.Vectors)

	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			require.NotEmpty(t, v.BlindFactorsHex, "vector must have at least one blind factor")

			privBytes, err := hex.DecodeString(v.PrivateKeyHex)
			require.NoError(t, err)
			message, err := hex.DecodeString(v.MessageHex)
			require.NoError(t, err)
			expectedPub, err := hex.DecodeString(v.BlindedPubKeyHex)
			require.NoError(t, err)
			expectedSig, err := hex.DecodeString(v.BlindedSigHex)
			require.NoError(t, err)
			factors := make([][]byte, len(v.BlindFactorsHex))
			for i, fh := range v.BlindFactorsHex {
				factors[i], err = hex.DecodeString(fh)
				require.NoError(t, err, "decode factor %d", i)
			}

			priv := new(PrivateKey)
			require.NoError(t, priv.FromBytes(privBytes))
			blinded := priv.Blind(factors[0])
			for _, f := range factors[1:] {
				blinded = blinded.Blind(f)
			}
			blindedPub := blinded.PublicKey()
			sig := blinded.Sign(message)

			require.Equal(t, expectedPub, blindedPub.Bytes(), "blinded public key mismatch")
			require.Equal(t, expectedSig, sig, "signature mismatch")
			require.True(t, blindedPub.Verify(sig, message), "signature failed self-verification")
			require.True(t, blindedPub.Verify(expectedSig, message), "expected signature failed verification")
		})
	}
}
