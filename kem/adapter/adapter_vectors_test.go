// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package adapter

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

// adapterVectorFile mirrors testvectors/kem/adapter_test_vectors.json. The same
// file is checked by the Lean port at CryptWalker/KEM/vectors.lean.
type adapterVectorFile struct {
	FormatVersion int `json:"format_version"`
	Primitive     string
	Vectors       []adapterTestVector
}

type adapterTestVector struct {
	Name                   string `json:"name"`
	NikeName               string `json:"nike_name"`
	PRF                    string `json:"prf"`
	StaticPrivateKeyHex    string `json:"static_private_key_hex"`
	StaticPublicKeyHex     string `json:"static_public_key_hex"`
	EphemeralPrivateKeyHex string `json:"ephemeral_private_key_hex"`
	CiphertextHex          string `json:"ciphertext_hex"`
	SharedSecretHex        string `json:"shared_secret_hex"`
}

// TestSharedAdapterVectors checks this implementation against the canonical
// NIKE-to-KEM adapter vectors, reached via the testdata symlink into the shared
// testvectors/ tree.
//
// Each vector pins both directions of the hashed-ElGamal construction:
//
//   - decapsulation, which is deterministic and directly callable, and
//   - encapsulation, which is not — Encapsulate draws its ephemeral from
//     crypto/rand and EncapsulateDeterministically is unimplemented. Because
//     this test is in-package it can reproduce Encapsulate's formula with the
//     recorded ephemeral, which is what pins the key ordering (static recipient
//     key first, ephemeral second).
//
// The PRF is taken from the vector's "prf" field rather than assumed, so the
// file can carry both the deployed BLAKE2b configuration and the portable
// SHA-256 one that implementations without BLAKE2b can still check.
func TestSharedAdapterVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "adapter_test_vectors.json"))
	require.NoError(t, err)

	var f adapterVectorFile
	require.NoError(t, json.Unmarshal(raw, &f))
	require.Equal(t, 1, f.FormatVersion)
	require.Equal(t, "kem_adapter", f.Primitive)
	require.NotEmpty(t, f.Vectors)

	nikeScheme := ecdh.Scheme(rand.Reader)

	seenPRF := map[string]int{}
	for _, v := range f.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			require.Equal(t, nikeScheme.Name(), v.NikeName, "vector recorded under a different NIKE")

			prf, err := PRFByName(v.PRF)
			require.NoError(t, err, "vector names a PRF this implementation does not have")
			scheme := FromNIKEWithPRF(nikeScheme, prf).(*Scheme)

			staticPrivBytes := mustHex(t, v.StaticPrivateKeyHex)
			ephPrivBytes := mustHex(t, v.EphemeralPrivateKeyHex)
			wantStaticPub := mustHex(t, v.StaticPublicKeyHex)
			wantCt := mustHex(t, v.CiphertextHex)
			wantSS := mustHex(t, v.SharedSecretHex)

			staticPriv, err := scheme.UnmarshalBinaryPrivateKey(staticPrivBytes)
			require.NoError(t, err)
			ephPriv, err := scheme.UnmarshalBinaryPrivateKey(ephPrivBytes)
			require.NoError(t, err)

			// Public keys derive as recorded.
			gotStaticPub, err := staticPriv.Public().MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, wantStaticPub, gotStaticPub, "static public key mismatch")

			gotEphPub, err := ephPriv.Public().MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, wantCt, gotEphPub, "ciphertext is the encoded ephemeral public key")

			// Decapsulation reproduces the recorded shared secret.
			gotSS, err := scheme.Decapsulate(staticPriv, wantCt)
			require.NoError(t, err)
			require.Equal(t, wantSS, gotSS, "decapsulated shared secret mismatch")

			// Encapsulation with the recorded ephemeral produces the same
			// shared secret: DH(eph_sk, static_pk), then PRF over the two keys.
			dh := nikeScheme.DeriveSecret(
				ephPriv.(*PrivateKey).privateKey,
				staticPriv.Public().(*PublicKey).publicKey,
			)
			encapSS, err := prf.Derive(dh, gotStaticPub, gotEphPub, scheme.SharedKeySize())
			require.NoError(t, err)
			require.Equal(t, wantSS, encapSS, "encapsulated shared secret mismatch")
		})
		seenPRF[v.PRF]++
	}

	// Both PRF families must actually be present; a silently truncated file
	// would otherwise look like a pass.
	require.NotZero(t, seenPRF[BLAKE2bXOF.Name()], "no blake2b-xof vectors")
	require.NotZero(t, seenPRF[SHA256v1.Name()], "no sha256-v1 vectors")
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}
