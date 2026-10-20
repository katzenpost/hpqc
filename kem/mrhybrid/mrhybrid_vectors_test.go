// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package mrhybrid

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/mlkem768"
	"github.com/katzenpost/hpqc/kem/schemes"
)

type vectorFile struct {
	Primitive string `json:"primitive"`
	Vectors   []struct {
		Name       string `json:"name"`
		PayloadHex string `json:"payload_hex"`
		Recipients []struct {
			X25519PrivateKeyHex string `json:"x25519_private_key_hex"`
			MLKEMDHex           string `json:"mlkem_d_hex"`
			MLKEMZHex           string `json:"mlkem_z_hex"`
			DerivedKeyHex       string `json:"derived_key_hex"`
			KEMCiphertextHex    string `json:"kem_ciphertext_hex"`
			DEKHex              string `json:"dek_hex"`
		} `json:"recipients"`
		EnvelopeHex       string `json:"envelope_hex"`
		ReplyPlaintextHex string `json:"reply_plaintext_hex"`
		ReplyEnvelopeHex  string `json:"reply_envelope_hex"`
	} `json:"vectors"`
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// privateKey builds an MLKEM768-X25519 private key from an X25519 scalar
// and an ML-KEM-768 seed (d, z).
func privateKey(t *testing.T, k kem.Scheme, x, d, z []byte) kem.PrivateKey {
	_, mlkemSk := mlkem768.Scheme().DeriveKeyPair(append(append([]byte{}, d...), z...))
	mlkemBytes, err := mlkemSk.MarshalBinary()
	require.NoError(t, err)
	sk, err := k.UnmarshalBinaryPrivateKey(append(append([]byte{}, x...), mlkemBytes...))
	require.NoError(t, err)
	return sk
}

// TestCrossCheckVectors checks hpqc's own vectors (testvectors/cmd/generate)
// and CryptWalker's (MultiRecipientHybrid/gen_multirecipient_hybrid_vectors.lean),
// both over MLKEM768-X25519. KEM encapsulation is randomized on both sides,
// so each recipient decapsulates the recorded ciphertext.
func TestCrossCheckVectors(t *testing.T) {
	k := schemes.ByName("MLKEM768-X25519")
	s := NewScheme(k)
	for _, file := range []string{"multirecipient_hybrid.json", "lean_multirecipient_hybrid_vectors.json"} {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", file))
			require.NoError(t, err)
			var f vectorFile
			require.NoError(t, json.Unmarshal(raw, &f))
			require.Equal(t, "multirecipient_hybrid_mlkem768_x25519", f.Primitive)
			require.NotEmpty(t, f.Vectors)

			for _, v := range f.Vectors {
				require.NotEmpty(t, v.Recipients, v.Name)
				ct := &Ciphertext{Envelope: unhex(t, v.EnvelopeHex)}
				for _, r := range v.Recipients {
					ct.KEMCiphertexts = append(ct.KEMCiphertexts, unhex(t, r.KEMCiphertextHex))
					ct.DEKCiphertexts = append(ct.DEKCiphertexts, unhex(t, r.DEKHex))
				}
				ct2, err := CiphertextFromBytes(s, ct.Marshal())
				require.NoError(t, err, v.Name)
				require.Equal(t, ct, ct2, v.Name)

				for i, r := range v.Recipients {
					sk := privateKey(t, k, unhex(t, r.X25519PrivateKeyHex), unhex(t, r.MLKEMDHex), unhex(t, r.MLKEMZHex))
					for _, c := range []*Ciphertext{ct.ForRecipient(i), ct} {
						derived, got, err := s.Decapsulate(sk, c)
						require.NoError(t, err, "%s recipient %d", v.Name, i)
						require.Equal(t, unhex(t, r.DerivedKeyHex), derived, "%s recipient %d", v.Name, i)
						require.Equal(t, v.PayloadHex, hex.EncodeToString(got), "%s recipient %d", v.Name, i)
					}
				}

				reply, err := s.DecryptEnvelope(unhex(t, v.Recipients[0].DerivedKeyHex), unhex(t, v.ReplyEnvelopeHex))
				require.NoError(t, err, v.Name)
				require.Equal(t, unhex(t, v.ReplyPlaintextHex), reply, v.Name)
			}
		})
	}
}
