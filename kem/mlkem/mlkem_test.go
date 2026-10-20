// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package mlkem

import (
	"crypto/sha3"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
)

var sizes = []struct {
	size             string
	standard, hedged *scheme
}{
	{"512", sch512, sch512Hedged},
	{"1024", sch1024, sch1024Hedged},
}

type vector struct {
	Name     string `json:"name"`
	Mode     string `json:"mode"`
	DHex     string `json:"d_hex"`
	ZHex     string `json:"z_hex"`
	EkHex    string `json:"ek_hex"`
	MHex     string `json:"m_hex"`
	CHex     string `json:"c_hex"`
	KHex     string `json:"k_hex"`
	WantPass bool   `json:"want_pass"`

	MHashHex string `json:"m_hash_hex"`
	EncapHex string `json:"encapsulation_key_hex"`
	CtHex    string `json:"ciphertext_hex"`
	SSHex    string `json:"shared_secret_hex"`
}

func load(t *testing.T, name string) []vector {
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	var f struct {
		Vectors []vector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	require.NotEmpty(t, f.Vectors)
	return f.Vectors
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func TestRoundTrip(t *testing.T) {
	for _, s := range []kem.Scheme{Scheme512(), SchemeHedged512(), Scheme1024(), SchemeHedged1024()} {
		pk, sk, err := s.GenerateKeyPair()
		require.NoError(t, err)
		ct, ss, err := s.Encapsulate(pk)
		require.NoError(t, err)
		require.Len(t, ct, s.CiphertextSize())
		ss2, err := s.Decapsulate(sk, ct)
		require.NoError(t, err)
		require.Equal(t, ss, ss2, s.Name())

		skb, err := sk.MarshalBinary()
		require.NoError(t, err)
		require.Len(t, skb, s.PrivateKeySize())
		sk2, err := s.UnmarshalBinaryPrivateKey(skb)
		require.NoError(t, err)
		require.True(t, sk.Equal(sk2))
		ss3, err := s.Decapsulate(sk2, ct)
		require.NoError(t, err)
		require.Equal(t, ss, ss3)

		skb[0] ^= 1
		_, err = s.UnmarshalBinaryPrivateKey(skb)
		require.Error(t, err, s.Name())
	}
}

func TestSizes(t *testing.T) {
	require.Equal(t, []int{800, 768}, []int{Scheme512().PublicKeySize(), Scheme512().CiphertextSize()})
	require.Equal(t, []int{1568, 1568}, []int{Scheme1024().PublicKeySize(), Scheme1024().CiphertextSize()})
}

func TestRejectsOtherParameterSets(t *testing.T) {
	pk, sk, err := Scheme512().GenerateKeyPair()
	require.NoError(t, err)
	_, _, err = Scheme1024().Encapsulate(pk)
	require.ErrorIs(t, err, kem.ErrTypeMismatch)
	_, err = Scheme1024().Decapsulate(sk, make([]byte, Scheme1024().CiphertextSize()))
	require.ErrorIs(t, err, kem.ErrTypeMismatch)
}

// The hedged and standard schemes share keys, so either decapsulates.
func TestHedgedSharesKeyFormat(t *testing.T) {
	for _, c := range sizes {
		pk, sk, err := c.standard.GenerateKeyPair()
		require.NoError(t, err)
		ct, ss, err := c.hedged.Encapsulate(pk)
		require.NoError(t, err)
		ss2, err := c.standard.Decapsulate(sk, ct)
		require.NoError(t, err)
		require.Equal(t, ss, ss2, c.size)
	}
}

func TestHedgedIsPreHashedEncapsInternal(t *testing.T) {
	m := make([]byte, 32)
	for i := range m {
		m[i] = byte(i)
	}
	mh := sha3.Sum256(m)
	for _, c := range sizes {
		pk, _, err := c.standard.GenerateKeyPair()
		require.NoError(t, err)
		ek, err := pk.MarshalBinary()
		require.NoError(t, err)

		ct, ss, err := c.hedged.encapsulateDerand(ek, m)
		require.NoError(t, err)
		wantCt, wantSs, err := c.standard.encapsulateDerand(ek, mh[:])
		require.NoError(t, err)
		require.Equal(t, wantCt, ct, c.size)
		require.Equal(t, wantSs, ss, c.size)

		fipsCt, _, err := c.standard.encapsulateDerand(ek, m)
		require.NoError(t, err)
		require.NotEqual(t, fipsCt, ct, c.size)
	}
}

func TestNISTKeyGen(t *testing.T) {
	for _, c := range sizes {
		for _, v := range load(t, "mlkem"+c.size+"_keygen.json") {
			pk, _ := c.standard.DeriveKeyPair(append(unhex(t, v.DHex), unhex(t, v.ZHex)...))
			ek, err := pk.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, unhex(t, v.EkHex), ek, v.Name)
		}
	}
}

func TestNISTEncapsulation(t *testing.T) {
	for _, c := range sizes {
		n := 0
		for _, v := range load(t, "mlkem"+c.size+"_encapdecap.json") {
			if v.Mode != "encap" {
				continue
			}
			n++
			ct, ss, err := c.standard.encapsulateDerand(unhex(t, v.EkHex), unhex(t, v.MHex))
			require.NoError(t, err, v.Name)
			require.Equal(t, unhex(t, v.CHex), ct, v.Name)
			require.Equal(t, unhex(t, v.KHex), ss, v.Name)
		}
		require.NotZero(t, n)
	}
}

func TestNISTCheckEncapsulationKey(t *testing.T) {
	for _, c := range sizes {
		n := 0
		for _, v := range load(t, "mlkem"+c.size+"_keycheck.json") {
			if v.Mode != "checkEK" {
				continue
			}
			n++
			_, err := c.standard.UnmarshalBinaryPublicKey(unhex(t, v.EkHex))
			require.Equal(t, v.WantPass, err == nil, v.Name)
		}
		require.NotZero(t, n)
	}
}

// Hedged vectors from Cryptlib's verified Lean implementation, which
// hpqc's Rust implementation also checks.
func TestHedgedLeanVectors(t *testing.T) {
	for _, c := range sizes {
		for _, v := range load(t, "lean_mlkem"+c.size+"_hedged_vectors.json") {
			pk, sk := c.hedged.DeriveKeyPair(append(unhex(t, v.DHex), unhex(t, v.ZHex)...))
			ek, err := pk.MarshalBinary()
			require.NoError(t, err)
			require.Equal(t, unhex(t, v.EncapHex), ek, v.Name)

			m := unhex(t, v.MHex)
			mh := sha3.Sum256(m)
			require.Equal(t, unhex(t, v.MHashHex), mh[:], v.Name)

			ct, ss, err := c.hedged.encapsulateDerand(ek, m)
			require.NoError(t, err)
			require.Equal(t, unhex(t, v.CtHex), ct, v.Name)
			require.Equal(t, unhex(t, v.SSHex), ss, v.Name)

			ss2, err := c.hedged.Decapsulate(sk, ct)
			require.NoError(t, err)
			require.Equal(t, ss, ss2, v.Name)
		}
	}
}
