// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package mlkem768

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/mlkem768"
	"github.com/stretchr/testify/require"
)

func TestHedgedRoundTrip(t *testing.T) {
	s := SchemeHedged()
	pk, sk, err := s.GenerateKeyPair()
	require.NoError(t, err)
	ct, ss, err := s.Encapsulate(pk)
	require.NoError(t, err)
	ss2, err := s.Decapsulate(sk, ct)
	require.NoError(t, err)
	require.Equal(t, ss, ss2)
}

func TestHedgedMatchesMLKEM(t *testing.T) {
	pk, _, err := SchemeHedged().GenerateKeyPair()
	require.NoError(t, err)
	ek, err := pk.MarshalBinary()
	require.NoError(t, err)

	m := make([]byte, 32)
	for i := range m {
		m[i] = byte(i)
	}

	ct, ss, err := encapsulateHedgedDerand(ek, m)
	require.NoError(t, err)
	fipsCt, fipsSs, err := mlkem768.EncapsulateDerand(ek, m)
	require.NoError(t, err)
	require.Equal(t, fipsCt, ct)
	require.Equal(t, fipsSs, ss)
}

func TestHedgedSharesKeyFormat(t *testing.T) {
	_, sk, err := Scheme().GenerateKeyPair()
	require.NoError(t, err)
	blob, err := sk.MarshalBinary()
	require.NoError(t, err)

	hsk, err := SchemeHedged().UnmarshalBinaryPrivateKey(blob)
	require.NoError(t, err)
	require.False(t, sk.Equal(hsk))

	ct, ss, err := SchemeHedged().Encapsulate(hsk.Public())
	require.NoError(t, err)
	ss2, err := Scheme().Decapsulate(sk, ct)
	require.NoError(t, err)
	require.Equal(t, ss, ss2)
}

type nistVectorFile struct {
	Vectors []struct {
		Name     string `json:"name"`
		Mode     string `json:"mode"`
		DHex     string `json:"d_hex"`
		ZHex     string `json:"z_hex"`
		EkHex    string `json:"ek_hex"`
		MHex     string `json:"m_hex"`
		CHex     string `json:"c_hex"`
		KHex     string `json:"k_hex"`
		WantPass bool   `json:"want_pass"`
	} `json:"vectors"`
}

func loadNIST(t *testing.T, name string) nistVectorFile {
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	var f nistVectorFile
	require.NoError(t, json.Unmarshal(raw, &f))
	require.NotEmpty(t, f.Vectors)
	return f
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

// The NIST ACVP ML-KEM-768 vectors, run against the hedged scheme. The
// decapsulation (VAL) and checkDK vectors use FIPS 203's expanded
// decapsulation key, which the seed-only mlkem768 API cannot load, so
// they are not exercised here; CryptWalker runs them against its hedged
// instance (KEM/MLKEMHedged/mlkemhedged768_test.lean).

func TestHedgedNISTKeyGen(t *testing.T) {
	for _, v := range loadNIST(t, "mlkem768_keygen.json").Vectors {
		seed := append(unhex(t, v.DHex), unhex(t, v.ZHex)...)
		pk, _ := SchemeHedged().DeriveKeyPair(seed)
		ek, err := pk.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, unhex(t, v.EkHex), ek, v.Name)
	}
}

func TestHedgedNISTEncap(t *testing.T) {
	n := 0
	for _, v := range loadNIST(t, "mlkem768_encapdecap.json").Vectors {
		if v.Mode != "encap" {
			continue
		}
		n++
		ct, ss, err := encapsulateHedgedDerand(unhex(t, v.EkHex), unhex(t, v.MHex))
		require.NoError(t, err, v.Name)
		require.Equal(t, unhex(t, v.CHex), ct, v.Name)
		require.Equal(t, unhex(t, v.KHex), ss, v.Name)
	}
	require.NotZero(t, n)
}

func TestHedgedNISTCheckEK(t *testing.T) {
	n := 0
	for _, v := range loadNIST(t, "mlkem768_keycheck.json").Vectors {
		if v.Mode != "checkEK" {
			continue
		}
		n++
		pk, err := SchemeHedged().UnmarshalBinaryPublicKey(unhex(t, v.EkHex))
		require.NoError(t, err, v.Name)
		_, _, err = SchemeHedged().Encapsulate(pk)
		if v.WantPass {
			require.NoError(t, err, v.Name)
		} else {
			require.Error(t, err, v.Name)
		}
	}
	require.NotZero(t, n)
}
