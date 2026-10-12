// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package mrhybrid

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
)

var testKEMs = []string{"MLKEM768", "MLKEM768-X25519", "X25519"}

func keys(t *testing.T, s *Scheme, n int) ([]kem.PublicKey, []kem.PrivateKey) {
	pks := make([]kem.PublicKey, n)
	sks := make([]kem.PrivateKey, n)
	for i := range n {
		var err error
		pks[i], sks[i], err = s.GenerateKeyPair()
		require.NoError(t, err)
	}
	return pks, sks
}

func forEachKEM(t *testing.T, f func(t *testing.T, s *Scheme)) {
	for _, name := range testKEMs {
		k := schemes.ByName(name)
		require.NotNil(t, k, name)
		t.Run(name, func(t *testing.T) { f(t, NewScheme(k)) })
	}
}

func TestRoundTrip(t *testing.T) {
	forEachKEM(t, func(t *testing.T, s *Scheme) {
		payload := []byte("a payload for several recipients")
		for _, n := range []int{1, 3, 10} {
			pks, sks := keys(t, s, n)
			derived, ct, err := s.Encapsulate(pks, payload)
			require.NoError(t, err)

			require.Len(t, derived, n)
			require.Len(t, ct.KEMCiphertexts, n)
			require.Len(t, ct.DEKCiphertexts, n)
			for i := range n {
				require.Len(t, derived[i], KeySize)
				require.Len(t, ct.KEMCiphertexts[i], s.KEM().CiphertextSize())
				require.Len(t, ct.DEKCiphertexts[i], DEKSize)
			}
			require.Len(t, ct.Envelope, len(payload)+EnvelopeOverhead)

			for i, sk := range sks {
				k, got, err := s.Decapsulate(sk, ct)
				require.NoError(t, err)
				require.Equal(t, payload, got)
				require.Equal(t, derived[i], k)

				k, got, err = s.Decapsulate(sk, ct.ForRecipient(i))
				require.NoError(t, err)
				require.Equal(t, payload, got)
				require.Equal(t, derived[i], k)
			}
		}
	})
}

func TestReply(t *testing.T) {
	forEachKEM(t, func(t *testing.T, s *Scheme) {
		pks, sks := keys(t, s, 2)
		derived, ct, err := s.Encapsulate(pks, []byte("hello"))
		require.NoError(t, err)

		k, _, err := s.Decapsulate(sks[1], ct.ForRecipient(1))
		require.NoError(t, err)
		reply, err := s.EnvelopeReply(k, []byte("reply from 1"))
		require.NoError(t, err)
		got, err := s.DecryptEnvelope(derived[1], reply)
		require.NoError(t, err)
		require.Equal(t, []byte("reply from 1"), got)

		_, err = s.DecryptEnvelope(derived[0], reply)
		require.Error(t, err)

		back, err := s.EnvelopeReply(derived[1], []byte("and back"))
		require.NoError(t, err)
		got, err = s.DecryptEnvelope(k, back)
		require.NoError(t, err)
		require.Equal(t, []byte("and back"), got)
	})
}

func TestRejects(t *testing.T) {
	forEachKEM(t, func(t *testing.T, s *Scheme) {
		pks, sks := keys(t, s, 3)
		_, ct, err := s.Encapsulate(pks, []byte("payload"))
		require.NoError(t, err)

		_, outsider := keys(t, s, 1)
		_, _, err = s.Decapsulate(outsider[0], ct)
		require.Error(t, err)

		_, _, err = s.Decapsulate(sks[0], ct.ForRecipient(1))
		require.Error(t, err)

		_, _, err = s.Decapsulate(sks[0], ct.ForRecipient(7))
		require.ErrorIs(t, err, ErrTrialDecryptFailed)

		tamper := func(f func(c *Ciphertext)) *Ciphertext {
			c, err := CiphertextFromBytes(s, ct.Marshal())
			require.NoError(t, err)
			f(c)
			return c.ForRecipient(0)
		}
		for name, c := range map[string]*Ciphertext{
			"envelope": tamper(func(c *Ciphertext) { c.Envelope[len(c.Envelope)-1] ^= 1 }),
			"dek":      tamper(func(c *Ciphertext) { c.DEKCiphertexts[0][NonceSize] ^= 1 }),
			"kem":      tamper(func(c *Ciphertext) { c.KEMCiphertexts[0][len(c.KEMCiphertexts[0])-1] ^= 1 }),
		} {
			_, _, err = s.Decapsulate(sks[0], c)
			require.Error(t, err, name)
		}

		_, _, err = s.Encapsulate(nil, []byte("payload"))
		require.ErrorIs(t, err, ErrNoRecipients)
	})
}

func TestCiphertextMarshal(t *testing.T) {
	forEachKEM(t, func(t *testing.T, s *Scheme) {
		pks, sks := keys(t, s, 2)
		_, ct, err := s.Encapsulate(pks, []byte("payload"))
		require.NoError(t, err)

		ct2, err := CiphertextFromBytes(s, ct.Marshal())
		require.NoError(t, err)
		require.Equal(t, ct, ct2)
		_, got, err := s.Decapsulate(sks[1], ct2)
		require.NoError(t, err)
		require.Equal(t, []byte("payload"), got)

		bad := *ct
		bad.DEKCiphertexts = bad.DEKCiphertexts[:1]
		_, err = CiphertextFromBytes(s, bad.Marshal())
		require.ErrorIs(t, err, ErrMalformedCiphertext)

		bad = *ct
		bad.KEMCiphertexts = [][]byte{ct.KEMCiphertexts[0][1:], ct.KEMCiphertexts[1]}
		_, err = CiphertextFromBytes(s, bad.Marshal())
		require.ErrorIs(t, err, ErrMalformedCiphertext)
	})
}
