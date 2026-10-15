// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package mrhybrid

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
)

// validCiphertext returns a well formed ciphertext of n pairs that no key
// opens.
func validCiphertext(s *Scheme, n int) *Ciphertext {
	c := &Ciphertext{Envelope: make([]byte, EnvelopeOverhead)}
	for range n {
		c.KEMCiphertexts = append(c.KEMCiphertexts, make([]byte, s.KEM().CiphertextSize()))
		c.DEKCiphertexts = append(c.DEKCiphertexts, make([]byte, DEKSize))
	}
	return c
}

func TestNilInputsErrorNotPanic(t *testing.T) {
	forEachKEM(t, func(t *testing.T, s *Scheme) {
		pks, sks := keys(t, s, 1)
		require.NotPanics(t, func() {
			_, _, err := s.Decapsulate(sks[0], nil)
			require.ErrorIs(t, err, ErrNilCiphertext)

			_, _, err = s.Decapsulate(nil, validCiphertext(s, 1))
			require.ErrorIs(t, err, ErrNilKey)

			_, _, err = s.Encapsulate([]kem.PublicKey{pks[0], nil}, []byte("payload"))
			require.ErrorIs(t, err, ErrNilKey)

			_, err = CiphertextFromBytes(nil, validCiphertext(s, 1).Marshal())
			require.ErrorIs(t, err, ErrInvalidScheme)

			var c *Ciphertext
			require.Empty(t, c.ForRecipient(0).KEMCiphertexts)
		})
	})

	for _, s := range []*Scheme{nil, NewScheme(nil)} {
		require.NotPanics(t, func() {
			require.Empty(t, s.Name())
			_, _, err := s.GenerateKeyPair()
			require.ErrorIs(t, err, ErrInvalidScheme)
			_, _, err = s.Encapsulate(nil, nil)
			require.ErrorIs(t, err, ErrInvalidScheme)
			_, _, err = s.Decapsulate(nil, nil)
			require.ErrorIs(t, err, ErrInvalidScheme)
		})
	}
}

// Several KEMs type-assert the private key in Decapsulate and panic on a key
// of another scheme. Decapsulate must turn that into an error.
func TestForeignKeysErrorNotPanic(t *testing.T) {
	s := NewScheme(schemes.ByName("MLKEM768"))
	foreignPk, foreignSk, err := schemes.ByName("XWING").GenerateKeyPair()
	require.NoError(t, err)

	require.NotPanics(t, func() {
		_, _, err := s.Decapsulate(foreignSk, validCiphertext(s, 1))
		require.ErrorIs(t, err, ErrDecapFailed)

		_, _, err = s.Encapsulate([]kem.PublicKey{foreignPk}, []byte("payload"))
		require.Error(t, err)
	})
}

func TestRecipientLimit(t *testing.T) {
	s := NewScheme(schemes.ByName("X25519"))
	pks, sks := keys(t, s, MaxRecipients+1)

	_, _, err := s.Encapsulate(pks, []byte("payload"))
	require.ErrorIs(t, err, ErrTooManyRecipients)

	_, ct, err := s.Encapsulate(pks[:MaxRecipients], []byte("payload"))
	require.NoError(t, err)
	ct2, err := CiphertextFromBytes(s, ct.Marshal())
	require.NoError(t, err)
	_, got, err := s.Decapsulate(sks[MaxRecipients-1], ct2)
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), got)

	big := validCiphertext(s, MaxRecipients+1)
	_, err = CiphertextFromBytes(s, big.Marshal())
	require.Error(t, err)
	_, _, err = s.Decapsulate(sks[0], big)
	require.ErrorIs(t, err, ErrMalformedCiphertext)
}

// Decapsulate is also handed ciphertexts that never went through
// CiphertextFromBytes, so it checks their shape itself.
func TestDecapsulateRejectsMalformed(t *testing.T) {
	forEachKEM(t, func(t *testing.T, s *Scheme) {
		_, sks := keys(t, s, 1)
		size := s.KEM().CiphertextSize()
		for name, f := range map[string]func(c *Ciphertext){
			"short kem":      func(c *Ciphertext) { c.KEMCiphertexts[0] = make([]byte, 1) },
			"long kem":       func(c *Ciphertext) { c.KEMCiphertexts[0] = make([]byte, size+1) },
			"nil kem":        func(c *Ciphertext) { c.KEMCiphertexts[0] = nil },
			"short dek":      func(c *Ciphertext) { c.DEKCiphertexts[0] = make([]byte, 5) },
			"long dek":       func(c *Ciphertext) { c.DEKCiphertexts[0] = make([]byte, DEKSize+1) },
			"short envelope": func(c *Ciphertext) { c.Envelope = make([]byte, EnvelopeOverhead-1) },
			"unpaired":       func(c *Ciphertext) { c.DEKCiphertexts = c.DEKCiphertexts[:1] },
		} {
			c := validCiphertext(s, 2)
			f(c)
			require.NotPanics(t, func() {
				_, _, err := s.Decapsulate(sks[0], c)
				require.ErrorIs(t, err, ErrMalformedCiphertext, name)
			}, name)
		}
	})
}

func TestCiphertextFromBytesStrict(t *testing.T) {
	s := NewScheme(schemes.ByName("X25519"))
	good := validCiphertext(s, 1)

	enc := func(v any) []byte {
		b, err := cbor.Marshal(v)
		require.NoError(t, err)
		return b
	}
	for name, b := range map[string][]byte{
		"empty":         nil,
		"garbage":       {0xff, 0x00, 0x13},
		"no recipients": (&Ciphertext{Envelope: good.Envelope}).Marshal(),
		"unknown field": enc(map[string]any{
			"KEMCiphertexts": good.KEMCiphertexts, "DEKCiphertexts": good.DEKCiphertexts,
			"Envelope": good.Envelope, "Extra": 1,
		}),
		"case folded": enc(map[string]any{
			"kemciphertexts": good.KEMCiphertexts, "DEKCiphertexts": good.DEKCiphertexts,
			"Envelope": good.Envelope,
		}),
		// A map header claiming 2^32 pairs, and an array header claiming
		// 2^32 elements, with no bytes behind them.
		"huge map":   {0xba, 0xff, 0xff, 0xff, 0xff},
		"huge array": {0xa1, 0x6e, 'K', 'E', 'M', 'C', 'i', 'p', 'h', 'e', 'r', 't', 'e', 'x', 't', 's', 0x9a, 0xff, 0xff, 0xff, 0xff},
		"indefinite": {0xbf, 0xff},
		"tagged":     append([]byte{0xd8, 0x2a}, good.Marshal()...),
	} {
		require.NotPanics(t, func() {
			_, err := CiphertextFromBytes(s, b)
			require.Error(t, err, name)
		}, name)
	}

	c, err := CiphertextFromBytes(s, good.Marshal())
	require.NoError(t, err)
	require.Equal(t, good, c)
}

func TestShortReplyEnvelope(t *testing.T) {
	s := NewScheme(schemes.ByName("X25519"))
	key := make([]byte, KeySize)
	for n := range EnvelopeOverhead + 1 {
		require.NotPanics(t, func() {
			_, err := s.DecryptEnvelope(key, make([]byte, n))
			require.Error(t, err)
		})
	}
	_, err := s.DecryptEnvelope(make([]byte, KeySize-1), make([]byte, 64))
	require.ErrorIs(t, err, ErrInvalidKeySize)
}

func FuzzCiphertextFromBytes(f *testing.F) {
	s := NewScheme(schemes.ByName("X25519"))
	_, sk, err := s.GenerateKeyPair()
	require.NoError(f, err)
	pk := sk.Public()
	_, ct, err := s.Encapsulate([]kem.PublicKey{pk, pk}, []byte("payload"))
	require.NoError(f, err)
	f.Add(ct.Marshal())
	f.Add(validCiphertext(s, 1).Marshal())
	f.Add([]byte{0xa0})

	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := CiphertextFromBytes(s, b)
		if err != nil {
			return
		}
		_, _, _ = s.Decapsulate(sk, c)
		_, _, _ = s.Decapsulate(sk, c.ForRecipient(0))
	})
}
