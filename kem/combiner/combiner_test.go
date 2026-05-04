// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package combiner_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/adapter"
	"github.com/katzenpost/hpqc/kem/combiner"
	"github.com/katzenpost/hpqc/kem/mlkem768"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

// newTestScheme builds a fast hybrid (MLKEM768 + X25519) for the unit
// tests. CTIDH is deliberately avoided: it is correct elsewhere, but
// slow enough to dominate runtime here.
func newTestScheme(t *testing.T) kem.Scheme {
	t.Helper()
	s, err := combiner.New("MLKEM768-X25519", []kem.Scheme{
		mlkem768.Scheme(),
		adapter.FromNIKE(x25519.Scheme(rand.Reader)),
	})
	if err != nil {
		t.Fatalf("combiner.New: %v", err)
	}
	return s
}

func TestNewRejectsNilSubScheme(t *testing.T) {
	_, err := combiner.New("bad", []kem.Scheme{mlkem768.Scheme(), nil})
	if !errors.Is(err, combiner.ErrNilScheme) {
		t.Fatalf("expected ErrNilScheme, got %v", err)
	}
}

func TestNewRejectsEmptySchemes(t *testing.T) {
	_, err := combiner.New("empty", nil)
	if !errors.Is(err, combiner.ErrEmptySchemes) {
		t.Fatalf("expected ErrEmptySchemes, got %v", err)
	}
}

func TestRoundTrip(t *testing.T) {
	s := newTestScheme(t)
	pub, priv, err := s.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	ct, ssEnc, err := s.Encapsulate(pub)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}
	if len(ct) != s.CiphertextSize() {
		t.Fatalf("ciphertext size %d != advertised %d", len(ct), s.CiphertextSize())
	}
	if len(ssEnc) != s.SharedKeySize() {
		t.Fatalf("shared key size %d != advertised %d", len(ssEnc), s.SharedKeySize())
	}

	ssDec, err := s.Decapsulate(priv, ct)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}
	if !bytes.Equal(ssEnc, ssDec) {
		t.Fatal("encapsulated and decapsulated shared secrets differ")
	}
}

func TestPublicKeyMarshalRoundTrip(t *testing.T) {
	s := newTestScheme(t)
	pub, _, err := s.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	blob, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(blob) != s.PublicKeySize() {
		t.Fatalf("public key blob size %d != advertised %d", len(blob), s.PublicKeySize())
	}
	pub2, err := s.UnmarshalBinaryPublicKey(blob)
	if err != nil {
		t.Fatalf("UnmarshalBinaryPublicKey: %v", err)
	}
	if !pub.Equal(pub2) {
		t.Fatal("round-tripped public key is not Equal to original")
	}
}

func TestPrivateKeyMarshalRoundTrip(t *testing.T) {
	s := newTestScheme(t)
	_, priv, err := s.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	blob, err := priv.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(blob) != s.PrivateKeySize() {
		t.Fatalf("private key blob size %d != advertised %d", len(blob), s.PrivateKeySize())
	}
	priv2, err := s.UnmarshalBinaryPrivateKey(blob)
	if err != nil {
		t.Fatalf("UnmarshalBinaryPrivateKey: %v", err)
	}
	if !priv.Equal(priv2) {
		t.Fatal("round-tripped private key is not Equal to original")
	}
}

func TestUnmarshalRejectsWrongSize(t *testing.T) {
	s := newTestScheme(t)
	if _, err := s.UnmarshalBinaryPublicKey(make([]byte, s.PublicKeySize()-1)); !errors.Is(err, kem.ErrPubKeySize) {
		t.Fatalf("expected ErrPubKeySize, got %v", err)
	}
	if _, err := s.UnmarshalBinaryPrivateKey(make([]byte, s.PrivateKeySize()+1)); !errors.Is(err, kem.ErrPrivKeySize) {
		t.Fatalf("expected ErrPrivKeySize, got %v", err)
	}
}

func TestDecapsulateRejectsWrongCiphertextSize(t *testing.T) {
	s := newTestScheme(t)
	_, priv, err := s.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if _, err := s.Decapsulate(priv, make([]byte, s.CiphertextSize()-1)); !errors.Is(err, kem.ErrCiphertextSize) {
		t.Fatalf("expected ErrCiphertextSize, got %v", err)
	}
}

// TestCrossSchemeKeyRejected ensures that a public key whose underlying
// scheme is a *different* combiner instance is refused, rather than
// silently misindexed or panicking.
func TestCrossSchemeKeyRejected(t *testing.T) {
	a := newTestScheme(t)
	// b has the same components in the opposite order, so the key sizes
	// happen to match but the scheme pointers do not.
	b, err := combiner.New("X25519-MLKEM768", []kem.Scheme{
		adapter.FromNIKE(x25519.Scheme(rand.Reader)),
		mlkem768.Scheme(),
	})
	if err != nil {
		t.Fatalf("combiner.New: %v", err)
	}
	pub, _, err := b.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if _, _, err := a.Encapsulate(pub); !errors.Is(err, kem.ErrTypeMismatch) {
		t.Fatalf("expected ErrTypeMismatch, got %v", err)
	}
}

func TestEqualOnDifferentSchemesReturnsFalse(t *testing.T) {
	a := newTestScheme(t)
	b, err := combiner.New("MLKEM768-X25519-other", []kem.Scheme{
		mlkem768.Scheme(),
		adapter.FromNIKE(x25519.Scheme(rand.Reader)),
	})
	if err != nil {
		t.Fatalf("combiner.New: %v", err)
	}
	pubA, privA, err := a.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubB, privB, err := b.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if pubA.Equal(pubB) {
		t.Fatal("public keys from different scheme instances must not compare Equal")
	}
	if privA.Equal(privB) {
		t.Fatal("private keys from different scheme instances must not compare Equal")
	}
}

func TestSplitPRFOrderDependence(t *testing.T) {
	// Different scheme instances with the *same* sub-schemes in *different*
	// orders should yield distinct shared secrets for an otherwise identical
	// key/ciphertext pair, because the SplitPRF concatenation order changes.
	forward, err := combiner.New("forward", []kem.Scheme{
		mlkem768.Scheme(),
		adapter.FromNIKE(x25519.Scheme(rand.Reader)),
	})
	if err != nil {
		t.Fatalf("combiner.New: %v", err)
	}
	reverse, err := combiner.New("reverse", []kem.Scheme{
		adapter.FromNIKE(x25519.Scheme(rand.Reader)),
		mlkem768.Scheme(),
	})
	if err != nil {
		t.Fatalf("combiner.New: %v", err)
	}
	pubF, _, err := forward.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubR, _, err := reverse.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	_, ssF, err := forward.Encapsulate(pubF)
	if err != nil {
		t.Fatalf("Encapsulate forward: %v", err)
	}
	_, ssR, err := reverse.Encapsulate(pubR)
	if err != nil {
		t.Fatalf("Encapsulate reverse: %v", err)
	}
	if bytes.Equal(ssF, ssR) {
		t.Fatal("shared secrets across reordered schemes collided; SplitPRF must be order-sensitive")
	}
}
