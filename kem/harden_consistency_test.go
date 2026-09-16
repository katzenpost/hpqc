// SPDX-License-Identifier: AGPL-3.0-only

package kem_test

import (
	"crypto/rand"
	"testing"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/adapter"
	"github.com/katzenpost/hpqc/kem/mlkem768"
	"github.com/katzenpost/hpqc/kem/xwing"
	"github.com/katzenpost/hpqc/nike/x25519"
)

func mustPub(t *testing.T, s kem.Scheme) kem.PublicKey {
	t.Helper()
	pk, _, err := s.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func TestEncapsulateWrongTypeReturnsError(t *testing.T) {
	xwingPub := mustPub(t, xwing.Scheme())
	mlkemPub := mustPub(t, mlkem768.Scheme())

	if _, _, err := xwing.Scheme().Encapsulate(mlkemPub); err == nil {
		t.Fatal("xwing Encapsulate: expected error on wrong-type key")
	}
	if _, _, err := mlkem768.Scheme().Encapsulate(xwingPub); err == nil {
		t.Fatal("mlkem768 Encapsulate: expected error on wrong-type key")
	}
}

func TestEqualWrongTypeReturnsFalse(t *testing.T) {
	xwingPub := mustPub(t, xwing.Scheme())
	mlkemPub := mustPub(t, mlkem768.Scheme())
	adapterPub := mustPub(t, adapter.FromNIKE(x25519.Scheme(rand.Reader)))

	if xwingPub.Equal(mlkemPub) {
		t.Fatal("xwing Equal: expected false on wrong-type key")
	}
	if mlkemPub.Equal(xwingPub) {
		t.Fatal("mlkem768 Equal: expected false on wrong-type key")
	}
	if adapterPub.Equal(xwingPub) {
		t.Fatal("adapter Equal: expected false on wrong-type key")
	}
}

func TestEncapsulateDeterministicallyReturnsError(t *testing.T) {
	s := adapter.FromNIKE(x25519.Scheme(rand.Reader))
	pub := mustPub(t, s)
	if _, _, err := s.(interface {
		EncapsulateDeterministically(kem.PublicKey, []byte) ([]byte, []byte, error)
	}).EncapsulateDeterministically(pub, make([]byte, s.SeedSize())); err == nil {
		t.Fatal("adapter EncapsulateDeterministically: expected error")
	}
}
