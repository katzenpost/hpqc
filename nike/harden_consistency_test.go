// SPDX-License-Identifier: AGPL-3.0-only

package nike_test

import (
	"crypto/rand"
	"testing"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh512"
	"github.com/katzenpost/hpqc/nike/hybrid"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/nike/x448"
)

func TestNikeWrongTypeKeyReturnsNil(t *testing.T) {
	// A key from one scheme fed to another must yield nil rather than
	// panicking on a bad type assertion.
	otherPub, otherPriv, err := x25519.Scheme(rand.Reader).GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	schemes := []nike.Scheme{
		x448.Scheme(rand.Reader),
		ctidh512.Scheme(),
		hybrid.CTIDH512X25519,
	}
	for _, s := range schemes {
		if got := s.DeriveSecret(otherPriv, otherPub); got != nil {
			t.Fatalf("%s DeriveSecret: expected nil on wrong-type key", s.Name())
		}
		if got := s.DerivePublicKey(otherPriv); got != nil {
			t.Fatalf("%s DerivePublicKey: expected nil on wrong-type key", s.Name())
		}
		if got := s.Blind(otherPub, otherPriv); got != nil {
			t.Fatalf("%s Blind: expected nil on wrong-type key", s.Name())
		}
	}
}
