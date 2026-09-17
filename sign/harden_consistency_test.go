// SPDX-License-Identifier: AGPL-3.0-only

package sign_test

import (
	"testing"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/sign/hybrid"
	"github.com/katzenpost/hpqc/sign/mldsa"
	"github.com/katzenpost/hpqc/sign/sphincsplus"
)

func genKeys(t *testing.T, s sign.Scheme) (sign.PublicKey, sign.PrivateKey) {
	t.Helper()
	pub, priv, err := s.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

type signEqCase struct {
	name string
	pub  sign.PublicKey
	priv sign.PrivateKey
}

func TestSignEqualWrongTypeReturnsFalse(t *testing.T) {
	edPub, edPriv := genKeys(t, ed25519.Scheme())
	mldsaPub, mldsaPriv := genKeys(t, mldsa.Scheme44())
	hybridPub, hybridPriv := genKeys(t, hybrid.MLDSA44Ed25519)

	cases := []signEqCase{
		{"ed25519", edPub, edPriv},
		{"hybrid", hybridPub, hybridPriv},
	}
	if s := sphincsplus.Scheme(); s != nil {
		sphincsPub, sphincsPriv := genKeys(t, s)
		cases = append(cases, signEqCase{"sphincsplus", sphincsPub, sphincsPriv})
	}
	for _, c := range cases {
		if c.pub.Equal(mldsaPub) {
			t.Fatalf("%s PublicKey.Equal: expected false on wrong-type key", c.name)
		}
		if c.priv.Equal(mldsaPriv) {
			t.Fatalf("%s PrivateKey.Equal: expected false on wrong-type key", c.name)
		}
	}
}
