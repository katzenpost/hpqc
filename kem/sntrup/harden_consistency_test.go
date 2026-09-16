// SPDX-License-Identifier: AGPL-3.0-only

package sntrup

import "testing"

func TestEqualNilInnerKeyReturnsFalse(t *testing.T) {
	if new(PublicKey).Equal(new(PublicKey)) {
		t.Fatal("PublicKey.Equal: expected false on nil inner key")
	}
	if new(PrivateKey).Equal(new(PrivateKey)) {
		t.Fatal("PrivateKey.Equal: expected false on nil inner key")
	}
}
