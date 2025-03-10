// SPDX-FileCopyrightText: Copyright (C) 2022-2024  David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only

package ctidh2048

import (
	"testing"

	"github.com/stretchr/testify/require"

	ctidh "codeberg.org/vula/highctidh/src/ctidh2048"
)

func TestCTIDH2048_NIKE(t *testing.T) {
	ctidhNike := Scheme()

	alicePublicKey, alicePrivateKey, err := ctidhNike.GenerateKeyPair()
	require.NoError(t, err)

	tmp := ctidh.DerivePublicKey(alicePrivateKey.(*PrivateKey).privateKey)
	require.Equal(t, alicePublicKey.Bytes(), tmp.Bytes())

	bobPubKey, bobPrivKey, err := ctidhNike.GenerateKeyPair()
	require.NoError(t, err)

	aliceS := ctidhNike.DeriveSecret(alicePrivateKey, bobPubKey)

	bobS := ctidh.DeriveSecret(bobPrivKey.(*PrivateKey).privateKey, alicePublicKey.(*PublicKey).publicKey)
	require.Equal(t, bobS, aliceS)
}
