// ecdh.go - Adapts ecdh module to our NIKE interface.
// Copyright (C) 2022  David Stainton and Yawning Angel
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package x25519

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/util"
)

func TestEcdhNike(t *testing.T) {
	ecdhNike := Scheme(rand.Reader)

	alicePublicKey, alicePrivateKey, err := ecdhNike.GenerateKeyPair()
	require.NoError(t, err)

	tmp := alicePrivateKey.(*PrivateKey).Public()
	require.Equal(t, alicePublicKey.Bytes(), tmp.Bytes())

	bobKeypair, err := NewKeypair(rand.Reader)
	require.NoError(t, err)

	aliceS := ecdhNike.DeriveSecret(alicePrivateKey, bobKeypair.Public())

	bobS := Exp(alicePublicKey.Bytes(), bobKeypair.Bytes())
	require.Equal(t, bobS, aliceS)
}

func TestPrivateKey(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	var shortBuffer = []byte("Short Buffer")

	privKey, err := NewKeypair(rand.Reader)
	require.NoError(t, err, "NewKeypair failed")

	var privKey2 PrivateKey
	assert.Error(privKey2.FromBytes(shortBuffer), "PrivateKey.FromBytes(short)")

	err = privKey2.FromBytes(privKey.Bytes())
	assert.NoError(err, "PrivateKey.ToBytes()->FromBytes()")
	assert.Equal(privKey, &privKey2, "PrivateKey.ToBytes()->FromBytes()")

	privKey2.Reset()
	assert.True(util.CtIsZero(privKey2.Bytes()), "PrivateKey.Reset()")

	var pubKey PublicKey
	assert.Error(pubKey.FromBytes(shortBuffer), "PublicKey.FromBytes(short)")

	err = pubKey.FromBytes(privKey.Public().Bytes())
	assert.NoError(err, "PrivateKey.PublicKey().Bytes->FromBytes()")
	assert.Equal(privKey.Public().Bytes(), pubKey.Bytes(), "PrivateKey.PublicKey().Bytes->FromBytes()")
}

func TestECDHOps(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	aliceKeypair, err := NewKeypair(rand.Reader)
	require.NoError(t, err, "NewKeygen() Alice failed")

	var bobSk, bobPk, bobS, tmp [GroupElementLength]byte
	_, err = rand.Reader.Read(bobSk[:])
	require.NoError(t, err, "failed to generate bobSk")
	curve25519.ScalarBaseMult(&bobPk, &bobSk)

	curve25519.ScalarBaseMult(&tmp, &aliceKeypair.privBytes)
	assert.Equal(aliceKeypair.Public().Bytes(), tmp[:], "ExpG() mismatch against X25519 scalar base mult")

	aliceS := Exp(bobPk[:], aliceKeypair.privBytes[:])
	copy(tmp[:], aliceKeypair.Public().Bytes())
	curve25519.ScalarMult(&bobS, &bobSk, &tmp)
	assert.Equal(bobS[:], aliceS, "Exp() mismatch against X25519 scalar mult")
}
