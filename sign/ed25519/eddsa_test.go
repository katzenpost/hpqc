// eddsa_test.go - Test eddsa wrapper signature scheme tests.
//
// Copyright (C) 2022  David Stainton.
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

package ed25519

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/util"
)

func TestEddsaScheme(t *testing.T) {
	t.Parallel()
	message := []byte("hello world")
	pubKey, privKey, err := Scheme().GenerateKey()
	require.NoError(t, err)
	signature := Scheme().Sign(privKey, message, nil)
	require.Equal(t, len(signature), Scheme().SignatureSize())
	ok := Scheme().Verify(pubKey, message, signature, nil)
	require.True(t, ok)
}

func TestEddsaSchemeTextUnmarshaler(t *testing.T) {
	t.Parallel()
	message := []byte("hello world")
	pubKey, privKey, err := Scheme().GenerateKey()
	require.NoError(t, err)

	pubKeyText, err := pubKey.MarshalBinary()
	require.NoError(t, err)

	pubKey2, err := Scheme().UnmarshalBinaryPublicKey(pubKeyText)
	require.NoError(t, err)

	signature := Scheme().Sign(privKey, message, nil)

	ok := Scheme().Verify(pubKey, message, signature, nil)
	require.True(t, ok)

	ok = Scheme().Verify(pubKey2, message, signature, nil)
	require.True(t, ok)
}

func TestKeypair(t *testing.T) {
	t.Parallel()

	var shortBuffer = []byte("Short Buffer")

	_, privKey, err := Scheme().GenerateKey()
	require.NoError(t, err, "NewKeypair()")

	var privKey2 PrivateKey
	require.Error(t, privKey2.FromBytes(shortBuffer))

	privKeyBlob, err := privKey.MarshalBinary()
	require.NoError(t, err)

	err = privKey2.FromBytes(privKeyBlob)
	require.NoError(t, err)

	privKeyBlob2, err := privKey2.MarshalBinary()
	require.NoError(t, err)

	require.Equal(t, privKeyBlob2, privKeyBlob)

	privKey2.Reset()
	require.True(t, util.CtIsZero(privKey2.privKey))

	var pubKey PublicKey
	require.Error(t, pubKey.FromBytes(shortBuffer))

	blob, err := privKey.(*PrivateKey).PublicKey().MarshalBinary()
	require.NoError(t, err)

	err = pubKey.FromBytes(blob)
	require.NoError(t, err)
	require.Equal(t, privKey.Public(), &pubKey)

	pkArr := pubKey.ByteArray()

	blob, err = privKey.Public().(*PublicKey).MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, blob, pkArr[:])
}

func TestEdDSAOps(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	_, privKey, err := Scheme().GenerateKey()
	require.NoError(t, err, "NewKeypair()")
	pubKey := privKey.Public().(*PublicKey)

	msg := []byte("The year was 2081, and everybody was finally equal.  They weren't only equal before God and the law.  They were equal every which way.  Nobody was smarter than anybody else.  Nobody was better looking than anybody else.  Nobody was stronger or quicker than anybody else.  All this equality was due to the 211th, 212th, and 213th Amendments to the Constitution, and to the unceasing vigilance of agents of the United States Handicapper General.")

	sig, err := privKey.Sign(nil, msg, nil)
	require.NoError(t, err)

	assert.Equal(SignatureSize, len(sig), "Sign() length")
	assert.True(pubKey.Verify(sig, msg), "Verify(sig, msg)")
	assert.False(pubKey.Verify(sig, msg[:16]), "Verify(sig, msg[:16])")
}

func TestCheckEdDSA(t *testing.T) {
	t.Parallel()
	// check that EdDSA signing works like the first test vector in
	// https://ed25519.cr.yp.to/python/sign.input
	// (this is a sanity check to ensure (R,s) is computed as it should
	// as it was non-obvious to me that the nonce is being clamped
	assert := assert.New(t)
	vector_signed := [64]byte{229, 86, 67, 0, 195, 96, 172, 114, 144, 134, 226, 204, 128, 110, 130, 138, 132, 135, 127, 30, 184, 229, 217, 116, 216, 115, 224, 101, 34, 73, 1, 85, 95, 184, 130, 21, 144, 163, 59, 172, 198, 30, 57, 112, 28, 249, 180, 107, 210, 91, 245, 240, 89, 91, 190, 36, 101, 81, 65, 67, 142, 122, 16, 11}
	tsk := [64]byte{157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73, 197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96, 215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26}
	tpk := [32]byte{215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243, 218, 166, 35, 37, 175, 2, 26, 104, 247, 7, 81, 26}
	rsk := new(PrivateKey)
	assert.NoError(rsk.FromBytes(tsk[:]))
	assert.Equal(tpk[:], rsk.PublicKey().Bytes())
	actual_signed, err := rsk.Sign(nil, []byte{}, nil)
	require.NoError(t, err)
	assert.Equal(vector_signed[:], actual_signed)
	verify_res := rsk.PublicKey().Verify(vector_signed[:], []byte{})
	assert.Equal(true, verify_res)
	// and 1 was NOT the message, so that shouldn't check out:
	verify_res = rsk.PublicKey().Verify(vector_signed[:], []byte{1})
	assert.Equal(false, verify_res)
}
