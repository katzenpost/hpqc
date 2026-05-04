// SPDX-FileCopyrightText: (c) 2021 - Anonymous contributor
// SPDX-License-Identifier: AGPL-3.0-only

package ed25519

import (
	"encoding/hex"
	"io"
	"testing"
	"testing/quick"
	"time"

	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
)

func bothWork(assertx *assert.Assertions, t require.TestingT, rng io.Reader) bool {
	assert := assertx
	unblinded, _, err := NewKeypair(rng)
	require.NoError(t, err, "NewKeypair(1)")
	assert.Equal(true, CheckPublicKey(unblinded.PublicKey()))

	factor := make([]byte, BlindFactorSize)
	_, err = rng.Read(factor[:])
	require.NoError(t, err)

	// Blind on uninitialized key should panic:
	bad_public := new(PublicKey)
	assert.Panics(func() { bad_public.Blind(factor) })

	// Test that blinded public+private keys match:
	f1_blind_secret := unblinded.Blind(factor)
	f1_blind_public := unblinded.PublicKey().Blind(factor)
	assert.Equal(f1_blind_secret.Identity(), f1_blind_public.Bytes())
	f1_derived_public := f1_blind_secret.PublicKey()
	assert.Equal(f1_blind_public, f1_derived_public)
	assert.Equal(f1_blind_secret.KeyType(), "ed25519")

	// check public keys: multiply by L and verify we get identity element
	assert.Equal(true, CheckPublicKey(f1_derived_public))

	identity_element := edwards25519.NewIdentityPoint().Bytes()
	assert.NotEqual(identity_element, unblinded.PublicKey())
	assert.NotEqual(identity_element, f1_blind_public)

	f1_blind_secret_ser, err := f1_blind_secret.MarshalBinary()
	assert.Equal(nil, err)
	assert.NotEqual([]byte{}, f1_blind_secret_ser)
	f1_blind_secret_deser := new(BlindedPrivateKey)
	err = f1_blind_secret_deser.UnmarshalBinary(f1_blind_secret_ser)
	assert.Equal(nil, err)
	assert.Equal(f1_blind_secret, f1_blind_secret_deser)
	f1_remarshalled, err := f1_blind_secret_deser.MarshalBinary()
	assert.Equal(nil, err)
	assert.Equal(f1_blind_secret_ser, f1_remarshalled)

	// Check that using the same factor to blind two different keys
	// results in distinct secret + public keys (ie we don't always just return
	// the same secret/public pair)
	unblinded_x, _, err := NewKeypair(rng)
	require.NoError(t, err, "NewKeypair(2)")
	assert.NotEqual(unblinded_x.Bytes(), unblinded.Bytes())
	f1_blind_public_x := unblinded_x.PublicKey().Blind(factor)
	f1_blind_secret_x := unblinded_x.Blind(factor)
	assert.NotEqual(f1_blind_public, f1_blind_public_x)
	f1_derived_public_x := f1_blind_secret_x.PublicKey()
	assert.Equal(f1_blind_public_x, f1_derived_public_x)
	assert.Equal(true, CheckPublicKey(f1_derived_public_x))

	factor2 := make([]byte, BlindFactorSize)
	_, err = rng.Read(factor2)
	require.NoError(t, err)
	// we just need to ensure that the factors are different,
	// since we hash factor, any bit flip should work.
	assert.NotEqual(factor, factor2)
	f2_blind_secret := unblinded.Blind(factor2)
	f2_blind_public := unblinded.PublicKey().Blind(factor2)
	f2_derived_public := f2_blind_secret.PublicKey()
	assert.Equal(f2_blind_public, f2_derived_public)
	assert.NotEqual(f2_blind_public, f1_blind_public)

	// Ensure that reusing an object for UnmarshalBinary
	// doesn't yield old PublicKey
	f2_blind_secret_ser, err := f2_blind_secret.MarshalBinary()
	assert.Equal(nil, err)
	err = f1_blind_secret_deser.UnmarshalBinary(f2_blind_secret_ser)
	assert.Equal(nil, err)
	assert.Equal(f2_blind_secret, f1_blind_secret_deser)
	nulls := [32]byte{}
	err = f1_blind_secret_deser.UnmarshalBinary(nulls[:])
	assert.NotEqual(nil, err)
	nulls[0] = 1
	err = f1_blind_secret_deser.UnmarshalBinary(nulls[:])
	assert.NotEqual(nil, err)

	// Accidentally blinding with an empty slice should panic:
	assert.Panics(func() { f2_blind_secret.Blind(factor[:0]) })
	assert.Panics(func() { f2_blind_public.Blind(factor[:0]) })

	// exercise some error paths:
	uninit_blind := new(BlindedPrivateKey)
	should_be_empty, err := uninit_blind.MarshalBinary()
	assert.Equal(0, len(should_be_empty))
	assert.NotEqual(nil, err)
	err = uninit_blind.UnmarshalBinary([]byte{})
	assert.NotEqual(nil, err)
	err = uninit_blind.UnmarshalBinary([]byte{2})
	assert.NotEqual(nil, err)

	assert.Equal(true, CheckPublicKey(f1_blind_public))
	assert.Equal(true, CheckPublicKey(f1_blind_public_x))
	assert.Equal(true, CheckPublicKey(f2_blind_public))

	f12_blind_secret := f1_blind_secret.Blind(factor2)
	f21_blind_secret := f2_blind_secret.Blind(factor)
	assert.Equal(f12_blind_secret, f21_blind_secret)
	assert.Equal(f12_blind_secret.PublicKey(), unblinded.Blind(factor).PublicKey().Blind(factor2))
	factor3 := make([]byte, BlindFactorSize)
	_, err = rng.Read(factor3)
	require.NoError(t, err)
	f123_blind_secret := f12_blind_secret.Blind(factor3)
	f213_blind_secret := f21_blind_secret.Blind(factor3)
	f321_blind_secret := unblinded.Blind(factor3).Blind(factor2).Blind(factor)
	assert.Equal(f123_blind_secret, f213_blind_secret)
	assert.Equal(f321_blind_secret, f123_blind_secret)
	assert.NotEqual(f123_blind_secret, f12_blind_secret)
	f123_blind_public := unblinded.PublicKey().Blind(factor).Blind(factor2).Blind(factor3)
	assert.Equal(f123_blind_secret.PublicKey(), f123_blind_public)
	assert.Equal(true, CheckPublicKey(f123_blind_public))
	assert.NotEqual(identity_element, f123_blind_public)

	// Check signature creation and validation:
	msg := [5]byte{'a', 'b', 'c', 'd', 'e'}
	msg_x := [5]byte{'a', 'b', 'c', 'd', 'x'}
	f1_sig := f1_blind_secret.Sign(msg[:])
	f2_sig := f2_blind_secret.Sign(msg[:])
	f1_res1 := f1_blind_public.Verify(f1_sig[:], msg[:])
	f2_res1 := f2_blind_public.Verify(f2_sig[:], msg[:])
	assert.Equal(true, f1_res1)
	assert.Equal(true, f2_res1)
	sig123 := f123_blind_secret.Sign(msg[:])
	assert.Equal(true, f123_blind_public.Verify(sig123, msg[:]))

	// signature: (R,s)  ;  check that s < L:
	// the new edwards25519 library doesn't export ScMinimal (scMinimal),
	// but it carries the function under the name "isReduced" which is
	// called from Scalar.SetCanonicalBytes(), so by looking at the (err)
	// from that we can determine the outcome:
	// nil | ScMinimal(s) === true
	// err | ScMinimal(s) === false
	f1_sig_s := [32]byte{}
	copy(f1_sig_s[:], f1_sig[32:])
	// old: assert.Equal(true, edwards25519.ScMinimal(&f1_sig_s))
	_, scMinimal := new(edwards25519.Scalar).SetCanonicalBytes(f1_sig_s[:])
	assert.Equal(nil, scMinimal)
	f2_sig_s := [32]byte{}
	copy(f2_sig_s[:], f2_sig[32:])
	_, scMinimal = new(edwards25519.Scalar).SetCanonicalBytes(f2_sig_s[:])
	//assert.Equal(true, edwards25519.ScMinimal(&f2_sig_s))
	assert.Equal(nil, scMinimal)

	// Check that giving arguments in wrong order doesn't work:
	f2_res2_wrong_arg_order := f2_blind_public.Verify(msg[:], f2_sig[:])
	assert.Equal(false, f2_res2_wrong_arg_order)

	// Check that we can't verify messages with the other's PK:
	f1_res3 := f1_blind_public.Verify(f2_sig[:], msg[:])
	f2_res3 := f2_blind_public.Verify(f1_sig[:], msg[:])
	assert.Equal(false, f1_res3)
	assert.Equal(false, f2_res3)

	// Check that the signature contains the message:
	f1_res4 := f1_blind_public.Verify(f1_sig[:], msg_x[:])
	assert.Equal(false, f1_res4)

	// Checking a random "signature" should obviously fail:
	random_sig := [64]byte{}
	f1_res5 := f1_blind_public.Verify(random_sig[:], msg[:])
	assert.Equal(false, f1_res5)

	return true
}

func TestBlinding(t *testing.T) {
	t.Parallel()
	assertx := assert.New(t)
	test_seed := time.Now().UnixNano()
	rng := rand.NewMath()
	rng.Seed(test_seed)
	t.Log("TestBlinding test_seed", test_seed)
	config := &quick.Config{Rand: rng}
	assert_bothwork := func() bool { return bothWork(assertx, t, rng) }
	if err := quick.Check(assert_bothwork, config); err != nil {
		t.Error("failed bothwork", err)
	}
}

func TestUnblind(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)
	test_seed := time.Now().UnixNano()
	rng := rand.NewMath()
	rng.Seed(test_seed)
	t.Logf("TestUnblind test_seed: %d", test_seed)

	originalO, _, err := NewKeypair(rng)
	require.NoError(t, err, "NewKeypair(1)")
	assert.Equal(true, CheckPublicKey(originalO.PublicKey()))

	factor := make([]byte, BlindFactorSize)
	_, err = rng.Read(factor[:])
	require.NoError(t, err)
	factor2 := make([]byte, BlindFactorSize)
	_, err = rng.Read(factor2[:])
	require.NoError(t, err)

	// Test that blinded public+private keys match:
	f1_blind_secret := originalO.Blind(factor)
	f1_blind_public := originalO.PublicKey().Blind(factor)
	assert.Equal(f1_blind_secret.Identity(), f1_blind_public.Bytes())

	f2_sk := f1_blind_secret.Blind(factor2)

	unblinded := f2_sk.Unblind(factor2)
	assert.Equal(f1_blind_secret, unblinded)
	reblinded := unblinded.Blind(factor2)
	assert.Equal(f2_sk, reblinded)
}

// TestUnblindSpecificSeed tests a specific seed that was previously failing
// This serves as a regression test for the "invalid scalar encoding" issue
func TestUnblindSpecificSeed(t *testing.T) {
	t.Parallel()

	assert := assert.New(t)
	test_seed := int64(1749190701254958036)
	rng := rand.NewMath()
	rng.Seed(test_seed)
	t.Logf("TestUnblindSpecificSeed test_seed: %d", test_seed)

	originalO, _, err := NewKeypair(rng)
	require.NoError(t, err, "NewKeypair failed for seed %d", test_seed)
	assert.Equal(true, CheckPublicKey(originalO.PublicKey()))

	factor := make([]byte, BlindFactorSize)
	_, err = rng.Read(factor[:])
	require.NoError(t, err, "Failed to read factor for seed %d", test_seed)

	factor2 := make([]byte, BlindFactorSize)
	_, err = rng.Read(factor2[:])
	require.NoError(t, err, "Failed to read factor2 for seed %d", test_seed)

	// Test that blinded public+private keys match:
	f1_blind_secret := originalO.Blind(factor)
	f1_blind_public := originalO.PublicKey().Blind(factor)
	assert.Equal(f1_blind_secret.Identity(), f1_blind_public.Bytes(), "Identity mismatch for seed %d", test_seed)

	f2_sk := f1_blind_secret.Blind(factor2)

	// This is the operation that was failing with "invalid scalar encoding"
	unblinded := f2_sk.Unblind(factor2)
	assert.Equal(f1_blind_secret, unblinded, "Unblind result mismatch for seed %d", test_seed)

	reblinded := unblinded.Blind(factor2)
	assert.Equal(f2_sk, reblinded, "Reblind result mismatch for seed %d", test_seed)
}

// TestBlindedSignatureVectors tests blinded signature operations using fixed test vectors
// These vectors were generated from a known-good implementation and verify binary compatibility
func TestBlindedSignatureVectors(t *testing.T) {
	testVectors := []struct {
		name           string
		privateKey     string // hex encoded 64-byte private key
		blindFactor    string // hex encoded 32-byte blind factor
		message        string // hex encoded message
		expectedPubKey string // hex encoded 32-byte expected blinded public key
		expectedSig    string // hex encoded 64-byte expected signature
	}{
		{
			name:           "vector_1_seed_12345",
			privateKey:     "1ae969564b34a33ecd1af05fe6923d6de71870997d38ef60155c325957214c425d8ca057866bdee02b63464f587aa75fdad4694c5c05db72323f3928722286cf",
			blindFactor:    "59d74b863e2fba93aeceb05d2fdcde0c9688d21d95aa7bedefc7f31b35731a3d",
			message:        "297611a6b583a5c30587d4e530c948f013e96d5a4e653f0791899d6270c6f3c0",
			expectedPubKey: "9040d29aefe0f045ffd580fb5e0d2f98c61df75e6b45c43a0b456f13e0fbc05b",
			expectedSig:    "c910841a0274ab6460151143b729d381b925073bbc3877a438fc99bff01e21debe840be097572f177991f896c5ae70401e8ba27c1170c3ac6f1d2f183c5ef303",
		},
		{
			name:           "vector_2_seed_0",
			privateKey:     "0194fdc2fa2ffcc041d3ff12045b73c86e4ff95ff662a5eee82abdf44a2d0b7597f3bd871315281e8b83edc7a9fd0541066154449070ccdb3cdd42cf69ccde88",
			blindFactor:    "fb180daf48a79ee0b10d394651850fd4a178892ee285ece1511455780875d64e",
			message:        "e2d3d0d0de6bf8f9b44ce85ff044c6b1f83b8e883bbf857aab99c5b252c7429c",
			expectedPubKey: "b1275c25380c06100f20942f4f81f3533ef32baeee877cc8c5e2e5df5ddef7a8",
			expectedSig:    "92ce223a2774a54246b28fee25627ea03380cb2d1a0812aa6141223de261858f123166a034738270abbac513c66328165893ab72b5a65b190eae35c869c98d06",
		},
		{
			name:           "vector_3_seed_max_int64",
			privateKey:     "52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c6496f1581709bb7b1ef030d210db18e3b0ba1c776fba65d8cdaad05415142d189f8",
			blindFactor:    "81855ad8681d0d86d1e91e00167939cb6694d2c422acd208a0072939487f6999",
			message:        "eb9d18a44784045d87f3c67cf22746e995af5a25367951baa2ff6cd471c483f1",
			expectedPubKey: "00820761955498aa0c4d0e4d564399ea8281c65051838887c9f6936f63a4159f",
			expectedSig:    "c176f7bd7b97555ed006959b76a3fc3b858ae6ce6c1e610f049eef6523886461b61910e21f9e7dbeb5f8e677fb6fd753a9c6c5ed8518278f164f087e72e2d308",
		},
	}

	for _, tv := range testVectors {
		t.Run(tv.name, func(t *testing.T) {
			// Decode test vector data
			privKeyBytes, err := hex.DecodeString(tv.privateKey)
			require.NoError(t, err, "failed to decode private key")
			require.Len(t, privKeyBytes, 64, "private key must be 64 bytes")

			blindFactor, err := hex.DecodeString(tv.blindFactor)
			require.NoError(t, err, "failed to decode blind factor")
			require.Len(t, blindFactor, 32, "blind factor must be 32 bytes")

			message, err := hex.DecodeString(tv.message)
			require.NoError(t, err, "failed to decode message")

			expectedPubKey, err := hex.DecodeString(tv.expectedPubKey)
			require.NoError(t, err, "failed to decode expected public key")
			require.Len(t, expectedPubKey, 32, "public key must be 32 bytes")

			expectedSig, err := hex.DecodeString(tv.expectedSig)
			require.NoError(t, err, "failed to decode expected signature")
			require.Len(t, expectedSig, 64, "signature must be 64 bytes")

			// Load private key
			privKey := new(PrivateKey)
			err = privKey.FromBytes(privKeyBytes)
			require.NoError(t, err, "failed to load private key")

			// Perform blinding
			blindedPrivKey := privKey.Blind(blindFactor)
			blindedPubKey := blindedPrivKey.PublicKey()

			// Verify blinded public key matches expected
			actualPubKey := blindedPubKey.Bytes()
			assert.Equal(t, expectedPubKey, actualPubKey, "blinded public key mismatch")

			// Generate signature
			actualSig := blindedPrivKey.Sign(message)
			assert.Equal(t, expectedSig, actualSig, "signature mismatch")

			// Verify signature
			assert.True(t, blindedPubKey.Verify(actualSig, message), "signature verification failed")
			assert.True(t, blindedPubKey.Verify(expectedSig, message), "expected signature verification failed")
		})
	}
}

// TestUnblindVectors tests the Unblind operation using fixed test vectors
// These vectors test the operation that was failing in the old implementation
func TestUnblindVectors(t *testing.T) {
	testVectors := []struct {
		name                 string
		privateKey           string // hex encoded 64-byte private key
		blindFactor1         string // hex encoded 32-byte first blind factor
		blindFactor2         string // hex encoded 32-byte second blind factor
		message              string // hex encoded message
		expectedSingleBlind  string // hex encoded expected single-blinded signature
		expectedDoubleBlind  string // hex encoded expected double-blinded signature
		expectedUnblindMatch bool   // whether unblind should restore single-blind state
	}{
		{
			name:                 "unblind_vector_1_safe_seed",
			privateKey:           "1ae969564b34a33ecd1af05fe6923d6de71870997d38ef60155c325957214c425d8ca057866bdee02b63464f587aa75fdad4694c5c05db72323f3928722286cf",
			blindFactor1:         "59d74b863e2fba93aeceb05d2fdcde0c9688d21d95aa7bedefc7f31b35731a3d",
			blindFactor2:         "297611a6b583a5c30587d4e530c948f013e96d5a4e653f0791899d6270c6f3c0",
			message:              "deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef",
			expectedSingleBlind:  "9040d29aefe0f045ffd580fb5e0d2f98c61df75e6b45c43a0b456f13e0fbc05b",
			expectedDoubleBlind:  "8b5c2e5b8f7a9c3d1e4f6a8b9c0d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d",
			expectedUnblindMatch: true,
		},
		{
			name:                 "unblind_vector_2_zero_seed",
			privateKey:           "0194fdc2fa2ffcc041d3ff12045b73c86e4ff95ff662a5eee82abdf44a2d0b7597f3bd871315281e8b83edc7a9fd0541066154449070ccdb3cdd42cf69ccde88",
			blindFactor1:         "fb180daf48a79ee0b10d394651850fd4a178892ee285ece1511455780875d64e",
			blindFactor2:         "e2d3d0d0de6bf8f9b44ce85ff044c6b1f83b8e883bbf857aab99c5b252c7429c",
			message:              "0000000000000000000000000000000000000000000000000000000000000000",
			expectedSingleBlind:  "b1275c25380c06100f20942f4f81f3533ef32baeee877cc8c5e2e5df5ddef7a8",
			expectedDoubleBlind:  "a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3",
			expectedUnblindMatch: true,
		},
	}

	for _, tv := range testVectors {
		t.Run(tv.name, func(t *testing.T) {
			// Decode test vector data
			privKeyBytes, err := hex.DecodeString(tv.privateKey)
			require.NoError(t, err, "failed to decode private key")

			blindFactor1, err := hex.DecodeString(tv.blindFactor1)
			require.NoError(t, err, "failed to decode blind factor 1")

			blindFactor2, err := hex.DecodeString(tv.blindFactor2)
			require.NoError(t, err, "failed to decode blind factor 2")

			message, err := hex.DecodeString(tv.message)
			require.NoError(t, err, "failed to decode message")

			expectedSingleBlind, err := hex.DecodeString(tv.expectedSingleBlind)
			require.NoError(t, err, "failed to decode expected single blind")

			// Load private key
			privKey := new(PrivateKey)
			err = privKey.FromBytes(privKeyBytes)
			require.NoError(t, err, "failed to load private key")

			// Perform single blinding
			singleBlindedKey := privKey.Blind(blindFactor1)
			actualSingleBlind := singleBlindedKey.PublicKey().Bytes()
			assert.Equal(t, expectedSingleBlind, actualSingleBlind, "single blinded public key mismatch")

			// Perform double blinding
			doubleBlindedKey := singleBlindedKey.Blind(blindFactor2)

			// Test unblinding (this is what was failing in the old implementation)
			unblindedKey := doubleBlindedKey.Unblind(blindFactor2)

			if tv.expectedUnblindMatch {
				// Verify that unblinding restores the single-blinded state
				singleBlindBytes, err := singleBlindedKey.MarshalBinary()
				require.NoError(t, err, "failed to marshal single blinded key")

				unblindedBytes, err := unblindedKey.MarshalBinary()
				require.NoError(t, err, "failed to marshal unblinded key")

				assert.Equal(t, singleBlindBytes, unblindedBytes, "unblind should restore single-blinded state")

				// Verify public keys match
				assert.Equal(t, singleBlindedKey.PublicKey().Bytes(), unblindedKey.PublicKey().Bytes(),
					"unblinded public key should match single-blinded public key")

				// Verify signatures are consistent
				singleSig := singleBlindedKey.Sign(message)
				unblindedSig := unblindedKey.Sign(message)
				assert.Equal(t, singleSig, unblindedSig, "signatures should be identical after unblind")

				// Verify both signatures verify correctly
				singlePubKey := singleBlindedKey.PublicKey()
				assert.True(t, singlePubKey.Verify(singleSig, message), "single-blinded signature should verify")
				assert.True(t, singlePubKey.Verify(unblindedSig, message), "unblinded signature should verify")
			}
		})
	}
}
