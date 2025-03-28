// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// standalone NIKE + symmetric cipher example
package main

import (
	"bytes"
	"fmt"

	"github.com/agl/gcmsiv"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
)

func main() {
	// pick a NIKE scheme
	scheme := schemes.ByName("x25519")

	// Alice and Bob generate key pairs
	// and exchange their public keys
	alicePub, alicePriv, err := scheme.GenerateKeyPairFromEntropy(rand.Reader)
	if err != nil {
		panic(err)
	}

	bobPub, bobPriv, err := scheme.GenerateKeyPairFromEntropy(rand.Reader)
	if err != nil {
		panic(err)
	}

	// Alice sends a message to Bob
	aliceSharedSecret := scheme.DeriveSecret(alicePriv, bobPub)
	aliceSecretHash := blake2b.Sum256(aliceSharedSecret)
	aliceCipher, err := gcmsiv.NewGCMSIV(aliceSecretHash[:])
	if err != nil {
		panic(err)
	}
	// encrypt with AES-GCM-SIV:
	alicePlaintext := []byte("yo, what's up?")
	nonce := make([]byte, aliceCipher.NonceSize())
	_, err = rand.Reader.Read(nonce)
	if err != nil {
		panic(err)
	}

	aliceCiphertext := aliceCipher.Seal([]byte{}, nonce, alicePlaintext, []byte{})

	fmt.Printf("Alice's message: %s\nEncrypted as: %x\n", alicePlaintext, aliceCiphertext)

	// we pretend Alice sends Bob the nonce and ciphertext
	// Bob decrypts ciphertext from Alice

	bobSharedSecret := scheme.DeriveSecret(bobPriv, alicePub)

	// sanity check
	if !bytes.Equal(aliceSharedSecret, bobSharedSecret) {
		panic("shared secrets must be equal")
	}

	bobSecretHash := blake2b.Sum256(aliceSharedSecret)
	bobCipher, err := gcmsiv.NewGCMSIV(bobSecretHash[:])
	if err != nil {
		panic(err)
	}

	bobPlaintext, err := bobCipher.Open([]byte{}, nonce, aliceCiphertext, []byte{})

	// sanity check
	if !bytes.Equal(alicePlaintext, bobPlaintext) {
		panic("plaintexts must be equal")
	}

	fmt.Printf("Bob decrypts ciphertext into plaintext: %s\n", bobPlaintext)
}
