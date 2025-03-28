// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// standalone KEM + symmetric cipher example
package main

import (
	"bytes"
	"fmt"

	"github.com/agl/gcmsiv"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
)

func main() {
	// pick a KEM scheme
	scheme := schemes.ByName("Xwing")

	// Bob generate key pairs
	// and we pretend he sends his public key to Alice.
	// Alice doesn't need a keypair because this is
	// an example using a KEM and not a NIKE.
	bobPub, bobPriv, err := scheme.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	// Alice would like to send Bob an encrypted message
	aliceKEMCiphertext, aliceSharedSecret, err := scheme.Encapsulate(bobPub)
	if err != nil {
		panic(err)
	}
	aliceSecretHash := blake2b.Sum256(aliceSharedSecret)
	aliceCipher, err := gcmsiv.NewGCMSIV(aliceSecretHash[:])
	if err != nil {
		panic(err)
	}
	alicePlaintext := []byte("yo, what's up?")
	nonce := make([]byte, aliceCipher.NonceSize())
	_, err = rand.Reader.Read(nonce)
	if err != nil {
		panic(err)
	}

	aliceCiphertext := aliceCipher.Seal([]byte{}, nonce, alicePlaintext, []byte{})

	fmt.Printf("Alice's message: %s\nEncrypted as: %x\n", alicePlaintext, aliceCiphertext)

	// we pretend Alice sends Bob the following:
	// aliceKEMCiphertext, aliceCiphertext, nonce

	bobSharedSecret, err := scheme.Decapsulate(bobPriv, aliceKEMCiphertext)
	if err != nil {
		panic(err)
	}
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
