// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package sealedbox provides anonymous public-key encryption to a single
// recipient over any NIKE: a sealed box in the sense of libsodium's
// crypto_box_seal, generalised from X25519 to nike.Scheme so that a
// post-quantum hybrid NIKE such as X25519-CTIDH1024 can be used in its
// place. The sender is not authenticated: the recipient learns nothing
// about who sealed a box. The key derivation differs from libsodium's,
// so even over X25519 the two are not interoperable.
//
// A sealed box is ephPub || secretbox(plaintext). A fresh ephemeral
// keypair is generated for every box, so the XSalsa20-Poly1305 key and
// nonce, both derived from the shared secret, are each used exactly
// once and the nonce is never transmitted. The derivation binds the scheme name and
// both public keys, with the name length as a big-endian uint16:
//
//	okm   = HKDF-BLAKE2b-256(ss, salt = nil,
//	                         info = "hpqc-nike-sealedbox-v1" || len(name) || name || ephPub || recipientPub)
//	key   = okm[0:32]
//	nonce = okm[32:56]
package sealedbox

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	gohash "hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/util"
)

const (
	keySize   = 32
	nonceSize = 24
)

var kdfLabel = []byte("hpqc-nike-sealedbox-v1")

var (
	// ErrOpen reports any failure to open a box. Opening never says
	// which check failed.
	ErrOpen = errors.New("sealedbox: open failed")

	// ErrDegenerateSharedSecret reports an all-zero shared secret.
	ErrDegenerateSharedSecret = errors.New("sealedbox: degenerate all-zero shared secret")

	// ErrKeyScheme reports a nil key or one that does not belong to the
	// scheme's NIKE.
	ErrKeyScheme = errors.New("sealedbox: key is not of this NIKE scheme")
)

// Scheme is a sealed box scheme over one NIKE.
type Scheme struct {
	nike nike.Scheme
}

// NewScheme returns the sealed box scheme over the given NIKE.
func NewScheme(scheme nike.Scheme) *Scheme {
	return &Scheme{
		nike: scheme,
	}
}

// Name returns "sealedbox-" followed by the NIKE name.
func (s *Scheme) Name() string {
	return "sealedbox-" + s.nike.Name()
}

// Overhead returns the number of bytes a box adds to its plaintext.
func (s *Scheme) Overhead() int {
	return s.nike.PublicKeySize() + secretbox.Overhead
}

// Seal encrypts plaintext to recipient under a fresh ephemeral key.
func (s *Scheme) Seal(recipient nike.PublicKey, plaintext []byte) ([]byte, error) {
	return s.SealWithEntropy(recipient, plaintext, rand.Reader)
}

// SealWithEntropy is Seal with the ephemeral keypair drawn from rng.
// It exists to build reproducible test vectors. The key and nonce are
// derived from the ephemeral key, so an rng that repeats its output
// repeats them too, and two boxes to one recipient under the same key
// and nonce reveal the XOR of their plaintexts. Use Seal otherwise.
func (s *Scheme) SealWithEntropy(recipient nike.PublicKey, plaintext []byte, rng io.Reader) ([]byte, error) {
	if recipient == nil {
		return nil, ErrKeyScheme
	}
	ephPub, ephPriv, err := s.nike.GenerateKeyPairFromEntropy(rng)
	if err != nil {
		return nil, err
	}
	defer ephPriv.Reset()
	ephPubBytes := ephPub.Bytes()

	key, nonce, err := s.deriveKeys(ephPriv, recipient, ephPubBytes, recipient.Bytes())
	if err != nil {
		return nil, err
	}
	defer util.ExplicitBzero(key[:])

	out := make([]byte, len(ephPubBytes), len(ephPubBytes)+len(plaintext)+secretbox.Overhead)
	copy(out, ephPubBytes)
	return secretbox.Seal(out, plaintext, nonce, key), nil
}

// Open decrypts a box sealed to pub, the public key of priv. pub is
// passed in rather than derived because deriving it costs as much as
// the key agreement for CSIDH-based NIKEs. A pub that does not match
// priv makes every box fail to open.
func (s *Scheme) Open(priv nike.PrivateKey, pub nike.PublicKey, ciphertext []byte) ([]byte, error) {
	if priv == nil || pub == nil {
		return nil, ErrOpen
	}
	pkSize := s.nike.PublicKeySize()
	if len(ciphertext) < pkSize+secretbox.Overhead {
		return nil, ErrOpen
	}
	ephPubBytes := ciphertext[:pkSize]
	ephPub, err := s.nike.UnmarshalBinaryPublicKey(ephPubBytes)
	if err != nil {
		return nil, ErrOpen
	}

	key, nonce, err := s.deriveKeys(priv, ephPub, ephPubBytes, pub.Bytes())
	if err != nil {
		return nil, ErrOpen
	}
	defer util.ExplicitBzero(key[:])

	sealed := ciphertext[pkSize:]
	plaintext, ok := secretbox.Open(make([]byte, 0, len(sealed)-secretbox.Overhead), sealed, nonce, key)
	if !ok {
		return nil, ErrOpen
	}
	return plaintext, nil
}

func (s *Scheme) deriveKeys(priv nike.PrivateKey, pub nike.PublicKey, ephPub, recipientPub []byte) (*[keySize]byte, *[nonceSize]byte, error) {
	ss := s.nike.DeriveSecret(priv, pub)
	if ss == nil {
		return nil, nil, ErrKeyScheme
	}
	defer util.ExplicitBzero(ss)
	if util.CtIsZero(ss) {
		return nil, nil, ErrDegenerateSharedSecret
	}

	name := []byte(s.nike.Name())
	info := make([]byte, 0, len(kdfLabel)+2+len(name)+len(ephPub)+len(recipientPub))
	info = append(info, kdfLabel...)
	info = binary.BigEndian.AppendUint16(info, uint16(len(name)))
	info = append(info, name...)
	info = append(info, ephPub...)
	info = append(info, recipientPub...)

	okm := make([]byte, keySize+nonceSize)
	defer util.ExplicitBzero(okm)
	if _, err := io.ReadFull(hkdf.New(newBlake2b256, ss, nil, info), okm); err != nil {
		return nil, nil, err
	}

	key := new([keySize]byte)
	nonce := new([nonceSize]byte)
	copy(key[:], okm[:keySize])
	copy(nonce[:], okm[keySize:])
	return key, nonce, nil
}

func newBlake2b256() gohash.Hash {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}
