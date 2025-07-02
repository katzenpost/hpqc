// SPDX-FileCopyrightText: (c) 2023 David Stainton and Yawning Angel
// SPDX-License-Identifier: AGPL-3.0-only

// Package is our ed25519 wrapper type which also conforms to our generic interfaces for signature schemes.
package ed25519

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/pem"
	"github.com/katzenpost/hpqc/util"
)

const (
	// PublicKeySize is the size of a serialized PublicKey in bytes (32 bytes).
	PublicKeySize = 32

	// PrivateKeySize is the size of a serialized PrivateKey in bytes (32 bytes).
	// This is the canonical scalar encoding, not the 64-byte seed+pubkey format.
	PrivateKeySize = 32

	// SignatureSize is the size of a serialized Signature in bytes (64 bytes).
	SignatureSize = ed25519.SignatureSize

	// KeySeedSize is the seed size used by NewKeyFromSeed to generate
	// a new key deterministically.
	KeySeedSize = 32

	keyType = "ed25519"
)

var errInvalidKey = errors.New("eddsa: invalid key")

// Scheme implements our sign.Scheme interface using the ed25519 wrapper.
type scheme struct{}

var sch *scheme = &scheme{}

// Scheme returns a sign Scheme interface.
func Scheme() *scheme { return sch }

func (s *scheme) Name() string {
	return "Ed25519"
}

func (s *scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	privKey, _, err := NewKeypair(rand.Reader)
	if err != nil {
		panic(err)
	}

	return privKey.PublicKey(), privKey, nil
}

func (s *scheme) Sign(sk sign.PrivateKey, message []byte, opts *sign.SignatureOpts) []byte {
	sig, err := sk.Sign(nil, message, nil)
	if err != nil {
		panic(err)
	}
	return sig
}

func (s *scheme) Verify(pk sign.PublicKey, message []byte, signature []byte, opts *sign.SignatureOpts) bool {
	return ed25519.Verify(pk.(*PublicKey).pubKey, message, signature)
}

func (s *scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	return NewKeyFromSeed(seed)
}

func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	pubKey := new(PublicKey)
	err := pubKey.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	privKey := new(PrivateKey)
	err := privKey.FromBytes(b)
	if err != nil {
		return nil, err
	}
	return privKey, nil
}

func (s *scheme) PublicKeySize() int {
	return PublicKeySize
}

func (s *scheme) PrivateKeySize() int {
	return PrivateKeySize
}

func (s *scheme) SignatureSize() int {
	return SignatureSize
}

func (s *scheme) SeedSize() int {
	return KeySeedSize
}

func (s *scheme) SupportsContext() bool {
	return false
}

type PrivateKey struct {
	// scalar is the 32-byte canonical scalar (this is what gets serialized)
	scalar [32]byte
	// originalSeed stores the original seed for KAT compatibility (not serialized)
	originalSeed *[32]byte
}

func NewEmptyPrivateKey() *PrivateKey {
	return &PrivateKey{}
}

func (p *PrivateKey) Scheme() sign.Scheme {
	return Scheme()
}

func (p *PrivateKey) Equal(key crypto.PrivateKey) bool {
	return hmac.Equal(p.Bytes(), key.(*PrivateKey).Bytes())
}

func (p *PrivateKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *PrivateKey) UnmarshalBinary(b []byte) error {
	return p.FromBytes(b)
}

// signer interface methods

func (p *PrivateKey) Public() crypto.PublicKey {
	return p.PublicKey()
}

func (p *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	sig := p.SignMessage(digest)
	return sig, nil
}

// InternalPtr returns a pointer to the internal (`golang.org/x/crypto/ed25519`)
// data structure.  Most people should not use this.
func (p *PrivateKey) InternalPtr() *ed25519.PrivateKey {
	// Use the canonical scalar as a pseudo-seed to create a compatible Ed25519 key
	privKey := ed25519.NewKeyFromSeed(p.scalar[:])
	return &privKey
}

func (p *PrivateKey) KeyType() string {
	return "ED25519 PRIVATE KEY"
}

func (p *PrivateKey) SignMessage(message []byte) (signature []byte) {
	// Use KAT-compatible signing if we have the original seed
	if p.originalSeed != nil {
		privKey := ed25519.NewKeyFromSeed(p.originalSeed[:])
		return ed25519.Sign(privKey, message)
	}

	// Otherwise use canonical scalar signing
	return p.signWithCanonicalScalar(message)
}

func (p *PrivateKey) Reset() {
	util.ExplicitBzero(p.scalar[:])
	if p.originalSeed != nil {
		util.ExplicitBzero(p.originalSeed[:])
		p.originalSeed = nil
	}
}

func (p *PrivateKey) Bytes() []byte {
	// Return the canonical scalar
	return p.scalar[:]
}

// FromBytes deserializes the byte slice b into the PrivateKey.
// The input should be a 32-byte canonical scalar.
func (p *PrivateKey) FromBytes(b []byte) error {
	if len(b) != PrivateKeySize {
		return errInvalidKey
	}

	// Validate that it's a canonical scalar
	scalar := new(edwards25519.Scalar)
	if _, err := scalar.SetCanonicalBytes(b); err != nil {
		return errInvalidKey
	}

	// Store the canonical scalar
	copy(p.scalar[:], b)
	return nil
}

// FromSeed creates a PrivateKey from a 32-byte seed (for KAT compatibility).
func (p *PrivateKey) FromSeed(seed []byte) error {
	if len(seed) != PrivateKeySize {
		return errInvalidKey
	}

	// Store the original seed for KAT-compatible signing
	p.originalSeed = new([32]byte)
	copy(p.originalSeed[:], seed)

	// Derive canonical scalar from seed using Ed25519 method
	h := sha512.Sum512(seed)

	// Clamp the first 32 bytes as per Ed25519 spec
	h[0] &= 248
	h[31] &= 127
	h[31] |= 64

	// Convert to canonical scalar representation
	scalar := new(edwards25519.Scalar)
	scalar.SetBytesWithClamping(h[:32])

	// Store the canonical scalar
	copy(p.scalar[:], scalar.Bytes())
	return nil
}

// Identity returns the key's identity, in this case it's our
// public key in bytes.
func (p *PrivateKey) Identity() []byte {
	return p.PublicKey().Bytes()
}

// PublicKey returns the PublicKey corresponding to the PrivateKey.
func (p *PrivateKey) PublicKey() *PublicKey {
	var pubKeyBytes []byte

	// Use KAT-compatible derivation if we have the original seed
	if p.originalSeed != nil {
		privKey := ed25519.NewKeyFromSeed(p.originalSeed[:])
		stdPubKey := privKey.Public().(ed25519.PublicKey)
		pubKeyBytes = stdPubKey
	} else {
		// Use the canonical scalar directly for public key computation
		scalar := new(edwards25519.Scalar)
		if _, err := scalar.SetCanonicalBytes(p.scalar[:]); err != nil {
			panic("invalid private key scalar: " + err.Error())
		}

		point := new(edwards25519.Point).ScalarBaseMult(scalar)
		pubKeyBytes = point.Bytes()
	}

	pubKey := new(PublicKey)
	if err := pubKey.FromBytes(pubKeyBytes); err != nil {
		panic("failed to create public key: " + err.Error())
	}

	return pubKey
}

// signWithCanonicalScalar implements Ed25519 signing using the canonical scalar
func (p *PrivateKey) signWithCanonicalScalar(message []byte) []byte {
	// Load the canonical scalar
	privateScalar := new(edwards25519.Scalar)
	if _, err := privateScalar.SetCanonicalBytes(p.scalar[:]); err != nil {
		panic("invalid private key scalar: " + err.Error())
	}

	// Use the canonical scalar as a pseudo-seed for nonce generation
	// This creates a deterministic but different nonce than standard Ed25519
	h := sha512.Sum512(p.scalar[:])
	noncePrefix := h[32:]

	// Create the nonce: SHA512(nonce_prefix || message)
	hasher := sha512.New()
	hasher.Write(noncePrefix)
	hasher.Write(message)
	nonceHash := hasher.Sum(nil)

	// Convert nonce hash to scalar
	nonceScalar := new(edwards25519.Scalar)
	nonceScalar.SetUniformBytes(nonceHash)

	// Compute R = nonce * G
	R := new(edwards25519.Point).ScalarBaseMult(nonceScalar)

	// Compute challenge: SHA512(R || A || message) where A is our public key
	A := p.PublicKey().Bytes()
	hasher.Reset()
	hasher.Write(R.Bytes())
	hasher.Write(A)
	hasher.Write(message)
	challengeHash := hasher.Sum(nil)

	// Convert challenge to scalar
	challengeScalar := new(edwards25519.Scalar)
	challengeScalar.SetUniformBytes(challengeHash)

	// Compute s = nonce + challenge * private_scalar
	s := new(edwards25519.Scalar)
	s.MultiplyAdd(challengeScalar, privateScalar, nonceScalar)

	// Return signature: R || s
	signature := make([]byte, 64)
	copy(signature[:32], R.Bytes())
	copy(signature[32:], s.Bytes())

	return signature
}

// PublicKey is the EdDSA public key using ed25519.
type PublicKey struct {
	pubKey    ed25519.PublicKey
	b64String string
}

func (p *PublicKey) Scheme() sign.Scheme {
	return Scheme()
}

func (p *PublicKey) Equal(pubKey crypto.PublicKey) bool {
	return hmac.Equal(p.pubKey[:], pubKey.(*PublicKey).pubKey[:])
}

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

// ToECDH converts the PublicKey to the corresponding ecdh.PublicKey.
func (p *PublicKey) ToECDH() *x25519.PublicKey {
	ed_pub, _ := new(edwards25519.Point).SetBytes(p.Bytes())
	r := new(x25519.PublicKey)
	if r.FromBytes(ed_pub.BytesMontgomery()) != nil {
		panic("edwards.Point from pub.BytesMontgomery failed, impossible. ")
	}
	return r
}

// InternalPtr returns a pointer to the internal (`golang.org/x/crypto/ed25519`)
// data structure.  Most people should not use this.
func (k *PublicKey) InternalPtr() *ed25519.PublicKey {
	return &k.pubKey
}

func (p *PublicKey) KeyType() string {
	return "ED25519 PUBLIC KEY"
}

func (p *PublicKey) Sum256() [32]byte {
	return blake2b.Sum256(p.Bytes())
}

func (p *PublicKey) Verify(signature, message []byte) bool {
	return ed25519.Verify(p.pubKey, message, signature)
}

func (p *PublicKey) Reset() {
	util.ExplicitBzero(p.pubKey)
	p.b64String = "[scrubbed]"
}

func (p *PublicKey) Bytes() []byte {
	return p.pubKey
}

// ByteArray returns the raw public key as an array suitable for use as a map
// key.
func (p *PublicKey) ByteArray() [PublicKeySize]byte {
	var pk [PublicKeySize]byte
	copy(pk[:], p.pubKey[:])
	return pk
}

func (p *PublicKey) rebuildB64String() {
	p.b64String = base64.StdEncoding.EncodeToString(p.Bytes())
}

func (p *PublicKey) FromBytes(data []byte) error {
	if len(data) != PublicKeySize {
		return errInvalidKey
	}

	p.pubKey = make([]byte, PublicKeySize)
	copy(p.pubKey, data)
	p.rebuildB64String()
	return nil
}

func (p *PublicKey) UnmarshalBinary(data []byte) error {
	return p.FromBytes(data)
}

func (p *PublicKey) MarshalText() (text []byte, err error) {
	return pem.ToPublicPEMBytes(p), nil
}

func (p *PublicKey) UnmarshalText(text []byte) error {
	pubkey, err := pem.FromPublicPEMString(string(text), p.Scheme())
	if err != nil {
		return err
	}
	p = pubkey.(*PublicKey)
	return nil
}

// NewKeypair generates a new PrivateKey sampled from the provided entropy
// source.
func NewKeypair(r io.Reader) (*PrivateKey, *PublicKey, error) {
	// Generate a standard Ed25519 keypair first
	_, privKey, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, nil, err
	}

	// Convert the 64-byte Ed25519 private key to our 32-byte canonical format
	k := new(PrivateKey)
	if err := k.fromEd25519PrivateKey(privKey); err != nil {
		return nil, nil, err
	}

	return k, k.PublicKey(), nil
}

// fromEd25519PrivateKey converts a 64-byte ed25519.PrivateKey to our canonical format
func (p *PrivateKey) fromEd25519PrivateKey(privKey ed25519.PrivateKey) error {
	if len(privKey) != 64 {
		return errors.New("invalid ed25519 private key length")
	}

	// Extract the seed (first 32 bytes) and derive canonical scalar
	seed := privKey[:32]
	return p.FromSeed(seed)
}

func NewKeyFromSeed(seed []byte) (*PublicKey, *PrivateKey) {
	if len(seed) != KeySeedSize {
		panic("seed must be of length KeySeedSize")
	}
	xof, err := blake2b.NewXOF(blake2b.OutputLengthUnknown, seed)
	if err != nil {
		panic(err)
	}
	privkey, pubkey, err := NewKeypair(xof)
	if err != nil {
		panic(err)
	}
	return pubkey, privkey
}
