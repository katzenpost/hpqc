// SPDX-FileCopyrightText: Copyright (C) 2022-2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package adapter provides an adhoc hashed ElGamal construction
// that essentially acts like an adapter, adapting a NIKE to KEM.
package adapter

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/nike"
	coreUtil "github.com/katzenpost/hpqc/util"
)

const (
	// SeedSize is the number of bytes needed to seed deterministic methods below.
	SeedSize = 32
)

var _ kem.PrivateKey = (*PrivateKey)(nil)
var _ kem.PublicKey = (*PublicKey)(nil)
var _ kem.Scheme = (*Scheme)(nil)

// PublicKey is an adapter for nike.PublicKey to kem.PublicKey.
type PublicKey struct {
	publicKey nike.PublicKey
	scheme    *Scheme
}

func (p *PublicKey) Scheme() kem.Scheme {
	return p.scheme
}

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	return p.publicKey.MarshalBinary()
}

func (p *PublicKey) Equal(pubkey kem.PublicKey) bool {
	if pubkey.(*PublicKey).scheme != p.scheme {
		return false
	}
	return hmac.Equal(pubkey.(*PublicKey).publicKey.Bytes(), p.publicKey.Bytes())
}

// PrivateKey is an adapter for nike.PrivateKey to kem.PrivateKey.
type PrivateKey struct {
	privateKey nike.PrivateKey
	scheme     *Scheme
}

func (p *PrivateKey) Scheme() kem.Scheme {
	return p.scheme
}

func (p *PrivateKey) MarshalBinary() ([]byte, error) {
	return p.privateKey.MarshalBinary()
}

func (p *PrivateKey) Equal(privkey kem.PrivateKey) bool {
	if privkey.(*PrivateKey).scheme != p.scheme {
		return false
	}
	return hmac.Equal(privkey.(*PrivateKey).privateKey.Bytes(), p.privateKey.Bytes())
}

func (p *PrivateKey) Public() kem.PublicKey {
	return &PublicKey{
		publicKey: p.privateKey.Public(),
		scheme:    p.scheme,
	}
}

// Scheme is an adapter for nike.Scheme to kem.Scheme.
// See docs/specs/kemsphinx.rst for some design notes
// on this NIKE to KEM adapter.
type Scheme struct {
	nike nike.Scheme
	prf  PRF
}

var _ kem.Scheme = (*Scheme)(nil)
var _ kem.PublicKey = (*PublicKey)(nil)
var _ kem.PrivateKey = (*PrivateKey)(nil)

// FromNIKE creates a new KEM adapter Scheme
// using the given NIKE Scheme.
func FromNIKE(nike nike.Scheme) kem.Scheme {
	if nike == nil {
		return nil
	}
	return &Scheme{
		nike: nike,
		prf:  BLAKE2bXOF,
	}
}

// FromNIKEWithPRF creates a KEM adapter Scheme over the given NIKE using an
// explicitly chosen PRF. FromNIKE is the deployed configuration; this exists so
// the construction can be exercised under a PRF that other implementations can
// also compute. Changing the PRF changes the shared key, so a scheme built here
// is wire-incompatible with one built by FromNIKE.
func FromNIKEWithPRF(n nike.Scheme, prf PRF) kem.Scheme {
	if n == nil || prf == nil {
		return nil
	}
	return &Scheme{
		nike: n,
		prf:  prf,
	}
}

// Name of the scheme
func (a *Scheme) Name() string {
	return a.nike.Name()
}

// GenerateKeyPair creates a new key pair.
func (a *Scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	pubkey, privkey, err := a.nike.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{
			publicKey: pubkey,
			scheme:    a,
		}, &PrivateKey{
			privateKey: privkey,
			scheme:     a,
		}, nil
}

// Encapsulate generates a shared key ss for the public key and
// encapsulates it into a ciphertext ct.
func (a *Scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	theirPubkey, ok := pk.(*PublicKey)
	if !ok || theirPubkey.scheme != a {
		return nil, nil, kem.ErrTypeMismatch
	}
	myPubkey, sk2, err := a.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	// ss = DH(my_privkey, their_pubkey)
	ss = a.nike.DeriveSecret(sk2.(*PrivateKey).privateKey, theirPubkey.publicKey)
	defer coreUtil.ExplicitBzero(ss)
	// shared_key = PRF(ss, static recipient key, ephemeral key)
	ss2, err := a.prf.Derive(ss, theirPubkey.publicKey.Bytes(),
		myPubkey.(*PublicKey).publicKey.Bytes(), a.SharedKeySize())
	if err != nil {
		return nil, nil, err
	}
	ct, _ = myPubkey.MarshalBinary()
	return ct, ss2, nil
}

// PRF derives the adapter's shared key from the raw NIKE shared secret and the
// two public keys that define the exchange. Both Encapsulate and Decapsulate
// pass the static recipient key first and the ephemeral key second.
type PRF interface {
	// Name identifies the PRF, and is what a shared test vector records so
	// consumers do not have to assume which one produced it.
	Name() string

	// Derive returns the shared key. ss is the raw NIKE shared secret,
	// pkStatic the recipient's long-term public key, pkEph the ephemeral
	// public key carried in the ciphertext, and sharedKeySize the scheme's
	// advertised shared key size.
	Derive(ss, pkStatic, pkEph []byte, sharedKeySize int) ([]byte, error)
}

// BLAKE2bXOF is the deployed PRF: a BLAKE2b XOF keyed by the shared secret,
// over the two public keys as message.
var BLAKE2bXOF PRF = blake2bXOF{}

// SHA256v1 is a fixed-width SHA-256 PRF used for cross-implementation test
// vectors. It is NOT the deployed construction; it exists because it can be
// computed by implementations that have SHA-256 but no BLAKE2b. Because its
// output is exactly one SHA-256 digest it only supports a 32-byte shared key,
// which covers X25519 but not the wider-key NIKEs.
var SHA256v1 PRF = sha256v1{}

// PRFByName resolves the name a test vector records.
func PRFByName(name string) (PRF, error) {
	switch name {
	case BLAKE2bXOF.Name():
		return BLAKE2bXOF, nil
	case SHA256v1.Name():
		return SHA256v1, nil
	default:
		return nil, fmt.Errorf("adapter: unknown PRF %q", name)
	}
}

type blake2bXOF struct{}

func (blake2bXOF) Name() string { return "blake2b-xof" }

func (blake2bXOF) Derive(ss, pkStatic, pkEph []byte, sharedKeySize int) ([]byte, error) {
	var h blake2b.XOF
	var err error
	// A 32-byte secret keys the XOF directly; anything else is pre-hashed.
	// The two paths share no domain separation, which is a wart worth fixing
	// (the KEM combiner in this repo always hashes), but changing it now would
	// change every deployed shared key.
	if len(ss) != 32 {
		sum := blake2b.Sum256(ss)
		h, err = blake2b.NewXOF(uint32(sharedKeySize), sum[:])
	} else {
		h, err = blake2b.NewXOF(uint32(sharedKeySize), ss)
	}
	if err != nil {
		return nil, err
	}
	if _, err = h.Write(pkStatic); err != nil {
		return nil, err
	}
	if _, err = h.Write(pkEph); err != nil {
		return nil, err
	}
	// NOTE: the XOF is sized at sharedKeySize but len(ss) bytes are read.
	// These are independent quantities; they coincide for every NIKE shipped
	// here. Preserved as-is to keep deployed outputs unchanged.
	out := make([]byte, len(ss))
	if _, err = h.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

// sha256v1Label domain-separates this PRF from any other use of SHA-256.
const sha256v1Label = "kemadapter-sha256-v1"

type sha256v1 struct{}

func (sha256v1) Name() string { return "sha256-v1" }

// Derive computes
//
//	SHA256(label || u32be(len(ss)) || ss
//	             || u32be(len(pkStatic)) || pkStatic
//	             || u32be(len(pkEph))    || pkEph)
//
// Every variable-length field is length-prefixed, so the encoding is
// unambiguous regardless of the underlying NIKE's key sizes.
func (sha256v1) Derive(ss, pkStatic, pkEph []byte, sharedKeySize int) ([]byte, error) {
	if sharedKeySize != sha256.Size {
		return nil, fmt.Errorf(
			"adapter: sha256-v1 PRF supports a %d-byte shared key, not %d",
			sha256.Size, sharedKeySize)
	}
	h := sha256.New()
	h.Write([]byte(sha256v1Label))
	for _, part := range [][]byte{ss, pkStatic, pkEph} {
		if err := writeLenPrefixed(h, part); err != nil {
			return nil, err
		}
	}
	return h.Sum(nil), nil
}

func writeLenPrefixed(h hash.Hash, b []byte) error {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, err := h.Write(n[:]); err != nil {
		return err
	}
	_, err := h.Write(b)
	return err
}

// Returns the shared key encapsulated in ciphertext ct for the
// private key sk.
// Implements DECAPSULATE as described in NIKE to KEM adapter,
// see docs/specs/kemsphinx.rst
func (a *Scheme) Decapsulate(myPrivkey kem.PrivateKey, ct []byte) ([]byte, error) {
	if len(ct) != a.CiphertextSize() {
		return nil, kem.ErrCiphertextSize
	}
	theirPubkey, err := a.UnmarshalBinaryPublicKey(ct)
	if err != nil {
		return nil, err
	}
	// s = DH(my_privkey, their_pubkey)
	ss := a.nike.DeriveSecret(myPrivkey.(*PrivateKey).privateKey, theirPubkey.(*PublicKey).publicKey)
	defer coreUtil.ExplicitBzero(ss)
	// shared_key = PRF(ss, static recipient key, ephemeral key)
	ss2, err := a.prf.Derive(ss, myPrivkey.Public().(*PublicKey).publicKey.Bytes(),
		theirPubkey.(*PublicKey).publicKey.Bytes(), a.SharedKeySize())
	if err != nil {
		return nil, err
	}
	return ss2, nil
}

// Unmarshals a PublicKey from the provided buffer.
func (a *Scheme) UnmarshalBinaryPublicKey(b []byte) (kem.PublicKey, error) {
	if len(b) != a.PublicKeySize() {
		return nil, fmt.Errorf("UnmarshalBinaryPublicKey: wrong key size %d != %d", len(b), a.PublicKeySize())
	}
	pubkey, err := a.nike.UnmarshalBinaryPublicKey(b)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		publicKey: pubkey,
		scheme:    a,
	}, nil
}

// Unmarshals a PrivateKey from the provided buffer.
func (a *Scheme) UnmarshalBinaryPrivateKey(b []byte) (kem.PrivateKey, error) {
	if len(b) != a.PrivateKeySize() {
		return nil, fmt.Errorf("UnmarshalBinaryPrivateKey: wrong key size %d != %d", len(b), a.PrivateKeySize())
	}
	privkey, err := a.nike.UnmarshalBinaryPrivateKey(b)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		privateKey: privkey,
		scheme:     a,
	}, nil
}

// Size of encapsulated keys.
func (a *Scheme) CiphertextSize() int {
	return a.nike.PublicKeySize()
}

// Size of established shared keys.
func (a *Scheme) SharedKeySize() int {
	return a.nike.PublicKeySize()
}

// Size of packed private keys.
func (a *Scheme) PrivateKeySize() int {
	return a.nike.PrivateKeySize()
}

// Size of packed public keys.
func (a *Scheme) PublicKeySize() int {
	return a.nike.PublicKeySize()
}

// DeriveKeyPair deterministically derives a pair of keys from a seed.
// Panics if the length of seed is not equal to the value returned by
// SeedSize.
func (a *Scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != a.SeedSize() {
		panic(fmt.Errorf("%s: provided len(seed) %d != a.SeedSize() %d", kem.ErrSeedSize, len(seed), a.SeedSize()))
	}
	h, err := blake2b.NewXOF(0, nil)
	if err != nil {
		panic(err)
	}

	seedHash := blake2b.Sum256(seed)
	defer coreUtil.ExplicitBzero(seedHash[:])
	count, err := h.Write(seedHash[:])
	if err != nil {
		panic(err)
	}
	if count != len(seedHash) {
		panic("blake2b.XOR failed")
	}
	pk, sk, err := a.nike.GenerateKeyPairFromEntropy(h)
	if err != nil {
		panic(err)
	}
	return &PublicKey{
			publicKey: pk,
			scheme:    a,
		}, &PrivateKey{
			privateKey: sk,
			scheme:     a,
		}
}

// Size of seed used in DeriveKey
func (a *Scheme) SeedSize() int {
	return SeedSize
}

// EncapsulateDeterministically generates a shared key ss for the public
// key deterministically from the given seed and encapsulates it into
// a ciphertext ct. If unsure, you're better off using Encapsulate().
// Implements ENCAPSULATE as described in NIKE to KEM adapter,
// see docs/specs/kemsphinx.rst
func (a *Scheme) EncapsulateDeterministically(pk kem.PublicKey, seed []byte) (
	ct, ss []byte, err error) {
	panic("not implemented")
}
