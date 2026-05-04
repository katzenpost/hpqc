// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package combiner defines a security preserving KEM combiner.
// The [KEM Combiners paper](https://eprint.iacr.org/2018/024.pdf) makes the
// observation that if a KEM combiner is not security preserving then the
// resulting hybrid KEM will not have IND-CCA2 security if one of the
// composing KEMs does not have IND-CCA2 security. Likewise the paper
// points out that when using a security preserving KEM combiner, if only
// one of the composing KEMs has IND-CCA2 security then the resulting
// hybrid KEM will have IND-CCA2 security.
//
// Our KEM combiner uses the split PRF design for an arbitrary number
// of kems, here shown with only three, in pseudo code:
//
// ```
//
//	func SplitPRF(ss1, ss2, ss3, cct1, cct2, cct3 []byte) []byte {
//	    cct := cct1 || cct2 || cct3
//	    return PRF(ss1 || cct) XOR PRF(ss2 || cct) XOR PRF(ss3 || cct)
//	}
//
// ```
package combiner

import (
	"errors"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/util"
	coreUtil "github.com/katzenpost/hpqc/util"
)

var (
	// ErrUninitialized indicates a key wasn't initialized.
	ErrUninitialized = errors.New("public or private key not initialized")

	// ErrNilScheme indicates a nil sub-scheme was supplied to New.
	ErrNilScheme = errors.New("KEM sub-scheme cannot be nil")

	// ErrEmptySchemes indicates no sub-schemes were supplied to New.
	ErrEmptySchemes = errors.New("at least one KEM sub-scheme is required")

	// ErrSeedSize indicates the supplied seed has the wrong length.
	ErrSeedSize = errors.New("wrong seed size")
)

var _ kem.PrivateKey = (*PrivateKey)(nil)
var _ kem.PublicKey = (*PublicKey)(nil)
var _ kem.Scheme = (*Scheme)(nil)

// PublicKey is the public key of a combined KEM.
type PublicKey struct {
	scheme *Scheme
	keys   []kem.PublicKey
}

// PrivateKey is the private key of a combined KEM.
type PrivateKey struct {
	scheme *Scheme
	keys   []kem.PrivateKey
}

// Scheme is a hybrid KEM built by combining sub-schemes via the split PRF.
type Scheme struct {
	name    string
	schemes []kem.Scheme
}

// PrivateKey methods

// Scheme returns the given private key's scheme object.
func (sk *PrivateKey) Scheme() kem.Scheme { return sk.scheme }

// MarshalBinary creates a binary blob of the key.
func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	if sk.keys == nil {
		return nil, ErrUninitialized
	}
	for _, s := range sk.keys {
		if s == nil {
			return nil, ErrUninitialized
		}
	}

	out := make([]byte, 0, sk.scheme.PrivateKeySize())
	for _, k := range sk.keys {
		blob, err := k.MarshalBinary()
		if err != nil {
			return nil, err
		}
		out = append(out, blob...)
	}
	return out, nil
}

// Equal performs a non-constant time key comparison.
func (sk *PrivateKey) Equal(other kem.PrivateKey) bool {
	oth, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	if sk.scheme != oth.scheme {
		return false
	}
	if len(sk.keys) != len(oth.keys) {
		return false
	}
	for i := range sk.keys {
		if sk.keys[i] == nil || oth.keys[i] == nil {
			return false
		}
		if !sk.keys[i].Equal(oth.keys[i]) {
			return false
		}
	}
	return true
}

// Public returns a public key, given a private key.
func (sk *PrivateKey) Public() kem.PublicKey {
	pubkeys := make([]kem.PublicKey, len(sk.keys))
	for i := range sk.keys {
		pubkeys[i] = sk.keys[i].Public()
	}
	return &PublicKey{
		scheme: sk.scheme,
		keys:   pubkeys,
	}
}

// PublicKey methods

// Scheme returns the scheme object for the given public key.
func (pk *PublicKey) Scheme() kem.Scheme { return pk.scheme }

// Equal performs a non-constant time key comparison.
func (pk *PublicKey) Equal(other kem.PublicKey) bool {
	oth, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	if pk.scheme != oth.scheme {
		return false
	}
	if len(pk.keys) != len(oth.keys) {
		return false
	}
	for i := range pk.keys {
		if pk.keys[i] == nil || oth.keys[i] == nil {
			return false
		}
		if !pk.keys[i].Equal(oth.keys[i]) {
			return false
		}
	}
	return true
}

// MarshalBinary returns a binary blob of the key.
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	if pk.keys == nil {
		return nil, ErrUninitialized
	}
	for _, s := range pk.keys {
		if s == nil {
			return nil, ErrUninitialized
		}
	}

	out := make([]byte, 0, pk.scheme.PublicKeySize())
	for _, k := range pk.keys {
		blob, err := k.MarshalBinary()
		if err != nil {
			return nil, err
		}
		out = append(out, blob...)
	}
	return out, nil
}

// Scheme methods

// New creates a new hybrid KEM given the slice of KEM schemes.
// It returns an error if any sub-scheme is nil or the slice is empty.
func New(name string, schemes []kem.Scheme) (*Scheme, error) {
	if len(schemes) == 0 {
		return nil, ErrEmptySchemes
	}
	for _, x := range schemes {
		if x == nil {
			return nil, ErrNilScheme
		}
	}
	return &Scheme{
		name:    name,
		schemes: schemes,
	}, nil
}

// Name returns the name of the KEM.
func (sch *Scheme) Name() string { return sch.name }

// PublicKeySize returns the KEM's public key size in bytes.
func (sch *Scheme) PublicKeySize() int {
	sum := 0
	for _, s := range sch.schemes {
		sum += s.PublicKeySize()
	}
	return sum
}

// PrivateKeySize returns the KEM's private key size in bytes.
func (sch *Scheme) PrivateKeySize() int {
	sum := 0
	for _, s := range sch.schemes {
		sum += s.PrivateKeySize()
	}
	return sum
}

// SeedSize returns the KEM's seed size in bytes.
func (sch *Scheme) SeedSize() int {
	sum := 0
	for _, s := range sch.schemes {
		sum += s.SeedSize()
	}
	return sum
}

// SharedKeySize returns the KEM's shared key size in bytes.
func (sch *Scheme) SharedKeySize() int {
	return blake2b.Size256
}

// CiphertextSize returns the KEM's ciphertext size in bytes.
func (sch *Scheme) CiphertextSize() int {
	sum := 0
	for _, s := range sch.schemes {
		sum += s.CiphertextSize()
	}
	return sum
}

// GenerateKeyPair generates a keypair.
func (sch *Scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	pubKeys := make([]kem.PublicKey, len(sch.schemes))
	privKeys := make([]kem.PrivateKey, len(sch.schemes))

	for i, s := range sch.schemes {
		pk, sk, err := s.GenerateKeyPair()
		if err != nil {
			return nil, nil, err
		}
		pubKeys[i] = pk
		privKeys[i] = sk
	}

	return &PublicKey{
			scheme: sch,
			keys:   pubKeys,
		}, &PrivateKey{
			scheme: sch,
			keys:   privKeys,
		}, nil
}

// DeriveKeyPair uses a seed value to deterministically generate a key pair.
// The seed is read but not modified.
func (sch *Scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != sch.SeedSize() {
		panic(ErrSeedSize)
	}

	pubKeys := make([]kem.PublicKey, len(sch.schemes))
	privKeys := make([]kem.PrivateKey, len(sch.schemes))

	offset := 0
	for i, s := range sch.schemes {
		seedSize := s.SeedSize()
		pubKeys[i], privKeys[i] = s.DeriveKeyPair(seed[offset : offset+seedSize])
		offset += seedSize
	}

	return &PublicKey{
			scheme: sch,
			keys:   pubKeys,
		}, &PrivateKey{
			scheme: sch,
			keys:   privKeys,
		}
}

// Encapsulate creates a shared secret and ciphertext given a public key.
func (sch *Scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	pub, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}
	if pub.scheme != sch {
		return nil, nil, kem.ErrTypeMismatch
	}
	if len(pub.keys) != len(sch.schemes) {
		return nil, nil, ErrUninitialized
	}

	ciphertexts := make([][]byte, len(sch.schemes))
	sharedSecrets := make([][]byte, len(sch.schemes))
	defer func() {
		for _, s := range sharedSecrets {
			coreUtil.ExplicitBzero(s)
		}
	}()
	ciphertextBlob := make([]byte, 0, sch.CiphertextSize())

	for i, s := range sch.schemes {
		cct, secret, encErr := s.Encapsulate(pub.keys[i])
		if encErr != nil {
			return nil, nil, encErr
		}
		ciphertexts[i] = cct
		sharedSecrets[i] = secret
		ciphertextBlob = append(ciphertextBlob, cct...)
	}

	ss, err = util.SplitPRF(sharedSecrets, ciphertexts)
	if err != nil {
		return nil, nil, err
	}
	return ciphertextBlob, ss, nil
}

// Decapsulate decrypts a given KEM ciphertext using the given private key.
func (sch *Scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	if len(ct) != sch.CiphertextSize() {
		return nil, kem.ErrCiphertextSize
	}
	priv, ok := sk.(*PrivateKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}
	if priv.scheme != sch {
		return nil, kem.ErrTypeMismatch
	}
	if len(priv.keys) != len(sch.schemes) {
		return nil, ErrUninitialized
	}

	sharedSecrets := make([][]byte, len(sch.schemes))
	defer func() {
		for _, s := range sharedSecrets {
			coreUtil.ExplicitBzero(s)
		}
	}()
	ciphertexts := make([][]byte, len(sch.schemes))

	offset := 0
	for i, s := range sch.schemes {
		ciphertextSize := s.CiphertextSize()
		ciphertexts[i] = ct[offset : offset+ciphertextSize]
		secret, err := s.Decapsulate(priv.keys[i], ciphertexts[i])
		if err != nil {
			coreUtil.ExplicitBzero(secret)
			return nil, err
		}
		sharedSecrets[i] = secret
		offset += ciphertextSize
	}

	return util.SplitPRF(sharedSecrets, ciphertexts)
}

// UnmarshalBinaryPublicKey unmarshals a binary blob representing a public key.
func (sch *Scheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
	if len(buf) != sch.PublicKeySize() {
		return nil, kem.ErrPubKeySize
	}
	publicKeys := make([]kem.PublicKey, len(sch.schemes))
	offset := 0
	for i, s := range sch.schemes {
		size := s.PublicKeySize()
		pk, err := s.UnmarshalBinaryPublicKey(buf[offset : offset+size])
		if err != nil {
			return nil, err
		}
		publicKeys[i] = pk
		offset += size
	}
	return &PublicKey{
		scheme: sch,
		keys:   publicKeys,
	}, nil
}

// UnmarshalBinaryPrivateKey unmarshals a binary blob representing a private key.
func (sch *Scheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
	if len(buf) != sch.PrivateKeySize() {
		return nil, kem.ErrPrivKeySize
	}
	privateKeys := make([]kem.PrivateKey, len(sch.schemes))
	offset := 0
	for i, s := range sch.schemes {
		size := s.PrivateKeySize()
		sk, err := s.UnmarshalBinaryPrivateKey(buf[offset : offset+size])
		if err != nil {
			return nil, err
		}
		privateKeys[i] = sk
		offset += size
	}
	return &PrivateKey{
		scheme: sch,
		keys:   privateKeys,
	}, nil
}
