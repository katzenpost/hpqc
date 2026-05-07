// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package mldsa implements the hpqc sign.Scheme interface for the FIPS 204
// ML-DSA signature scheme, in its three standard parameterisations
// (ML-DSA-44, ML-DSA-65, ML-DSA-87). The underlying implementation is
// provided by filippo.io/mldsa.
package mldsa

import (
	"crypto"
	"crypto/hmac"
	"errors"
	"io"

	"filippo.io/mldsa"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/pem"
)

// KeySeedSize is the seed size required by NewPrivateKey/DeriveKey, in bytes.
// It matches mldsa.PrivateKeySize since the on-disk private key is the seed.
const KeySeedSize = mldsa.PrivateKeySize

type scheme struct {
	name        string
	params      *mldsa.Parameters
	pubKeySize  int
	signSize    int
}

var _ sign.Scheme = (*scheme)(nil)
var _ sign.PublicKey = (*publicKey)(nil)
var _ sign.PrivateKey = (*privateKey)(nil)

var (
	sch44 = &scheme{
		name:       "ML-DSA-44",
		params:     mldsa.MLDSA44(),
		pubKeySize: mldsa.MLDSA44PublicKeySize,
		signSize:   mldsa.MLDSA44SignatureSize,
	}
	sch65 = &scheme{
		name:       "ML-DSA-65",
		params:     mldsa.MLDSA65(),
		pubKeySize: mldsa.MLDSA65PublicKeySize,
		signSize:   mldsa.MLDSA65SignatureSize,
	}
	sch87 = &scheme{
		name:       "ML-DSA-87",
		params:     mldsa.MLDSA87(),
		pubKeySize: mldsa.MLDSA87PublicKeySize,
		signSize:   mldsa.MLDSA87SignatureSize,
	}
)

// Scheme44 returns the ML-DSA-44 sign.Scheme.
func Scheme44() sign.Scheme { return sch44 }

// Scheme65 returns the ML-DSA-65 sign.Scheme.
func Scheme65() sign.Scheme { return sch65 }

// Scheme87 returns the ML-DSA-87 sign.Scheme.
func Scheme87() sign.Scheme { return sch87 }

func (s *scheme) Name() string { return s.name }

func (s *scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	sk, err := mldsa.GenerateKey(s.params)
	if err != nil {
		return nil, nil, err
	}
	return s.wrap(sk)
}

func (s *scheme) wrap(sk *mldsa.PrivateKey) (sign.PublicKey, sign.PrivateKey, error) {
	pubkey := &publicKey{
		scheme:    s,
		publicKey: sk.PublicKey(),
	}
	privkey := &privateKey{
		scheme:     s,
		publicKey:  pubkey,
		privateKey: sk,
	}
	return pubkey, privkey, nil
}

func (s *scheme) Sign(sk sign.PrivateKey, message []byte, opts *sign.SignatureOpts) []byte {
	sig, err := sk.Sign(nil, message, nil)
	if err != nil {
		panic(err)
	}
	return sig
}

func (s *scheme) Verify(pk sign.PublicKey, message []byte, signature []byte, opts *sign.SignatureOpts) bool {
	return pk.(*publicKey).Verify(signature, message)
}

func (s *scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	if len(seed) != KeySeedSize {
		panic(sign.ErrSeedSize)
	}
	sk, err := mldsa.NewPrivateKey(s.params, seed)
	if err != nil {
		panic(err)
	}
	pub, priv, err := s.wrap(sk)
	if err != nil {
		panic(err)
	}
	return pub, priv
}

func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	if len(b) != s.pubKeySize {
		return nil, sign.ErrPubKeySize
	}
	pk, err := mldsa.NewPublicKey(s.params, b)
	if err != nil {
		return nil, err
	}
	return &publicKey{
		scheme:    s,
		publicKey: pk,
	}, nil
}

func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	if len(b) != KeySeedSize {
		return nil, sign.ErrPrivKeySize
	}
	sk, err := mldsa.NewPrivateKey(s.params, b)
	if err != nil {
		return nil, err
	}
	return &privateKey{
		scheme:     s,
		publicKey:  &publicKey{scheme: s, publicKey: sk.PublicKey()},
		privateKey: sk,
	}, nil
}

func (s *scheme) PublicKeySize() int  { return s.pubKeySize }
func (s *scheme) PrivateKeySize() int { return KeySeedSize }
func (s *scheme) SignatureSize() int  { return s.signSize }
func (s *scheme) SeedSize() int       { return KeySeedSize }
func (s *scheme) SupportsContext() bool {
	// ML-DSA itself supports an arbitrary 0..255 byte context string, but to
	// keep the hpqc Scheme surface uniform with our other schemes (Ed25519,
	// Sphincs+) we do not plumb it through. Hybrid pairings rely on the
	// minimum of the two halves' SupportsContext, so this also keeps the
	// Ed25519+ML-DSA hybrids well-defined.
	return false
}

type privateKey struct {
	scheme     *scheme
	privateKey *mldsa.PrivateKey
	publicKey  *publicKey
}

func (p *privateKey) Scheme() sign.Scheme { return p.scheme }

func (p *privateKey) Equal(key crypto.PrivateKey) bool {
	other, ok := key.(*privateKey)
	if !ok {
		return false
	}
	return hmac.Equal(p.Bytes(), other.Bytes())
}

func (p *privateKey) Public() crypto.PublicKey {
	return p.publicKey
}

func (p *privateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return p.privateKey.Sign(rand, digest, nil)
}

func (p *privateKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *privateKey) UnmarshalBinary(b []byte) error {
	if len(b) != KeySeedSize {
		return sign.ErrPrivKeySize
	}
	sk, err := mldsa.NewPrivateKey(p.scheme.params, b)
	if err != nil {
		return err
	}
	p.privateKey = sk
	p.publicKey = &publicKey{scheme: p.scheme, publicKey: sk.PublicKey()}
	return nil
}

// Bytes returns the 32-byte seed for the private key.
func (p *privateKey) Bytes() []byte {
	return p.privateKey.Bytes()
}

type publicKey struct {
	scheme    *scheme
	publicKey *mldsa.PublicKey
}

func (p *publicKey) Scheme() sign.Scheme { return p.scheme }

func (p *publicKey) Equal(key crypto.PublicKey) bool {
	other, ok := key.(*publicKey)
	if !ok {
		return false
	}
	return hmac.Equal(p.Bytes(), other.Bytes())
}

func (p *publicKey) MarshalBinary() ([]byte, error) {
	return p.Bytes(), nil
}

func (p *publicKey) UnmarshalBinary(b []byte) error {
	if len(b) != p.scheme.pubKeySize {
		return sign.ErrPubKeySize
	}
	pk, err := mldsa.NewPublicKey(p.scheme.params, b)
	if err != nil {
		return err
	}
	p.publicKey = pk
	return nil
}

func (p *publicKey) MarshalText() (text []byte, err error) {
	return pem.ToPublicPEMBytes(p), nil
}

// Bytes returns the public key encoding.
func (p *publicKey) Bytes() []byte {
	return p.publicKey.Bytes()
}

// Verify returns true if signature is a valid ML-DSA signature of message.
func (p *publicKey) Verify(sig, message []byte) bool {
	return mldsa.Verify(p.publicKey, message, sig, nil) == nil
}

// Sum256 returns a BLAKE2b-256 digest of the public key, useful as a stable
// short identifier.
func (p *publicKey) Sum256() [32]byte {
	return blake2b.Sum256(p.Bytes())
}

// Compile-time guard that mldsa never silently changes its seed size.
var _ = func() error {
	if mldsa.PrivateKeySize != 32 {
		return errors.New("hpqc/sign/mldsa: unexpected mldsa.PrivateKeySize")
	}
	return nil
}
