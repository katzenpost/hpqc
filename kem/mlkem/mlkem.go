// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package mlkem provides ML-KEM-512 and ML-KEM-1024 (FIPS 203) through our
// KEM interfaces, and their hedged variants. ML-KEM-768 is in kem/mlkem768.
//
// A private key encodes as the encapsulation key followed by the 64-byte
// seed d || z, as in kem/mlkem768. The hedged schemes differ only in
// encapsulation and share every wire format with the standard ones; they
// are not FIPS 203.
package mlkem

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"

	"github.com/katzenpost/hpqc/kem"
)

const (
	SeedSize      = 64
	SharedKeySize = 32
)

var (
	_ kem.Scheme     = (*scheme)(nil)
	_ kem.PublicKey  = (*PublicKey)(nil)
	_ kem.PrivateKey = (*PrivateKey)(nil)
)

var errKeyMismatch = errors.New("mlkem: encapsulation key does not match seed")

// params is one FIPS 203 parameter set.
type params struct {
	name, hedgedName              string
	publicKeySize, ciphertextSize int

	// keyGen is ML-KEM.KeyGen_internal on the seed d || z, returning the
	// encapsulation key and Decaps_internal with the decapsulation key.
	keyGen func(seed []byte) (ek []byte, decaps func(ct []byte) []byte)

	// encaps is ML-KEM.Encaps_internal(ek, m), failing if ek does not pass
	// the FIPS 203 modulus check.
	encaps func(ek, m []byte) (ct, ss []byte, err error)
}

var (
	sch512        = &scheme{params: params512}
	sch512Hedged  = &scheme{params: params512, hedged: true}
	sch1024       = &scheme{params: params1024}
	sch1024Hedged = &scheme{params: params1024, hedged: true}
)

// Scheme512 returns the ML-KEM-512 KEM interface.
func Scheme512() kem.Scheme { return sch512 }

// SchemeHedged512 returns the hedged ML-KEM-512 KEM interface.
func SchemeHedged512() kem.Scheme { return sch512Hedged }

// Scheme1024 returns the ML-KEM-1024 KEM interface.
func Scheme1024() kem.Scheme { return sch1024 }

// SchemeHedged1024 returns the hedged ML-KEM-1024 KEM interface.
func SchemeHedged1024() kem.Scheme { return sch1024Hedged }

type PublicKey struct {
	scheme   *scheme
	encapKey []byte
}

func (p *PublicKey) Scheme() kem.Scheme { return p.scheme }

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	return append([]byte(nil), p.encapKey...), nil
}

func (p *PublicKey) Equal(other kem.PublicKey) bool {
	o, ok := other.(*PublicKey)
	if !ok || o.scheme != p.scheme {
		return false
	}
	return hmac.Equal(o.encapKey, p.encapKey)
}

type PrivateKey struct {
	scheme   *scheme
	encapKey []byte
	seed     []byte
	decaps   func(ct []byte) []byte
}

func (p *PrivateKey) Scheme() kem.Scheme { return p.scheme }

func (p *PrivateKey) MarshalBinary() ([]byte, error) {
	return append(append([]byte(nil), p.encapKey...), p.seed...), nil
}

func (p *PrivateKey) Equal(other kem.PrivateKey) bool {
	o, ok := other.(*PrivateKey)
	if !ok || o.scheme != p.scheme {
		return false
	}
	return hmac.Equal(o.seed, p.seed)
}

func (p *PrivateKey) Public() kem.PublicKey {
	return &PublicKey{scheme: p.scheme, encapKey: p.encapKey}
}

type scheme struct {
	*params
	hedged bool
}

func (s *scheme) Name() string {
	if s.hedged {
		return s.hedgedName
	}
	return s.name
}

func (s *scheme) newPrivateKey(seed []byte) *PrivateKey {
	seed = append([]byte(nil), seed...)
	ek, decaps := s.keyGen(seed)
	return &PrivateKey{scheme: s, encapKey: ek, seed: seed, decaps: decaps}
}

func (s *scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	var seed [SeedSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, nil, err
	}
	sk := s.newPrivateKey(seed[:])
	return sk.Public(), sk, nil
}

func (s *scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != SeedSize {
		panic(kem.ErrSeedSize)
	}
	sk := s.newPrivateKey(seed)
	return sk.Public(), sk
}

func (s *scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	pub, ok := pk.(*PublicKey)
	if !ok || pub.scheme.params != s.params {
		return nil, nil, kem.ErrTypeMismatch
	}
	return s.encapsulate(pub.encapKey)
}

func (s *scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	priv, ok := sk.(*PrivateKey)
	if !ok || priv.scheme.params != s.params {
		return nil, kem.ErrTypeMismatch
	}
	if len(ct) != s.ciphertextSize {
		return nil, kem.ErrCiphertextSize
	}
	return priv.decaps(ct), nil
}

// UnmarshalBinaryPublicKey rejects keys that fail the FIPS 203 modulus check.
func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (kem.PublicKey, error) {
	if len(b) != s.publicKeySize {
		return nil, kem.ErrPubKeySize
	}
	if _, _, err := s.encaps(b, make([]byte, 32)); err != nil {
		return nil, kem.ErrPubKey
	}
	return &PublicKey{scheme: s, encapKey: append([]byte(nil), b...)}, nil
}

// UnmarshalBinaryPrivateKey rebuilds the key from its seed and rejects it if
// the encoded encapsulation key does not match.
func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (kem.PrivateKey, error) {
	if len(b) != s.PrivateKeySize() {
		return nil, kem.ErrPrivKeySize
	}
	sk := s.newPrivateKey(b[s.publicKeySize:])
	if !hmac.Equal(sk.encapKey, b[:s.publicKeySize]) {
		return nil, errKeyMismatch
	}
	return sk, nil
}

func (s *scheme) CiphertextSize() int { return s.ciphertextSize }
func (s *scheme) SharedKeySize() int  { return SharedKeySize }
func (s *scheme) PrivateKeySize() int { return s.publicKeySize + SeedSize }
func (s *scheme) PublicKeySize() int  { return s.publicKeySize }
func (s *scheme) SeedSize() int       { return SeedSize }
