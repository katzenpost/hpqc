// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package hqc provides KEM wrappers around the go-hqc implementation of
// the HQC (Hamming Quasi-Cyclic) code-based post-quantum KEM, exposing
// the three NIST parameter sets through our common kem.Scheme interface.
//
// Note that go-hqc tracks the HQC v5.0.0 reference (NIST round 4) and is
// explicitly pre-FIPS: key and shared-secret sizes are liable to change
// once FIPS 207 is published. Callers should treat these schemes as
// experimental until that time.
package hqc

import (
	"crypto/hmac"

	gohqc "github.com/shurlinet/go-hqc"

	"github.com/katzenpost/hpqc/kem"
)

var (
	_ kem.Scheme     = (*scheme)(nil)
	_ kem.PublicKey  = (*PublicKey)(nil)
	_ kem.PrivateKey = (*PrivateKey)(nil)
)

// clone returns a fresh copy of b so that callers retain the bytes after
// the originating go-hqc key has been Destroyed.
func clone(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

type PublicKey struct {
	scheme *scheme
	bytes  []byte
}

func (p *PublicKey) Scheme() kem.Scheme { return p.scheme }

func (p *PublicKey) MarshalBinary() ([]byte, error) {
	return clone(p.bytes), nil
}

func (p *PublicKey) Equal(other kem.PublicKey) bool {
	o, ok := other.(*PublicKey)
	if !ok || o.scheme != p.scheme {
		return false
	}
	return hmac.Equal(o.bytes, p.bytes)
}

type PrivateKey struct {
	scheme *scheme
	bytes  []byte
	pub    []byte
}

func (p *PrivateKey) Scheme() kem.Scheme { return p.scheme }

func (p *PrivateKey) MarshalBinary() ([]byte, error) {
	return clone(p.bytes), nil
}

func (p *PrivateKey) Equal(other kem.PrivateKey) bool {
	o, ok := other.(*PrivateKey)
	if !ok || o.scheme != p.scheme {
		return false
	}
	return hmac.Equal(o.bytes, p.bytes)
}

func (p *PrivateKey) Public() kem.PublicKey {
	return &PublicKey{scheme: p.scheme, bytes: clone(p.pub)}
}

// scheme adapts a single go-hqc parameter set to kem.Scheme by way of
// closures. go-hqc exposes distinct concrete key types per parameter
// set rather than a shared interface, so the closures absorb that
// per-parameter-set variation and the rest of the wrapper stays generic.
type scheme struct {
	name           string
	seedSize       int
	publicKeySize  int
	privateKeySize int
	ciphertextSize int
	sharedKeySize  int

	generate    func() (sk, pk []byte, err error)
	derive      func(seed []byte) (sk, pk []byte, err error)
	extractPub  func(sk []byte) (pk []byte, err error)
	encapsulate func(pk []byte) (ct, ss []byte, err error)
	decapsulate func(sk, ct []byte) (ss []byte, err error)
}

func (s *scheme) Name() string { return s.name }

func (s *scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	sk, pk, err := s.generate()
	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{scheme: s, bytes: pk},
		&PrivateKey{scheme: s, bytes: sk, pub: pk}, nil
}

func (s *scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	pub, ok := pk.(*PublicKey)
	if !ok || pub.scheme != s {
		return nil, nil, kem.ErrTypeMismatch
	}
	return s.encapsulate(pub.bytes)
}

func (s *scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	priv, ok := sk.(*PrivateKey)
	if !ok || priv.scheme != s {
		return nil, kem.ErrTypeMismatch
	}
	if len(ct) != s.ciphertextSize {
		return nil, kem.ErrCiphertextSize
	}
	return s.decapsulate(priv.bytes, ct)
}

func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (kem.PublicKey, error) {
	if len(b) != s.publicKeySize {
		return nil, kem.ErrPubKeySize
	}
	return &PublicKey{scheme: s, bytes: clone(b)}, nil
}

func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (kem.PrivateKey, error) {
	if len(b) != s.privateKeySize {
		return nil, kem.ErrPrivKeySize
	}
	pub, err := s.extractPub(b)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{scheme: s, bytes: clone(b), pub: pub}, nil
}

func (s *scheme) CiphertextSize() int { return s.ciphertextSize }
func (s *scheme) SharedKeySize() int  { return s.sharedKeySize }
func (s *scheme) PrivateKeySize() int { return s.privateKeySize }
func (s *scheme) PublicKeySize() int  { return s.publicKeySize }
func (s *scheme) SeedSize() int       { return s.seedSize }

func (s *scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	if len(seed) != s.seedSize {
		panic(kem.ErrSeedSize)
	}
	sk, pk, err := s.derive(seed)
	if err != nil {
		panic(err)
	}
	return &PublicKey{scheme: s, bytes: pk},
		&PrivateKey{scheme: s, bytes: sk, pub: pk}
}

var (
	hqc128 = &scheme{
		name:           "HQC-128",
		seedSize:       gohqc.SeedSize128,
		publicKeySize:  gohqc.PublicKeySize128,
		privateKeySize: gohqc.SecretKeySize128,
		ciphertextSize: gohqc.CiphertextSize128,
		sharedKeySize:  gohqc.SharedSecretSize128,
		generate: func() (sk, pk []byte, err error) {
			dk, err := gohqc.GenerateKey128()
			if err != nil {
				return nil, nil, err
			}
			defer dk.Destroy()
			return clone(dk.Bytes()), clone(dk.EncapsulationKey().Bytes()), nil
		},
		derive: func(seed []byte) (sk, pk []byte, err error) {
			dk, err := gohqc.NewDecapsulationKey128(seed)
			if err != nil {
				return nil, nil, err
			}
			defer dk.Destroy()
			return clone(dk.Bytes()), clone(dk.EncapsulationKey().Bytes()), nil
		},
		extractPub: func(sk []byte) ([]byte, error) {
			dk, err := gohqc.ParseDecapsulationKey128(sk)
			if err != nil {
				return nil, err
			}
			defer dk.Destroy()
			return clone(dk.EncapsulationKey().Bytes()), nil
		},
		encapsulate: func(pk []byte) (ct, ss []byte, err error) {
			ek, err := gohqc.ParseEncapsulationKey128(pk)
			if err != nil {
				return nil, nil, err
			}
			ss, ct = ek.Encapsulate()
			return ct, ss, nil
		},
		decapsulate: func(sk, ct []byte) ([]byte, error) {
			dk, err := gohqc.ParseDecapsulationKey128(sk)
			if err != nil {
				return nil, err
			}
			defer dk.Destroy()
			return dk.Decapsulate(ct)
		},
	}

	hqc192 = &scheme{
		name:           "HQC-192",
		seedSize:       gohqc.SeedSize192,
		publicKeySize:  gohqc.PublicKeySize192,
		privateKeySize: gohqc.SecretKeySize192,
		ciphertextSize: gohqc.CiphertextSize192,
		sharedKeySize:  gohqc.SharedSecretSize192,
		generate: func() (sk, pk []byte, err error) {
			dk, err := gohqc.GenerateKey192()
			if err != nil {
				return nil, nil, err
			}
			defer dk.Destroy()
			return clone(dk.Bytes()), clone(dk.EncapsulationKey().Bytes()), nil
		},
		derive: func(seed []byte) (sk, pk []byte, err error) {
			dk, err := gohqc.NewDecapsulationKey192(seed)
			if err != nil {
				return nil, nil, err
			}
			defer dk.Destroy()
			return clone(dk.Bytes()), clone(dk.EncapsulationKey().Bytes()), nil
		},
		extractPub: func(sk []byte) ([]byte, error) {
			dk, err := gohqc.ParseDecapsulationKey192(sk)
			if err != nil {
				return nil, err
			}
			defer dk.Destroy()
			return clone(dk.EncapsulationKey().Bytes()), nil
		},
		encapsulate: func(pk []byte) (ct, ss []byte, err error) {
			ek, err := gohqc.ParseEncapsulationKey192(pk)
			if err != nil {
				return nil, nil, err
			}
			ss, ct = ek.Encapsulate()
			return ct, ss, nil
		},
		decapsulate: func(sk, ct []byte) ([]byte, error) {
			dk, err := gohqc.ParseDecapsulationKey192(sk)
			if err != nil {
				return nil, err
			}
			defer dk.Destroy()
			return dk.Decapsulate(ct)
		},
	}

	hqc256 = &scheme{
		name:           "HQC-256",
		seedSize:       gohqc.SeedSize256,
		publicKeySize:  gohqc.PublicKeySize256,
		privateKeySize: gohqc.SecretKeySize256,
		ciphertextSize: gohqc.CiphertextSize256,
		sharedKeySize:  gohqc.SharedSecretSize256,
		generate: func() (sk, pk []byte, err error) {
			dk, err := gohqc.GenerateKey256()
			if err != nil {
				return nil, nil, err
			}
			defer dk.Destroy()
			return clone(dk.Bytes()), clone(dk.EncapsulationKey().Bytes()), nil
		},
		derive: func(seed []byte) (sk, pk []byte, err error) {
			dk, err := gohqc.NewDecapsulationKey256(seed)
			if err != nil {
				return nil, nil, err
			}
			defer dk.Destroy()
			return clone(dk.Bytes()), clone(dk.EncapsulationKey().Bytes()), nil
		},
		extractPub: func(sk []byte) ([]byte, error) {
			dk, err := gohqc.ParseDecapsulationKey256(sk)
			if err != nil {
				return nil, err
			}
			defer dk.Destroy()
			return clone(dk.EncapsulationKey().Bytes()), nil
		},
		encapsulate: func(pk []byte) (ct, ss []byte, err error) {
			ek, err := gohqc.ParseEncapsulationKey256(pk)
			if err != nil {
				return nil, nil, err
			}
			ss, ct = ek.Encapsulate()
			return ct, ss, nil
		},
		decapsulate: func(sk, ct []byte) ([]byte, error) {
			dk, err := gohqc.ParseDecapsulationKey256(sk)
			if err != nil {
				return nil, err
			}
			defer dk.Destroy()
			return dk.Decapsulate(ct)
		},
	}
)

// Scheme128 returns the HQC-128 (NIST level 1) KEM scheme.
func Scheme128() kem.Scheme { return hqc128 }

// Scheme192 returns the HQC-192 (NIST level 3) KEM scheme.
func Scheme192() kem.Scheme { return hqc192 }

// Scheme256 returns the HQC-256 (NIST level 5) KEM scheme.
func Scheme256() kem.Scheme { return hqc256 }
