//go:build !windows
// +build !windows

// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package falcon implements the hpqc sign.Scheme interface for the
// padded Falcon parameter sets exposed by github.com/katzenpost/falcon
// (Falcon-padded-512 and Falcon-padded-1024). Signatures and keys are
// fixed-length, suitable for protocols where variable-length
// signatures would complicate framing.
//
// The underlying C is PQClean's reference implementation. As is the
// case for sphincsplus, the cgo dependency is gated out of Windows
// builds via a stub.
package falcon

import (
	"crypto"
	"crypto/hmac"
	"errors"
	"io"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/falcon/padded1024"
	"github.com/katzenpost/falcon/padded512"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/pem"
)

// KeySeedSize is the seed size returned by SeedSize. Falcon's PQClean
// surface does not expose seeded key generation, so DeriveKey panics;
// the value here matches the convention used by our other PQ schemes.
const KeySeedSize = 32

type scheme struct {
	name          string
	pubKeySize    int
	privKeySize   int
	signatureSize int

	generate func() (pub, priv []byte, err error)
	sign     func(priv, msg []byte) ([]byte, error)
	verify   func(pub, msg, sig []byte) bool
}

var _ sign.Scheme = (*scheme)(nil)
var _ sign.PublicKey = (*publicKey)(nil)
var _ sign.PrivateKey = (*privateKey)(nil)

var (
	schPadded512 = &scheme{
		name:          "Falcon-padded-512",
		pubKeySize:    padded512.PublicKeySize,
		privKeySize:   padded512.PrivateKeySize,
		signatureSize: padded512.SignatureSize,
		generate: func() ([]byte, []byte, error) {
			pk, sk, err := padded512.GenerateKey()
			if err != nil {
				return nil, nil, err
			}
			pubBuf := make([]byte, padded512.PublicKeySize)
			privBuf := make([]byte, padded512.PrivateKeySize)
			copy(pubBuf, pk[:])
			copy(privBuf, sk[:])
			return pubBuf, privBuf, nil
		},
		sign: func(priv, msg []byte) ([]byte, error) {
			if len(priv) != padded512.PrivateKeySize {
				return nil, sign.ErrPrivKeySize
			}
			var sk padded512.PrivateKey
			copy(sk[:], priv)
			return padded512.Sign(&sk, msg)
		},
		verify: func(pub, msg, sig []byte) bool {
			if len(pub) != padded512.PublicKeySize {
				return false
			}
			var pk padded512.PublicKey
			copy(pk[:], pub)
			return padded512.Verify(&pk, msg, sig)
		},
	}

	schPadded1024 = &scheme{
		name:          "Falcon-padded-1024",
		pubKeySize:    padded1024.PublicKeySize,
		privKeySize:   padded1024.PrivateKeySize,
		signatureSize: padded1024.SignatureSize,
		generate: func() ([]byte, []byte, error) {
			pk, sk, err := padded1024.GenerateKey()
			if err != nil {
				return nil, nil, err
			}
			pubBuf := make([]byte, padded1024.PublicKeySize)
			privBuf := make([]byte, padded1024.PrivateKeySize)
			copy(pubBuf, pk[:])
			copy(privBuf, sk[:])
			return pubBuf, privBuf, nil
		},
		sign: func(priv, msg []byte) ([]byte, error) {
			if len(priv) != padded1024.PrivateKeySize {
				return nil, sign.ErrPrivKeySize
			}
			var sk padded1024.PrivateKey
			copy(sk[:], priv)
			return padded1024.Sign(&sk, msg)
		},
		verify: func(pub, msg, sig []byte) bool {
			if len(pub) != padded1024.PublicKeySize {
				return false
			}
			var pk padded1024.PublicKey
			copy(pk[:], pub)
			return padded1024.Verify(&pk, msg, sig)
		},
	}
)

// SchemePadded512 returns the Falcon-padded-512 sign.Scheme.
func SchemePadded512() sign.Scheme { return schPadded512 }

// SchemePadded1024 returns the Falcon-padded-1024 sign.Scheme.
func SchemePadded1024() sign.Scheme { return schPadded1024 }

func (s *scheme) Name() string { return s.name }

func (s *scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	pubBytes, privBytes, err := s.generate()
	if err != nil {
		return nil, nil, err
	}
	pk := &publicKey{scheme: s, bytes: pubBytes}
	sk := &privateKey{scheme: s, bytes: privBytes, publicKey: pk}
	return pk, sk, nil
}

func (s *scheme) Sign(sk sign.PrivateKey, message []byte, opts *sign.SignatureOpts) []byte {
	priv := sk.(*privateKey)
	sig, err := s.sign(priv.bytes, message)
	if err != nil {
		panic(err)
	}
	return sig
}

func (s *scheme) Verify(pk sign.PublicKey, message, signature []byte, opts *sign.SignatureOpts) bool {
	return s.verify(pk.(*publicKey).bytes, message, signature)
}

func (s *scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	// PQClean's Falcon API does not expose a seeded keygen entry
	// point. Sphincs+ presents the same limitation in this tree.
	panic("DeriveKey not implemented for Falcon")
}

func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	if len(b) != s.pubKeySize {
		return nil, sign.ErrPubKeySize
	}
	pk := &publicKey{scheme: s, bytes: make([]byte, len(b))}
	copy(pk.bytes, b)
	return pk, nil
}

func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	if len(b) != s.privKeySize {
		return nil, sign.ErrPrivKeySize
	}
	sk := &privateKey{scheme: s, bytes: make([]byte, len(b))}
	copy(sk.bytes, b)
	return sk, nil
}

func (s *scheme) PublicKeySize() int    { return s.pubKeySize }
func (s *scheme) PrivateKeySize() int   { return s.privKeySize }
func (s *scheme) SignatureSize() int    { return s.signatureSize }
func (s *scheme) SeedSize() int         { return KeySeedSize }
func (s *scheme) SupportsContext() bool { return false }

type privateKey struct {
	scheme    *scheme
	bytes     []byte
	publicKey *publicKey
}

func (p *privateKey) Scheme() sign.Scheme { return p.scheme }

func (p *privateKey) Equal(key crypto.PrivateKey) bool {
	other, ok := key.(*privateKey)
	if !ok {
		return false
	}
	return hmac.Equal(p.bytes, other.bytes)
}

func (p *privateKey) Public() crypto.PublicKey {
	if p.publicKey == nil {
		return nil
	}
	return p.publicKey
}

func (p *privateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) (signature []byte, err error) {
	return p.scheme.sign(p.bytes, digest)
}

func (p *privateKey) MarshalBinary() ([]byte, error) {
	out := make([]byte, len(p.bytes))
	copy(out, p.bytes)
	return out, nil
}

func (p *privateKey) UnmarshalBinary(b []byte) error {
	if len(b) != p.scheme.privKeySize {
		return sign.ErrPrivKeySize
	}
	p.bytes = make([]byte, len(b))
	copy(p.bytes, b)
	p.publicKey = nil
	return nil
}

type publicKey struct {
	scheme *scheme
	bytes  []byte
}

func (p *publicKey) Scheme() sign.Scheme { return p.scheme }

func (p *publicKey) Equal(key crypto.PublicKey) bool {
	other, ok := key.(*publicKey)
	if !ok {
		return false
	}
	return hmac.Equal(p.bytes, other.bytes)
}

func (p *publicKey) MarshalBinary() ([]byte, error) {
	out := make([]byte, len(p.bytes))
	copy(out, p.bytes)
	return out, nil
}

func (p *publicKey) UnmarshalBinary(b []byte) error {
	if len(b) != p.scheme.pubKeySize {
		return sign.ErrPubKeySize
	}
	p.bytes = make([]byte, len(b))
	copy(p.bytes, b)
	return nil
}

func (p *publicKey) MarshalText() (text []byte, err error) {
	return pem.ToPublicPEMBytes(p), nil
}

// Sum256 returns a BLAKE2b-256 digest of the public key, useful as a
// stable short identifier.
func (p *publicKey) Sum256() [32]byte {
	return blake2b.Sum256(p.bytes)
}

// Compile-time guards that the upstream Falcon parameter sizes do not
// silently change underneath us.
var _ = func() error {
	if padded512.SignatureSize != 666 {
		return errors.New("hpqc/sign/falcon: unexpected padded512.SignatureSize")
	}
	if padded1024.SignatureSize != 1280 {
		return errors.New("hpqc/sign/falcon: unexpected padded1024.SignatureSize")
	}
	return nil
}
