// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package sqisign implements the hpqc sign.Scheme interface for SQIsign
// level 1. The actual cryptographic work is performed by the
// github.com/katzenpost/sqisign/bindings/go binding, which links the
// Rust port's sqisign-ffi staticlib through cgo.
//
// SQIsign is a NIST Round 2 candidate; this implementation has not been
// audited. Treat it as experimental. See the upstream repository's
// SECURITY.md before deploying it anywhere that matters.
package sqisign

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/blake2b"

	sqisignbinding "github.com/katzenpost/sqisign/bindings/go/sqisign"

	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/pem"
)

// KeySeedSize is the seed size returned by SeedSize. SQIsign's
// keypair entry point in the C ABI takes a 48-byte entropy block, not
// a seed in the DeriveKey sense; DeriveKey therefore panics, mirroring
// the Falcon wrapper in this tree. The value here is kept at 32 so
// the umbrella hybrid SeedSize values line up with the other PQ
// schemes registered in hpqc.
const KeySeedSize = 32

// Sizes mirror the SQIsign level 1 C ABI constants. The compile-time
// guard at the bottom of this file rejects any silent drift in the
// underlying binding.
const (
	publicKeySize    = sqisignbinding.PublicKeyBytes
	privateKeySize   = sqisignbinding.SecretKeyBytes
	signatureSize    = sqisignbinding.SignatureBytes
	entropySize      = sqisignbinding.EntropyBytes
	schemeName       = "SQIsign-lvl1"
)

type scheme struct{}

var (
	_ sign.Scheme     = (*scheme)(nil)
	_ sign.PublicKey  = (*publicKey)(nil)
	_ sign.PrivateKey = (*privateKey)(nil)
)

var theScheme = &scheme{}

// Scheme returns the SQIsign level 1 sign.Scheme.
func Scheme() sign.Scheme { return theScheme }

func (s *scheme) Name() string { return schemeName }

func (s *scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	entropy := make([]byte, entropySize)
	if _, err := rand.Read(entropy); err != nil {
		return nil, nil, err
	}
	pubBytes, privBytes, err := sqisignbinding.KeyGen(entropy)
	if err != nil {
		return nil, nil, err
	}
	pk := &publicKey{bytes: pubBytes}
	sk := &privateKey{bytes: privBytes, publicKey: pk}
	return pk, sk, nil
}

func (s *scheme) Sign(sk sign.PrivateKey, message []byte, opts *sign.SignatureOpts) []byte {
	if opts != nil && opts.Context != "" {
		panic(sign.ErrContextNotSupported)
	}
	priv := sk.(*privateKey)
	entropy := make([]byte, entropySize)
	if _, err := rand.Read(entropy); err != nil {
		panic(err)
	}
	sig, err := sqisignbinding.Sign(priv.bytes, message, entropy)
	if err != nil {
		panic(err)
	}
	return sig
}

func (s *scheme) Verify(pk sign.PublicKey, message, signature []byte, opts *sign.SignatureOpts) bool {
	if opts != nil && opts.Context != "" {
		panic(sign.ErrContextNotSupported)
	}
	ok, err := sqisignbinding.Verify(signature, pk.(*publicKey).bytes, message)
	if err != nil {
		return false
	}
	return ok
}

func (s *scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	// The SQIsign C ABI consumes a 48-byte CTR-DRBG seed, not a
	// generic 32-byte symmetric seed; we follow the Falcon wrapper's
	// precedent and refuse to invent a KDF here. Callers that need
	// deterministic keygen can drop down to the binding's KeyGen and
	// supply their own 48-byte entropy.
	panic("DeriveKey not implemented for SQIsign")
}

func (s *scheme) UnmarshalBinaryPublicKey(b []byte) (sign.PublicKey, error) {
	if len(b) != publicKeySize {
		return nil, sign.ErrPubKeySize
	}
	pk := &publicKey{bytes: make([]byte, len(b))}
	copy(pk.bytes, b)
	return pk, nil
}

func (s *scheme) UnmarshalBinaryPrivateKey(b []byte) (sign.PrivateKey, error) {
	if len(b) != privateKeySize {
		return nil, sign.ErrPrivKeySize
	}
	sk := &privateKey{bytes: make([]byte, len(b))}
	copy(sk.bytes, b)
	return sk, nil
}

func (s *scheme) PublicKeySize() int    { return publicKeySize }
func (s *scheme) PrivateKeySize() int   { return privateKeySize }
func (s *scheme) SignatureSize() int    { return signatureSize }
func (s *scheme) SeedSize() int         { return KeySeedSize }
func (s *scheme) SupportsContext() bool { return false }

type privateKey struct {
	bytes     []byte
	publicKey *publicKey
}

func (p *privateKey) Scheme() sign.Scheme { return theScheme }

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

func (p *privateKey) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	entropy := make([]byte, entropySize)
	if _, err := rand.Read(entropy); err != nil {
		return nil, err
	}
	return sqisignbinding.Sign(p.bytes, digest, entropy)
}

func (p *privateKey) MarshalBinary() ([]byte, error) {
	out := make([]byte, len(p.bytes))
	copy(out, p.bytes)
	return out, nil
}

func (p *privateKey) UnmarshalBinary(b []byte) error {
	if len(b) != privateKeySize {
		return sign.ErrPrivKeySize
	}
	p.bytes = make([]byte, len(b))
	copy(p.bytes, b)
	p.publicKey = nil
	return nil
}

type publicKey struct {
	bytes []byte
}

func (p *publicKey) Scheme() sign.Scheme { return theScheme }

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
	if len(b) != publicKeySize {
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
// stable short identifier. Matches the helper exposed by the Falcon
// wrapper.
func (p *publicKey) Sum256() [32]byte {
	return blake2b.Sum256(p.bytes)
}

// Compile-time guard so a future change to the binding's wire sizes
// does not silently change the surface we expose.
var _ = func() {
	if publicKeySize != 65 {
		panic("hpqc/sign/sqisign: unexpected SQIsign lvl1 public key size")
	}
	if privateKeySize != 353 {
		panic("hpqc/sign/sqisign: unexpected SQIsign lvl1 private key size")
	}
	if signatureSize != 148 {
		panic("hpqc/sign/sqisign: unexpected SQIsign lvl1 signature size")
	}
	if entropySize != 48 {
		panic("hpqc/sign/sqisign: unexpected SQIsign lvl1 entropy size")
	}
}
