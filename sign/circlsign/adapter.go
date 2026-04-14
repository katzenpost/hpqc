// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package circlsign adapts circl sign types to hpqc sign interfaces.
package circlsign

import (
	"crypto"
	"io"

	circlSign "github.com/katzenpost/circl/sign"

	"github.com/katzenpost/hpqc/sign"
)

var _ sign.Scheme = (*Scheme)(nil)
var _ sign.PublicKey = (*PublicKey)(nil)
var _ sign.PrivateKey = (*PrivateKey)(nil)

// PublicKey wraps a circl sign public key.
type PublicKey struct {
	key    circlSign.PublicKey
	scheme *Scheme
}

func (pk *PublicKey) Scheme() sign.Scheme {
	return pk.scheme
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	return pk.key.MarshalBinary()
}

func (pk *PublicKey) Equal(other crypto.PublicKey) bool {
	otherPk, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return pk.key.Equal(otherPk.key)
}

// PrivateKey wraps a circl sign private key.
type PrivateKey struct {
	key    circlSign.PrivateKey
	scheme *Scheme
}

func (sk *PrivateKey) Scheme() sign.Scheme {
	return sk.scheme
}

func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	return sk.key.MarshalBinary()
}

func (sk *PrivateKey) Equal(other crypto.PrivateKey) bool {
	otherSk, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return sk.key.Equal(otherSk.key)
}

func (sk *PrivateKey) Public() crypto.PublicKey {
	return &PublicKey{
		key:    sk.key.Public().(circlSign.PublicKey),
		scheme: sk.scheme,
	}
}

func (sk *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return sk.key.Sign(rand, digest, opts)
}

// Scheme wraps a circl sign scheme.
type Scheme struct {
	inner circlSign.Scheme
}

// FromCircl wraps a circl sign scheme as an hpqc sign scheme.
func FromCircl(s circlSign.Scheme) sign.Scheme {
	return &Scheme{inner: s}
}

func (s *Scheme) Name() string { return s.inner.Name() }

func (s *Scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	pk, sk, err := s.inner.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{key: pk, scheme: s}, &PrivateKey{key: sk, scheme: s}, nil
}

func (s *Scheme) Sign(sk sign.PrivateKey, message []byte, opts *sign.SignatureOpts) []byte {
	wrapper := sk.(*PrivateKey)
	var circlOpts *circlSign.SignatureOpts
	if opts != nil {
		circlOpts = &circlSign.SignatureOpts{Context: opts.Context}
	}
	return s.inner.Sign(wrapper.key, message, circlOpts)
}

func (s *Scheme) Verify(pk sign.PublicKey, message []byte, signature []byte, opts *sign.SignatureOpts) bool {
	wrapper := pk.(*PublicKey)
	var circlOpts *circlSign.SignatureOpts
	if opts != nil {
		circlOpts = &circlSign.SignatureOpts{Context: opts.Context}
	}
	return s.inner.Verify(wrapper.key, message, signature, circlOpts)
}

func (s *Scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	pk, sk := s.inner.DeriveKey(seed)
	return &PublicKey{key: pk, scheme: s}, &PrivateKey{key: sk, scheme: s}
}

func (s *Scheme) UnmarshalBinaryPublicKey(buf []byte) (sign.PublicKey, error) {
	pk, err := s.inner.UnmarshalBinaryPublicKey(buf)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: pk, scheme: s}, nil
}

func (s *Scheme) UnmarshalBinaryPrivateKey(buf []byte) (sign.PrivateKey, error) {
	sk, err := s.inner.UnmarshalBinaryPrivateKey(buf)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: sk, scheme: s}, nil
}

func (s *Scheme) PublicKeySize() int    { return s.inner.PublicKeySize() }
func (s *Scheme) PrivateKeySize() int   { return s.inner.PrivateKeySize() }
func (s *Scheme) SignatureSize() int    { return s.inner.SignatureSize() }
func (s *Scheme) SeedSize() int         { return s.inner.SeedSize() }
func (s *Scheme) SupportsContext() bool { return s.inner.SupportsContext() }
