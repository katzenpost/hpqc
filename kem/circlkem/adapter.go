// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package circlkem adapts circl KEM types to hpqc KEM interfaces.
package circlkem

import (
	circlKem "github.com/katzenpost/circl/kem"

	"github.com/katzenpost/hpqc/kem"
)

var _ kem.Scheme = (*Scheme)(nil)
var _ kem.PublicKey = (*PublicKey)(nil)
var _ kem.PrivateKey = (*PrivateKey)(nil)

// PublicKey wraps a circl KEM public key.
type PublicKey struct {
	key    circlKem.PublicKey
	scheme *Scheme
}

func (pk *PublicKey) Scheme() kem.Scheme {
	return pk.scheme
}

func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	return pk.key.MarshalBinary()
}

func (pk *PublicKey) Equal(other kem.PublicKey) bool {
	otherPk, ok := other.(*PublicKey)
	if !ok {
		return false
	}
	return pk.key.Equal(otherPk.key)
}

// PrivateKey wraps a circl KEM private key.
type PrivateKey struct {
	key    circlKem.PrivateKey
	scheme *Scheme
}

func (sk *PrivateKey) Scheme() kem.Scheme {
	return sk.scheme
}

func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	return sk.key.MarshalBinary()
}

func (sk *PrivateKey) Equal(other kem.PrivateKey) bool {
	otherSk, ok := other.(*PrivateKey)
	if !ok {
		return false
	}
	return sk.key.Equal(otherSk.key)
}

func (sk *PrivateKey) Public() kem.PublicKey {
	return &PublicKey{
		key:    sk.key.Public(),
		scheme: sk.scheme,
	}
}

// Scheme wraps a circl KEM scheme.
type Scheme struct {
	inner circlKem.Scheme
}

// FromCircl wraps a circl KEM scheme as an hpqc KEM scheme.
func FromCircl(s circlKem.Scheme) kem.Scheme {
	return &Scheme{inner: s}
}

func (s *Scheme) Name() string {
	return s.inner.Name()
}

func (s *Scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	pk, sk, err := s.inner.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return &PublicKey{key: pk, scheme: s}, &PrivateKey{key: sk, scheme: s}, nil
}

func (s *Scheme) Encapsulate(pk kem.PublicKey) (ct, ss []byte, err error) {
	wrapper, ok := pk.(*PublicKey)
	if !ok {
		return nil, nil, kem.ErrTypeMismatch
	}
	return s.inner.Encapsulate(wrapper.key)
}

func (s *Scheme) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	wrapper, ok := sk.(*PrivateKey)
	if !ok {
		return nil, kem.ErrTypeMismatch
	}
	return s.inner.Decapsulate(wrapper.key, ct)
}

func (s *Scheme) UnmarshalBinaryPublicKey(buf []byte) (kem.PublicKey, error) {
	pk, err := s.inner.UnmarshalBinaryPublicKey(buf)
	if err != nil {
		return nil, err
	}
	return &PublicKey{key: pk, scheme: s}, nil
}

func (s *Scheme) UnmarshalBinaryPrivateKey(buf []byte) (kem.PrivateKey, error) {
	sk, err := s.inner.UnmarshalBinaryPrivateKey(buf)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{key: sk, scheme: s}, nil
}

func (s *Scheme) CiphertextSize() int { return s.inner.CiphertextSize() }
func (s *Scheme) SharedKeySize() int  { return s.inner.SharedKeySize() }
func (s *Scheme) PrivateKeySize() int { return s.inner.PrivateKeySize() }
func (s *Scheme) PublicKeySize() int  { return s.inner.PublicKeySize() }
func (s *Scheme) SeedSize() int       { return s.inner.SeedSize() }

func (s *Scheme) DeriveKeyPair(seed []byte) (kem.PublicKey, kem.PrivateKey) {
	pk, sk := s.inner.DeriveKeyPair(seed)
	return &PublicKey{key: pk, scheme: s}, &PrivateKey{key: sk, scheme: s}
}
