// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package mrhybrid

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
)

// ErrMalformedCiphertext reports a decoded ciphertext whose parts are
// inconsistent with each other or with the scheme.
var ErrMalformedCiphertext = errors.New("mrhybrid: malformed ciphertext")

var (
	ccbor cbor.EncMode

	// dcbor decodes untrusted ciphertexts. Its limits keep a hostile blob
	// from costing more than its own size to decode, and from carrying more
	// pairs than MaxRecipients.
	dcbor cbor.DecMode
)

// Ciphertext is one payload addressed to several recipients: one KEM
// ciphertext and one DEK per recipient, and the payload sealed once.
type Ciphertext struct {
	KEMCiphertexts [][]byte
	DEKCiphertexts [][]byte
	Envelope       []byte
}

// ForRecipient returns the ciphertext recipient i is handed: the envelope,
// and only recipient i's KEM ciphertext and DEK.
func (c *Ciphertext) ForRecipient(i int) *Ciphertext {
	if c == nil {
		return &Ciphertext{}
	}
	out := &Ciphertext{Envelope: c.Envelope}
	if i >= 0 && i < len(c.KEMCiphertexts) && i < len(c.DEKCiphertexts) {
		out.KEMCiphertexts = [][]byte{c.KEMCiphertexts[i]}
		out.DEKCiphertexts = [][]byte{c.DEKCiphertexts[i]}
	}
	return out
}

// Marshal encodes the ciphertext as canonical CBOR.
func (c *Ciphertext) Marshal() []byte {
	blob, err := ccbor.Marshal(c)
	if err != nil {
		panic(err)
	}
	return blob
}

// CiphertextFromBytes decodes a ciphertext produced by Marshal.
func CiphertextFromBytes(scheme *Scheme, b []byte) (*Ciphertext, error) {
	if !scheme.valid() {
		return nil, ErrInvalidScheme
	}
	c := &Ciphertext{}
	if err := dcbor.Unmarshal(b, c); err != nil {
		return nil, err
	}
	if len(c.KEMCiphertexts) == 0 {
		return nil, ErrMalformedCiphertext
	}
	if err := scheme.checkShape(c); err != nil {
		return nil, err
	}
	return c, nil
}

// checkShape reports whether c's parts have the sizes the scheme produces:
// as many DEKs as KEM ciphertexts, at most MaxRecipients of them, each of
// exactly its size, and an envelope at least EnvelopeOverhead long.
func (s *Scheme) checkShape(c *Ciphertext) error {
	if len(c.KEMCiphertexts) != len(c.DEKCiphertexts) || len(c.KEMCiphertexts) > MaxRecipients {
		return ErrMalformedCiphertext
	}
	ctSize := s.kem.CiphertextSize()
	for i := range c.KEMCiphertexts {
		if len(c.KEMCiphertexts[i]) != ctSize || len(c.DEKCiphertexts[i]) != DEKSize {
			return ErrMalformedCiphertext
		}
	}
	if len(c.Envelope) < EnvelopeOverhead {
		return ErrMalformedCiphertext
	}
	return nil
}

func init() {
	var err error
	ccbor, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	dcbor, err = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		MaxNestedLevels:   4,
		MaxArrayElements:  MaxRecipients,
		MaxMapPairs:       16,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		FieldNameMatching: cbor.FieldNameMatchingCaseSensitive,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}
