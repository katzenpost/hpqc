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

var ccbor cbor.EncMode

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
	c := &Ciphertext{}
	if err := cbor.Unmarshal(b, c); err != nil {
		return nil, err
	}
	if len(c.KEMCiphertexts) != len(c.DEKCiphertexts) {
		return nil, ErrMalformedCiphertext
	}
	for i := range c.KEMCiphertexts {
		if len(c.KEMCiphertexts[i]) != scheme.kem.CiphertextSize() || len(c.DEKCiphertexts[i]) != DEKSize {
			return nil, ErrMalformedCiphertext
		}
	}
	if len(c.Envelope) < EnvelopeOverhead {
		return nil, ErrMalformedCiphertext
	}
	return c, nil
}

func init() {
	var err error
	ccbor, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
}
