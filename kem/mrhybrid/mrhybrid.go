// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package mrhybrid provides multi-recipient hybrid encryption over any KEM.
//
// This is not mkem: mkem is built over a NIKE, which lets one ephemeral key
// be combined with every recipient's public key, and lets a reply be sealed
// by combining a private key with the other party's public key. A KEM has no
// such combine operation, so here each recipient gets its own KEM ciphertext.
// The payload is still sealed once, under a random message key, which is
// wrapped under each recipient's derived key (a DEK). Encapsulate returns the
// derived keys to the sender and Decapsulate returns the recipient's derived
// key, so replies are a plain symmetric round trip under that key.
//
// The construction is CryptWalker's MultiRecipientHybrid.Adapter.hybridOfKEM
// with AES-256-GCM-SIV and BLAKE2b-256, byte for byte:
//
//	secret_i := BLAKE2b-256(ss_i)            for ct_i, ss_i := Encapsulate(pk_i)
//	envelope := nonce ‖ AEAD(msgKey, payload)
//	dek_i    := nonce_i ‖ AEAD(secret_i, msgKey)
package mrhybrid

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"github.com/agl/gcmsiv"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/util"
)

const (
	// KeySize is the AEAD key size, and the size of a derived key.
	KeySize = 32

	// NonceSize is the AES-256-GCM-SIV nonce size.
	NonceSize = 12

	// TagSize is the AES-256-GCM-SIV tag size.
	TagSize = 16

	// DEKSize is the size of one DEK: nonce, wrapped message key, tag.
	DEKSize = NonceSize + KeySize + TagSize

	// EnvelopeOverhead is how much longer an envelope is than its plaintext.
	EnvelopeOverhead = NonceSize + TagSize
)

var (
	// ErrInvalidKeySize reports an AEAD key that is not KeySize bytes.
	ErrInvalidKeySize = errors.New("mrhybrid: invalid AEAD key size")

	// ErrCiphertextTooShort reports a sealed value shorter than the nonce.
	ErrCiphertextTooShort = errors.New("mrhybrid: ciphertext shorter than the nonce")

	// ErrTrialDecryptFailed reports that no (KEM ciphertext, DEK) pair opened.
	ErrTrialDecryptFailed = errors.New("mrhybrid: failed to trial decrypt")

	// ErrDecapFailed reports the underlying KEM's decapsulation erroring.
	ErrDecapFailed = errors.New("mrhybrid: KEM decapsulation failed")

	// ErrNoRecipients reports an Encapsulate call with no recipients.
	ErrNoRecipients = errors.New("mrhybrid: no recipients")
)

// Scheme is multi-recipient hybrid encryption over a KEM.
type Scheme struct {
	kem kem.Scheme
}

// NewScheme returns the multi-recipient hybrid scheme over k.
func NewScheme(k kem.Scheme) *Scheme {
	return &Scheme{kem: k}
}

// Name returns the scheme's name.
func (s *Scheme) Name() string {
	return "MultiRecipientHybrid-" + s.kem.Name() + "-AES-256-GCM-SIV"
}

// KEM returns the underlying KEM.
func (s *Scheme) KEM() kem.Scheme {
	return s.kem
}

// GenerateKeyPair returns a fresh key pair of the underlying KEM.
func (s *Scheme) GenerateKeyPair() (kem.PublicKey, kem.PrivateKey, error) {
	return s.kem.GenerateKeyPair()
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}
	return gcmsiv.NewGCMSIV(key)
}

func seal(key, plaintext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func open(key, ciphertext []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < NonceSize {
		return nil, ErrCiphertextTooShort
	}
	return aead.Open(nil, ciphertext[:NonceSize], ciphertext[NonceSize:], nil)
}

func deriveKey(ss []byte) []byte {
	secret := hash.Sum256(ss)
	util.ExplicitBzero(ss)
	return secret[:]
}

// Encapsulate seals payload to every recipient in keys. It returns the
// derived key used for each recipient, in the order of keys; the sender
// must keep derivedKeys[i] to read recipient i's reply.
func (s *Scheme) Encapsulate(keys []kem.PublicKey, payload []byte) (derivedKeys [][]byte, ct *Ciphertext, err error) {
	if len(keys) == 0 {
		return nil, nil, ErrNoRecipients
	}
	kemCts := make([][]byte, len(keys))
	derivedKeys = make([][]byte, len(keys))
	for i, pk := range keys {
		var ss []byte
		kemCts[i], ss, err = s.kem.Encapsulate(pk)
		if err != nil {
			wipe(derivedKeys)
			return nil, nil, err
		}
		derivedKeys[i] = deriveKey(ss)
	}

	msgKey := make([]byte, KeySize)
	defer util.ExplicitBzero(msgKey)
	if _, err := rand.Read(msgKey); err != nil {
		wipe(derivedKeys)
		return nil, nil, err
	}
	envelope, err := seal(msgKey, payload)
	if err != nil {
		wipe(derivedKeys)
		return nil, nil, err
	}
	deks := make([][]byte, len(keys))
	for i := range derivedKeys {
		if deks[i], err = seal(derivedKeys[i], msgKey); err != nil {
			wipe(derivedKeys)
			return nil, nil, err
		}
	}
	return derivedKeys, &Ciphertext{
		KEMCiphertexts: kemCts,
		DEKCiphertexts: deks,
		Envelope:       envelope,
	}, nil
}

// Decapsulate opens ct with sk, returning the recipient's derived key and
// the payload. It tries each (KEM ciphertext, DEK) pair in turn, so it
// accepts both the full ciphertext and one reduced by ForRecipient.
func (s *Scheme) Decapsulate(sk kem.PrivateKey, ct *Ciphertext) (derivedKey, payload []byte, err error) {
	if len(ct.KEMCiphertexts) != len(ct.DEKCiphertexts) {
		return nil, nil, ErrTrialDecryptFailed
	}
	decapErr := false
	for i := range ct.KEMCiphertexts {
		ss, err := s.kem.Decapsulate(sk, ct.KEMCiphertexts[i])
		if err != nil {
			decapErr = true
			continue
		}
		secret := deriveKey(ss)
		msgKey, err := open(secret, ct.DEKCiphertexts[i])
		if err != nil {
			util.ExplicitBzero(secret)
			continue
		}
		payload, err = open(msgKey, ct.Envelope)
		util.ExplicitBzero(msgKey)
		if err != nil {
			util.ExplicitBzero(secret)
			return nil, nil, err
		}
		return secret, payload, nil
	}
	if decapErr && len(ct.KEMCiphertexts) == 1 {
		return nil, nil, ErrDecapFailed
	}
	return nil, nil, ErrTrialDecryptFailed
}

// EnvelopeReply seals a reply under a derived key both sides hold.
func (s *Scheme) EnvelopeReply(derivedKey, plaintext []byte) ([]byte, error) {
	return seal(derivedKey, plaintext)
}

// DecryptEnvelope opens a reply sealed by EnvelopeReply.
func (s *Scheme) DecryptEnvelope(derivedKey, envelope []byte) ([]byte, error) {
	return open(derivedKey, envelope)
}

func wipe(keys [][]byte) {
	for _, k := range keys {
		util.ExplicitBzero(k)
	}
}
