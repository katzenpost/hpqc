// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package voucher implements the Contact Voucher protocol cryptography.
//
// The Contact Voucher lets a newcomer (the joiner) hand an existing group
// member (the inductor) a single small Voucher out of band, after which the
// two exchange read capabilities through a hash-derived rendezvous stream.
// See website/content/en/docs/specs/contact_voucher_narration.md.
//
// The public surface is four pure functions, with no IO: VoucherMint,
// VoucherInduct, VoucherOpenReply, and DeriveVoucherStream. The caller
// performs all pigeonhole reads and writes, the all-or-nothing COPY, and the
// box-0 tombstone using the caps and payloads they return. This package and
// the Python package hpqc.voucher agree byte-for-byte under shared test
// vectors; randomness is injectable (a seed) so every function is
// deterministic for those vectors.
package voucher

import (
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"io"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
)

// VoucherSaltSize is the size of a VoucherSalt, which re-seeds the joiner's
// MessageStream KDF ratchet (see bacap.WriteCap.MutateKDFState).
const VoucherSaltSize = 32

var (
	// ErrInvalidArgument is returned for malformed caller input.
	ErrInvalidArgument = errors.New("voucher: invalid argument")
	// ErrVoucherHashMismatch is returned when a VoucherPayload does not hash
	// to the Voucher.
	ErrVoucherHashMismatch = errors.New("voucher: payload does not hash to the voucher")
	// ErrSignatureVerificationFailed is returned when the SignedPleaseAdd does
	// not verify under its read cap's root public key.
	ErrSignatureVerificationFailed = errors.New("voucher: signed please-add did not verify")
	// ErrSealOpenFailed is returned when a sealed reply cannot be opened.
	ErrSealOpenFailed = errors.New("voucher: could not open sealed reply")
)

// sealNike is the VoucherKeypair seal's hybrid NIKE: CTIDH1024-X25519, X25519
// first, the same scheme the storage replicas use. sealMKEM wraps it.
var (
	sealNike = schemes.ByName("CTIDH1024-X25519")
	sealMKEM = mkem.NewScheme(sealNike)
)

// shakeReader returns SHAKE256(seed) as an io.Reader. Python obtains the same
// stream from hashlib.shake_256(seed), so a shared seed yields identical keys
// and ciphertext across the two implementations.
func shakeReader(seed []byte) io.Reader {
	h := sha3.NewSHAKE256()
	h.Write(seed)
	return h
}

// MintResult is what VoucherMint returns. Voucher is the 32-byte token handed
// to the inductor out of band; VoucherPayload is published to VoucherStream
// box 0. The caller persists VoucherSecretKey to open the reply later.
type MintResult struct {
	Voucher          []byte
	VoucherPayload   []byte
	VoucherWriteCap  []byte
	VoucherReadCap   []byte
	VoucherSecretKey []byte
	VoucherPublicKey []byte
}

// InductResult is what VoucherInduct returns. MutatedMessageReadCap is the
// joiner's MessageStream read cap after the VoucherSalt has been applied: the
// live read cap the inductor hands the group. SealedReply is written to
// VoucherStream box 1; Salt is the VoucherSalt the inductor minted.
type InductResult struct {
	DisplayName           string
	MutatedMessageReadCap []byte
	SealedReply           []byte
	VoucherWriteCap       []byte
	VoucherReadCap        []byte
	Salt                  []byte
}

// OpenReplyResult is what VoucherOpenReply returns: the opaque WhoReply blob,
// the VoucherSalt, and MutatedMessageWriteCap, the joiner's MessageStream
// write cap after the salt has been applied (the live write cap to write
// real messages with).
type OpenReplyResult struct {
	WhoReply               []byte
	Salt                   []byte
	MutatedMessageWriteCap []byte
}

// VoucherStreamResult is what DeriveVoucherStream returns: the rendezvous
// stream caps.
type VoucherStreamResult struct {
	VoucherWriteCap []byte
	VoucherReadCap  []byte
}

// newVoucherKeypair generates a VoucherKeypair, deterministically from
// SHAKE256(seed) when seed is non-nil, otherwise at random.
func newVoucherKeypair(seed []byte) (priv, pub []byte, err error) {
	var pubKey nike.PublicKey
	var privKey nike.PrivateKey
	if seed == nil {
		pubKey, privKey, err = sealNike.GenerateKeyPair()
	} else {
		pubKey, privKey, err = sealNike.GenerateKeyPairFromEntropy(shakeReader(seed))
	}
	if err != nil {
		return nil, nil, err
	}
	return privKey.Bytes(), pubKey.Bytes(), nil
}

// VoucherMint mints a Voucher from the joiner's MessageStream write cap.
// keypairSeed may be nil for a random VoucherKeypair.
func VoucherMint(messageWriteCap []byte, displayName string, keypairSeed []byte) (*MintResult, error) {
	writeCap, err := bacap.NewWriteCapFromBytes(messageWriteCap)
	if err != nil {
		return nil, ErrInvalidArgument
	}
	readCapBytes, err := writeCap.ReadCap().MarshalBinary()
	if err != nil {
		return nil, err
	}
	voucherPriv, voucherPub, err := newVoucherKeypair(keypairSeed)
	if err != nil {
		return nil, err
	}

	pa := &pleaseAdd{DisplayName: displayName, MessageReadCap: readCapBytes}
	paBytes, err := pa.marshal()
	if err != nil {
		return nil, err
	}
	sig := writeCap.RootPrivateKey().SignMessage(paBytes)
	spa := &signedPleaseAdd{PleaseAdd: paBytes, Signature: sig}
	spaBytes, err := spa.marshal()
	if err != nil {
		return nil, err
	}

	vp := &voucherPayload{SignedPleaseAdd: spaBytes, VoucherPubKey: voucherPub}
	payloadBytes, err := vp.marshal()
	if err != nil {
		return nil, err
	}
	voucher := hash.Sum256(payloadBytes)

	stream, err := deriveStream(voucher[:])
	if err != nil {
		return nil, err
	}
	return &MintResult{
		Voucher:          voucher[:],
		VoucherPayload:   payloadBytes,
		VoucherWriteCap:  stream.VoucherWriteCap,
		VoucherReadCap:   stream.VoucherReadCap,
		VoucherSecretKey: voucherPriv,
		VoucherPublicKey: voucherPub,
	}, nil
}

// VoucherInduct verifies a published VoucherPayload and seals a reply to the
// joiner. salt and sealSeed may be nil (a fresh random salt, a random seal).
func VoucherInduct(voucher, voucherPayload, whoReply, salt, sealSeed []byte) (*InductResult, error) {
	if len(voucher) != hash.HashSize {
		return nil, ErrInvalidArgument
	}
	got := hash.Sum256(voucherPayload)
	if !constantTimeEqual(got[:], voucher) {
		return nil, ErrVoucherHashMismatch
	}
	vp, err := voucherPayloadFromBytes(voucherPayload)
	if err != nil {
		return nil, ErrInvalidArgument
	}
	spa, err := signedPleaseAddFromBytes(vp.SignedPleaseAdd)
	if err != nil {
		return nil, ErrInvalidArgument
	}
	pa, err := pleaseAddFromBytes(spa.PleaseAdd)
	if err != nil {
		return nil, ErrInvalidArgument
	}
	readCap, err := bacap.ReadCapFromBytes(pa.MessageReadCap)
	if err != nil {
		return nil, ErrInvalidArgument
	}
	if !readCap.RootPublicKey().Verify(spa.Signature, spa.PleaseAdd) {
		return nil, ErrSignatureVerificationFailed
	}

	if salt == nil {
		salt = make([]byte, VoucherSaltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
	}
	if len(salt) != VoucherSaltSize {
		return nil, ErrInvalidArgument
	}
	sealed, err := sealReply(vp.VoucherPubKey, whoReply, salt, sealSeed)
	if err != nil {
		return nil, err
	}

	// Mutate the joiner's read cap by the salt: this is the live read cap the
	// inductor hands the group, addressing the salt-determined box sequence.
	mutatedReadCap, err := readCap.MutateKDFState(salt).MarshalBinary()
	if err != nil {
		return nil, err
	}

	stream, err := deriveStream(voucher)
	if err != nil {
		return nil, err
	}
	return &InductResult{
		DisplayName:           pa.DisplayName,
		MutatedMessageReadCap: mutatedReadCap,
		SealedReply:           sealed,
		VoucherWriteCap:       stream.VoucherWriteCap,
		VoucherReadCap:        stream.VoucherReadCap,
		Salt:                  salt,
	}, nil
}

// VoucherOpenReply opens the inductor's sealed reply with the joiner's
// VoucherSecretKey, recovers the VoucherSalt, and mutates the joiner's
// MessageStream write cap by it. The returned MutatedMessageWriteCap is the
// live write cap with which the joiner writes real messages; it lands on the
// same box sequence as the read cap the inductor mutated and handed the group.
func VoucherOpenReply(voucherSecretKey, sealedReply, messageWriteCap []byte) (*OpenReplyResult, error) {
	priv, err := sealNike.UnmarshalBinaryPrivateKey(voucherSecretKey)
	if err != nil {
		return nil, ErrInvalidArgument
	}
	ct, err := mkem.CiphertextFromBytes(sealMKEM, sealedReply)
	if err != nil {
		return nil, ErrSealOpenFailed
	}
	plaintext, err := sealMKEM.Decapsulate(priv, ct)
	if err != nil {
		return nil, ErrSealOpenFailed
	}
	reply, err := voucherReplyFromBytes(plaintext)
	if err != nil {
		return nil, ErrSealOpenFailed
	}

	writeCap, err := bacap.NewWriteCapFromBytes(messageWriteCap)
	if err != nil {
		return nil, ErrInvalidArgument
	}
	mutatedWriteCap, err := writeCap.MutateKDFState(reply.VoucherSalt).MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &OpenReplyResult{
		WhoReply:               reply.WhoReply,
		Salt:                   reply.VoucherSalt,
		MutatedMessageWriteCap: mutatedWriteCap,
	}, nil
}

// DeriveVoucherStream derives the VoucherStream caps deterministically from
// the Voucher, which the inductor needs to read box 0 before inducting.
func DeriveVoucherStream(voucher []byte) (*VoucherStreamResult, error) {
	return deriveStream(voucher)
}

func deriveStream(voucher []byte) (*VoucherStreamResult, error) {
	if len(voucher) != hash.HashSize {
		return nil, ErrInvalidArgument
	}
	writeCap, err := bacap.NewWriteCap(shakeReader(voucher))
	if err != nil {
		return nil, err
	}
	wcBytes, err := writeCap.MarshalBinary()
	if err != nil {
		return nil, err
	}
	rcBytes, err := writeCap.ReadCap().MarshalBinary()
	if err != nil {
		return nil, err
	}
	return &VoucherStreamResult{VoucherWriteCap: wcBytes, VoucherReadCap: rcBytes}, nil
}

func sealReply(voucherPubKey, whoReply, salt, sealSeed []byte) ([]byte, error) {
	voucherPub, err := sealNike.UnmarshalBinaryPublicKey(voucherPubKey)
	if err != nil {
		return nil, ErrInvalidArgument
	}
	plaintext, err := (&voucherReply{WhoReply: whoReply, VoucherSalt: salt}).marshal()
	if err != nil {
		return nil, err
	}
	var ct *mkem.Ciphertext
	if sealSeed == nil {
		_, ct = sealMKEM.Encapsulate([]nike.PublicKey{voucherPub}, plaintext)
	} else {
		_, ct = sealMKEM.EncapsulateWithEntropy([]nike.PublicKey{voucherPub}, plaintext, shakeReader(sealSeed))
	}
	return ct.Marshal(), nil
}

// constantTimeEqual reports whether two equal-length byte slices are equal.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
