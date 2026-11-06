// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package voucher implements the cryptography of the Contact Voucher, the way
// a newcomer joins a Pigeonhole group.
//
// The joiner mints a Voucher, a 32-byte code it hands to a member of the
// group out of band. Both sides derive the same rendezvous BACAP stream from
// the Voucher: the joiner publishes its request in box 0, and the member
// answering (the inductor) publishes a sealed reply from box 1 on. The reply
// carries the group's members and a salt that moves the joiner's stream to
// a fresh, unpredictable position.
//
// # Flow
//
//	joiner:    m := VoucherMintCompact(writeCap, name, nil)
//	           write m.VoucherPayload to box 0 of the stream at m.VoucherWriteCap
//	           hand m.Voucher to a member; keep m.VoucherSecretKey
//	inductor:  s := DeriveVoucherStream(voucher); read box 0 with s.VoucherReadCap
//	           r := VoucherInduct(voucher, payload, whoReply, nil, nil)
//	           write r.SealedReply from box 1 on (see Forms); give the group r.MutatedMessageReadCap
//	joiner:    read the reply from box 1 on
//	           o := VoucherOpenReply(m.VoucherSecretKey, sealedReply, writeCap)
//	           write to the group with o.MutatedMessageWriteCap; read members from o.WhoReply
//
// # Forms
//
// A Voucher comes in two forms, chosen when it is minted.
//
//   - Compact (VoucherMintCompact, the default of VoucherMint): box 0 is the
//     CBOR array [read_cap, voucher_pub_key, display_name, signature]. The
//     reply is a single-recipient sealed box written framed over boxes 1, 2,
//     …: pieces of the box size less one byte, each behind 'C', the last
//     behind 'F'.
//   - Long (VoucherMintLong): box 0 is the signed CBOR map form that clients
//     before the compact form read. The reply is the MKEM ciphertext,
//     written unframed in box 1 alone.
//
// VoucherInduct answers a payload in the form it was minted in, and
// VoucherOpenReply opens either. PayloadVersion tells the forms apart. The
// framing of a compact reply over boxes is the caller's to do; this package
// only seals and opens.
//
// Both forms are authenticated twice. The Voucher is the BLAKE2b-256 of box
// 0, so the inductor detects any change to it. The payload is signed by the
// joiner's stream root key, so the joiner holds the stream it names.
//
// # Guarantees
//
// Every function is pure: no IO, no clock, no global state. Secrets and
// capabilities cross the API as opaque bytes. Randomness can be fixed by the
// seed and salt arguments, and with them this package and the Python package
// hpqc.voucher produce the same bytes; the shared vectors are
// testdata/voucher_vectors.json (long form) and
// testdata/voucher_vectors_v2.json (compact form). Pass nil seeds in
// production.
//
// Specification: katzenpost/website, docs/specs/katzenqt1_reticulum.md
// (Vouchers) and docs/specs/contact_voucher_narration.md.
package voucher

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"io"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/protocols/mkem"
	"github.com/katzenpost/hpqc/protocols/sealedbox"
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
	// sealBox seals the compact form's reply: one recipient, no DEK layer.
	sealBox = sealedbox.NewScheme(sealNike)
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
	// Version is the payload's form: 2 the compact array, 1 the signed map.
	Version          int
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
	// Version is the form the payload was in and the reply is in: 2 is the
	// compact array, sealed as a sealed box and written framed over boxes 1
	// on; 1 is the signed map, sealed with the MKEM and written to box 1.
	Version               int
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

// VoucherMint mints a Voucher in the compact form. It is VoucherMintCompact,
// the form new clients use; see VoucherMintLong for joining an inductor that
// only reads the long form.
func VoucherMint(messageWriteCap []byte, displayName string, keypairSeed []byte) (*MintResult, error) {
	return VoucherMintCompact(messageWriteCap, displayName, keypairSeed)
}

// VoucherMintCompact mints a Voucher in the compact form.
//
// messageWriteCap is the joiner's own MessageStream write capability (a
// marshalled bacap.WriteCap); displayName is the name the group will show.
// The result's VoucherPayload, the CBOR array [read_cap, voucher_pub_key,
// display_name, signature], goes to box 0 of the stream at VoucherWriteCap;
// Voucher is handed to a member out of band; VoucherSecretKey must be kept to
// open the reply, which will be a sealed box framed over boxes 1 on.
//
// keypairSeed fixes the seal keypair for test vectors; pass nil otherwise.
// Errors: ErrInvalidArgument for a malformed write cap.
func VoucherMintCompact(messageWriteCap []byte, displayName string, keypairSeed []byte) (*MintResult, error) {
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
	vp := &voucherPayloadV2{MessageReadCap: readCapBytes, VoucherPubKey: voucherPub, DisplayName: displayName}
	signed, err := vp.signedBytes()
	if err != nil {
		return nil, err
	}
	vp.Signature = writeCap.RootPrivateKey().SignMessage(signed)
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
		Version:          2,
		Voucher:          voucher[:],
		VoucherPayload:   payloadBytes,
		VoucherWriteCap:  stream.VoucherWriteCap,
		VoucherReadCap:   stream.VoucherReadCap,
		VoucherSecretKey: voucherPriv,
		VoucherPublicKey: voucherPub,
	}, nil
}

// VoucherMintLong mints a Voucher in the long form, the signed CBOR map that
// inductors from before the compact form read. Use it to join a group whose
// members have not upgraded. The reply will be the MKEM ciphertext, unframed
// in box 1 alone. Arguments, results and errors are as for
// VoucherMintCompact.
func VoucherMintLong(messageWriteCap []byte, displayName string, keypairSeed []byte) (*MintResult, error) {
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
		Version:          1,
		Voucher:          voucher[:],
		VoucherPayload:   payloadBytes,
		VoucherWriteCap:  stream.VoucherWriteCap,
		VoucherReadCap:   stream.VoucherReadCap,
		VoucherSecretKey: voucherPriv,
		VoucherPublicKey: voucherPub,
	}, nil
}

// VoucherInduct answers a Voucher: it checks the published payload and seals
// a reply to the joiner, in the form the payload was minted in.
//
// voucher is the code the joiner handed over; voucherPayload is what box 0
// of its stream (from DeriveVoucherStream) holds; whoReply is the opaque
// group membership to send, the protocol's ReplyWho encoding. The result's
// SealedReply is written from box 1 on: framed if Version is 2, unframed in
// box 1 if Version is 1. MutatedMessageReadCap is where the group reads the
// joiner from now on; DisplayName is the name it asked for.
//
// salt and sealSeed fix the salt and the seal's ephemeral key for test
// vectors; pass nil otherwise. Errors: ErrVoucherHashMismatch when the
// payload is not the one the Voucher names, ErrSignatureVerificationFailed
// when its signature does not verify under the read cap it names, and
// ErrInvalidArgument for anything malformed.
func VoucherInduct(voucher, voucherPayload, whoReply, salt, sealSeed []byte) (*InductResult, error) {
	if len(voucher) != hash.HashSize {
		return nil, ErrInvalidArgument
	}
	got := hash.Sum256(voucherPayload)
	if !hmac.Equal(got[:], voucher) {
		return nil, ErrVoucherHashMismatch
	}
	version, err := PayloadVersion(voucherPayload)
	if err != nil {
		return nil, err
	}
	var displayName string
	var readCapBytes, voucherPubKey []byte
	if version == 2 {
		vp, err := voucherPayloadV2FromBytes(voucherPayload)
		if err != nil {
			return nil, ErrInvalidArgument
		}
		rc, err := bacap.ReadCapFromBytes(vp.MessageReadCap)
		if err != nil {
			return nil, ErrInvalidArgument
		}
		signed, err := vp.signedBytes()
		if err != nil {
			return nil, ErrInvalidArgument
		}
		if !rc.RootPublicKey().Verify(vp.Signature, signed) {
			return nil, ErrSignatureVerificationFailed
		}
		displayName, readCapBytes, voucherPubKey = vp.DisplayName, vp.MessageReadCap, vp.VoucherPubKey
	} else {
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
		rc, err := bacap.ReadCapFromBytes(pa.MessageReadCap)
		if err != nil {
			return nil, ErrInvalidArgument
		}
		if !rc.RootPublicKey().Verify(spa.Signature, spa.PleaseAdd) {
			return nil, ErrSignatureVerificationFailed
		}
		displayName, readCapBytes, voucherPubKey = pa.DisplayName, pa.MessageReadCap, vp.VoucherPubKey
	}
	readCap, err := bacap.ReadCapFromBytes(readCapBytes)
	if err != nil {
		return nil, ErrInvalidArgument
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
	var sealed []byte
	if version == 2 {
		sealed, err = sealReplyV2(voucherPubKey, whoReply, salt, sealSeed)
	} else {
		sealed, err = sealReply(voucherPubKey, whoReply, salt, sealSeed)
	}
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
		Version:               version,
		DisplayName:           displayName,
		MutatedMessageReadCap: mutatedReadCap,
		SealedReply:           sealed,
		VoucherWriteCap:       stream.VoucherWriteCap,
		VoucherReadCap:        stream.VoucherReadCap,
		Salt:                  salt,
	}, nil
}

// VoucherOpenReply opens the reply to a Voucher the caller minted.
//
// voucherSecretKey is MintResult.VoucherSecretKey; sealedReply is the reply's
// bytes, reassembled from boxes 1 on for a compact Voucher or box 1 alone for
// a long one (either is accepted); messageWriteCap is the write cap the
// Voucher was minted from. The result's MutatedMessageWriteCap is where the
// joiner writes to the group from now on, the stream the inductor told the
// group to read; WhoReply is the group membership the inductor sent.
//
// Errors: ErrSealOpenFailed when the reply was not sealed to this key or is
// malformed, ErrInvalidArgument for a malformed key or write cap.
func VoucherOpenReply(voucherSecretKey, sealedReply, messageWriteCap []byte) (*OpenReplyResult, error) {
	priv, err := sealNike.UnmarshalBinaryPrivateKey(voucherSecretKey)
	if err != nil {
		return nil, ErrInvalidArgument
	}
	var whoReply, voucherSalt []byte
	if isMKEMReply(sealedReply) {
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
		whoReply, voucherSalt = reply.WhoReply, reply.VoucherSalt
	} else {
		plaintext, err := sealBox.Open(priv, sealNike.DerivePublicKey(priv), sealedReply)
		if err != nil {
			return nil, ErrSealOpenFailed
		}
		reply, err := voucherReplyV2FromBytes(plaintext)
		if err != nil || len(reply.VoucherSalt) != VoucherSaltSize {
			return nil, ErrSealOpenFailed
		}
		whoReply, voucherSalt = reply.WhoReply, reply.VoucherSalt
	}
	reply := &voucherReply{WhoReply: whoReply, VoucherSalt: voucherSalt}

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

// DeriveVoucherStream returns the rendezvous stream's capabilities, which
// both sides compute from the Voucher alone: the inductor reads box 0 and
// writes the reply with them, the joiner reads the reply. Box 0 is the
// stream's first index; the reply starts at the next. Errors:
// ErrInvalidArgument unless voucher is 32 bytes.
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

// isMKEMReply says whether a sealed reply is the map form's MKEM ciphertext:
// a CBOR map with its three keys. The sealed box form begins with an
// ephemeral public key, not a map.
func isMKEMReply(sealed []byte) bool {
	if len(sealed) == 0 || sealed[0]>>5 != 5 {
		return false
	}
	var m map[string]cbor.RawMessage
	if err := cbor.Unmarshal(sealed, &m); err != nil || len(m) != 3 {
		return false
	}
	_, a := m["EphemeralPublicKey"]
	_, b := m["DEKCiphertexts"]
	_, c := m["Envelope"]
	return a && b && c
}

// sealReplyV2 seals [who_reply, salt] to the VoucherKeypair public key as a
// sealed box, the ephemeral key from SHAKE256(sealSeed) when given.
func sealReplyV2(voucherPubKey, whoReply, salt, sealSeed []byte) ([]byte, error) {
	voucherPub, err := sealNike.UnmarshalBinaryPublicKey(voucherPubKey)
	if err != nil {
		return nil, ErrInvalidArgument
	}
	plaintext, err := (&voucherReplyV2{WhoReply: whoReply, VoucherSalt: salt}).marshal()
	if err != nil {
		return nil, err
	}
	if sealSeed == nil {
		return sealBox.Seal(voucherPub, plaintext)
	}
	return sealBox.SealWithEntropy(voucherPub, plaintext, shakeReader(sealSeed))
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
		_, ct, err = sealMKEM.Encapsulate([]nike.PublicKey{voucherPub}, plaintext)
	} else {
		_, ct, err = sealMKEM.EncapsulateWithEntropy([]nike.PublicKey{voucherPub}, plaintext, shakeReader(sealSeed))
	}
	if err != nil {
		return nil, err
	}
	return ct.Marshal(), nil
}
