// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package voucher

import (
	"github.com/fxamacker/cbor/v2"
)

// ccbor is the canonical (RFC 7049) CBOR encoder. The Python port encodes
// these structures with cbor2's canonical=True, which sorts map keys
// length-first then bytewise; CanonicalEncOptions does the same, so the two
// implementations produce byte-identical encodings (and hence shared test
// vectors).
var ccbor cbor.EncMode

func init() {
	em, err := cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	ccbor = em
}

// pleaseAdd is a joiner's request to be added: a display name plus the
// MessageStream read cap. The CBOR keys match the Python messages module.
type pleaseAdd struct {
	DisplayName    string `cbor:"DisplayName"`
	MessageReadCap []byte `cbor:"MessageReadCap"`
}

func (p *pleaseAdd) marshal() ([]byte, error) { return ccbor.Marshal(p) }

func pleaseAddFromBytes(data []byte) (*pleaseAdd, error) {
	p := &pleaseAdd{}
	if err := cbor.Unmarshal(data, p); err != nil {
		return nil, err
	}
	return p, nil
}

// signedPleaseAdd wraps the CBOR of a pleaseAdd with an Ed25519 signature
// over those bytes, made by the read cap's root signing key.
type signedPleaseAdd struct {
	PleaseAdd []byte `cbor:"PleaseAdd"`
	Signature []byte `cbor:"Signature"`
}

func (s *signedPleaseAdd) marshal() ([]byte, error) { return ccbor.Marshal(s) }

func signedPleaseAddFromBytes(data []byte) (*signedPleaseAdd, error) {
	s := &signedPleaseAdd{}
	if err := cbor.Unmarshal(data, s); err != nil {
		return nil, err
	}
	return s, nil
}

// voucherPayload is VoucherStream box 0's content: the signedPleaseAdd and
// the ReplyStream public key.
type voucherPayload struct {
	SignedPleaseAdd []byte `cbor:"SignedPleaseAdd"`
	ReplyPubKey     []byte `cbor:"ReplyPubKey"`
}

func (v *voucherPayload) marshal() ([]byte, error) { return ccbor.Marshal(v) }

func voucherPayloadFromBytes(data []byte) (*voucherPayload, error) {
	v := &voucherPayload{}
	if err := cbor.Unmarshal(data, v); err != nil {
		return nil, err
	}
	return v, nil
}

// voucherReply is the sealed reply plaintext: an opaque WhoReply blob plus
// the VoucherSalt that becomes the joiner's live MessageStream context.
type voucherReply struct {
	WhoReply    []byte `cbor:"WhoReply"`
	VoucherSalt []byte `cbor:"VoucherSalt"`
}

func (v *voucherReply) marshal() ([]byte, error) { return ccbor.Marshal(v) }

func voucherReplyFromBytes(data []byte) (*voucherReply, error) {
	v := &voucherReply{}
	if err := cbor.Unmarshal(data, v); err != nil {
		return nil, err
	}
	return v, nil
}
