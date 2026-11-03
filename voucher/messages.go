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
// the VoucherKeypair public key.
type voucherPayload struct {
	SignedPleaseAdd []byte `cbor:"SignedPleaseAdd"`
	VoucherPubKey   []byte `cbor:"VoucherPubKey"`
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
// the VoucherSalt that re-seeds the joiner's MessageStream KDF ratchet.
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

// voucherPayloadV2 is box 0 in the compact form: the CBOR array
// [read_cap, voucher_pub_key, display_name]. The Voucher is the hash of
// these bytes, which is what authenticates them; there is no signature.
type voucherPayloadV2 struct {
	_              struct{} `cbor:",toarray"`
	MessageReadCap []byte
	VoucherPubKey  []byte
	DisplayName    string
}

func (v *voucherPayloadV2) marshal() ([]byte, error) { return ccbor.Marshal(v) }

func voucherPayloadV2FromBytes(data []byte) (*voucherPayloadV2, error) {
	v := &voucherPayloadV2{}
	if err := cbor.Unmarshal(data, v); err != nil {
		return nil, err
	}
	return v, nil
}

// voucherReplyV2 is the sealed reply plaintext in the compact form: the
// CBOR array [who_reply, salt].
type voucherReplyV2 struct {
	_           struct{} `cbor:",toarray"`
	WhoReply    []byte
	VoucherSalt []byte
}

func (r *voucherReplyV2) marshal() ([]byte, error) { return ccbor.Marshal(r) }

func voucherReplyV2FromBytes(data []byte) (*voucherReplyV2, error) {
	r := &voucherReplyV2{}
	if err := cbor.Unmarshal(data, r); err != nil {
		return nil, err
	}
	return r, nil
}

// PayloadVersion is 1 for the map form of a VoucherPayload and 2 for the
// array form, by the first byte's CBOR major type.
func PayloadVersion(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, ErrInvalidArgument
	}
	switch data[0] >> 5 {
	case 5:
		return 1, nil
	case 4:
		return 2, nil
	}
	return 0, ErrInvalidArgument
}
