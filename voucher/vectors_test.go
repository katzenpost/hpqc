// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package voucher

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// vectors is the shared cross-language fixture: the Python implementation
// produced it, and this test proves the Go implementation reproduces every
// field byte-for-byte from the same deterministic inputs. The Python suite
// asserts against the same file, so the two are pinned to each other.
type vectors struct {
	Inputs struct {
		MessageWriteCap string `json:"message_write_cap"`
		DisplayName     string `json:"display_name"`
		ReplySeed       string `json:"reply_seed"`
		Salt            string `json:"salt"`
		SealSeed        string `json:"seal_seed"`
		WhoReply        string `json:"who_reply"`
	} `json:"inputs"`
	Mint struct {
		Voucher         string `json:"voucher"`
		VoucherPayload  string `json:"voucher_payload"`
		VoucherWriteCap string `json:"voucher_write_cap"`
		VoucherReadCap  string `json:"voucher_read_cap"`
		ReplyPrivateKey string `json:"reply_private_key"`
		ReplyPublicKey  string `json:"reply_public_key"`
	} `json:"mint"`
	Induct struct {
		DisplayName     string `json:"display_name"`
		MessageReadCap  string `json:"message_read_cap"`
		SealedReply     string `json:"sealed_reply"`
		VoucherWriteCap string `json:"voucher_write_cap"`
		VoucherReadCap  string `json:"voucher_read_cap"`
		Salt            string `json:"salt"`
	} `json:"induct"`
	Open struct {
		WhoReply string `json:"who_reply"`
		Salt     string `json:"salt"`
	} `json:"open"`
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()
	data, err := os.ReadFile("testdata/voucher_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	v := &vectors{}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func eqHex(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if g := hex.EncodeToString(got); g != want {
		t.Errorf("%s mismatch:\n go: %s\n py: %s", name, g, want)
	}
}

func TestVectorsMint(t *testing.T) {
	v := loadVectors(t)
	mint, err := VoucherMint(
		unhex(t, v.Inputs.MessageWriteCap),
		v.Inputs.DisplayName,
		unhex(t, v.Inputs.ReplySeed),
	)
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, "voucher", mint.Voucher, v.Mint.Voucher)
	eqHex(t, "voucher_payload", mint.VoucherPayload, v.Mint.VoucherPayload)
	eqHex(t, "voucher_write_cap", mint.VoucherWriteCap, v.Mint.VoucherWriteCap)
	eqHex(t, "voucher_read_cap", mint.VoucherReadCap, v.Mint.VoucherReadCap)
	eqHex(t, "reply_private_key", mint.ReplyPrivateKey, v.Mint.ReplyPrivateKey)
	eqHex(t, "reply_public_key", mint.ReplyPublicKey, v.Mint.ReplyPublicKey)
}

func TestVectorsInduct(t *testing.T) {
	v := loadVectors(t)
	induct, err := VoucherInduct(
		unhex(t, v.Mint.Voucher),
		unhex(t, v.Mint.VoucherPayload),
		unhex(t, v.Inputs.WhoReply),
		unhex(t, v.Inputs.Salt),
		unhex(t, v.Inputs.SealSeed),
	)
	if err != nil {
		t.Fatal(err)
	}
	if induct.DisplayName != v.Induct.DisplayName {
		t.Errorf("display name: got %q want %q", induct.DisplayName, v.Induct.DisplayName)
	}
	eqHex(t, "message_read_cap", induct.MessageReadCap, v.Induct.MessageReadCap)
	eqHex(t, "sealed_reply", induct.SealedReply, v.Induct.SealedReply)
	eqHex(t, "voucher_write_cap", induct.VoucherWriteCap, v.Induct.VoucherWriteCap)
	eqHex(t, "salt", induct.Salt, v.Induct.Salt)
}

func TestVectorsOpenReply(t *testing.T) {
	v := loadVectors(t)
	open, err := VoucherOpenReply(
		unhex(t, v.Mint.ReplyPrivateKey),
		unhex(t, v.Induct.SealedReply),
	)
	if err != nil {
		t.Fatal(err)
	}
	eqHex(t, "who_reply", open.WhoReply, v.Open.WhoReply)
	eqHex(t, "salt", open.Salt, v.Open.Salt)
}
