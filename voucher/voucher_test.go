// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package voucher

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
)

// The Python hpqc.voucher.derive_voucher_stream of the voucher 0x00..0x1f,
// captured from the reference implementation. Proves the SHAKE256-seeded
// BACAP derivation agrees across the two tongues.
const (
	pyVWrite = "69f07c8840ce80024db30939882c3d5bbc9c98b3e31e4513ebd2ca9b4503cdd37f11eff9e9087568203f383f9d9bdf5b254170f65f0c6fa49d2954ed51173b881006b420b77b47429fce1a2ba8b60449e521f01db004cce92013e387643f2600bc6e37829f9c58789dcf42f4919652a91204029651c53477f6107652f8b9100ed03505ae25240fa1c0b5b4119fb481e72a69454691dc32bcc9be797a2e3775124ad433b2ebe11504"
	pyVRead  = "7f11eff9e9087568203f383f9d9bdf5b254170f65f0c6fa49d2954ed51173b881006b420b77b47429fce1a2ba8b60449e521f01db004cce92013e387643f2600bc6e37829f9c58789dcf42f4919652a91204029651c53477f6107652f8b9100ed03505ae25240fa1c0b5b4119fb481e72a69454691dc32bcc9be797a2e3775124ad433b2ebe11504"
)

func voucher0to31() []byte {
	v := make([]byte, 32)
	for i := range v {
		v[i] = byte(i)
	}
	return v
}

func TestDeriveVoucherStreamMatchesPython(t *testing.T) {
	stream, err := DeriveVoucherStream(voucher0to31())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(stream.VoucherWriteCap); got != pyVWrite {
		t.Errorf("write cap mismatch:\n go: %s\n py: %s", got, pyVWrite)
	}
	if got := hex.EncodeToString(stream.VoucherReadCap); got != pyVRead {
		t.Errorf("read cap mismatch:\n go: %s\n py: %s", got, pyVRead)
	}
}

func TestRoundTrip(t *testing.T) {
	bobWC, err := bacap.NewWriteCap(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bob, _ := bobWC.MarshalBinary()
	whoReply := []byte("opaque-membership-blob")

	mint, err := VoucherMint(bob, "bob", nil)
	if err != nil {
		t.Fatal(err)
	}
	induct, err := VoucherInduct(mint.Voucher, mint.VoucherPayload, whoReply, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if induct.DisplayName != "bob" {
		t.Errorf("display name: got %q", induct.DisplayName)
	}
	// The inductor returns Bob's salt-mutated read cap, not the raw one.
	wantMutatedReadCap, _ := bobWC.ReadCap().MutateKDFState(induct.Salt).MarshalBinary()
	if !bytes.Equal(induct.MutatedMessageReadCap, wantMutatedReadCap) {
		t.Error("mutated message read cap mismatch")
	}
	if !bytes.Equal(induct.VoucherWriteCap, mint.VoucherWriteCap) {
		t.Error("voucher write cap mismatch between mint and induct")
	}
	opened, err := VoucherOpenReply(mint.VoucherSecretKey, induct.SealedReply, bob)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened.WhoReply, whoReply) {
		t.Error("who reply mismatch")
	}
	if !bytes.Equal(opened.Salt, induct.Salt) {
		t.Error("salt mismatch")
	}
	// The crux: Bob's mutated write cap and Alice's mutated read cap meet.
	mutatedWC, err := bacap.NewWriteCapFromBytes(opened.MutatedMessageWriteCap)
	if err != nil {
		t.Fatal(err)
	}
	mutatedWCRead, _ := mutatedWC.ReadCap().MarshalBinary()
	if !bytes.Equal(mutatedWCRead, induct.MutatedMessageReadCap) {
		t.Error("mutated write cap's read cap does not match the inductor's mutated read cap")
	}
}

func TestHashMismatchRejected(t *testing.T) {
	bobWC, _ := bacap.NewWriteCap(rand.Reader)
	bob, _ := bobWC.MarshalBinary()
	mint, _ := VoucherMint(bob, "bob", nil)
	tampered := append([]byte(nil), mint.VoucherPayload...)
	tampered[0] ^= 0xFF
	if _, err := VoucherInduct(mint.Voucher, tampered, []byte("x"), nil, nil); err != ErrVoucherHashMismatch {
		t.Errorf("expected hash mismatch, got %v", err)
	}
}

func TestWrongReplyKeyCannotOpen(t *testing.T) {
	wcA, _ := bacap.NewWriteCap(rand.Reader)
	a, _ := wcA.MarshalBinary()
	wcB, _ := bacap.NewWriteCap(rand.Reader)
	b, _ := wcB.MarshalBinary()
	mintA, _ := VoucherMint(a, "alice", nil)
	mintB, _ := VoucherMint(b, "bob", nil)
	induct, _ := VoucherInduct(mintA.Voucher, mintA.VoucherPayload, []byte("x"), nil, nil)
	if _, err := VoucherOpenReply(mintB.VoucherSecretKey, induct.SealedReply, b); err != ErrSealOpenFailed {
		t.Errorf("expected seal open failed, got %v", err)
	}
}

// An inductor answers a map payload with the MKEM reply and an array payload
// with the sealed box, and a joiner opens either.
func TestBothFormsRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mint    func([]byte, string, []byte) (*MintResult, error)
		version int
	}{{"compact", VoucherMint, 2}, {"map", VoucherMintV1, 1}} {
		t.Run(tc.name, func(t *testing.T) {
			bobWC, _ := bacap.NewWriteCap(rand.Reader)
			bob, _ := bobWC.MarshalBinary()
			mint, err := tc.mint(bob, "bob", nil)
			if err != nil {
				t.Fatal(err)
			}
			if v, _ := PayloadVersion(mint.VoucherPayload); v != tc.version || mint.Version != tc.version {
				t.Fatalf("payload version %d, mint %d", v, mint.Version)
			}
			induct, err := VoucherInduct(mint.Voucher, mint.VoucherPayload, []byte("who"), nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if induct.Version != tc.version {
				t.Errorf("induct version %d", induct.Version)
			}
			if isMKEMReply(induct.SealedReply) != (tc.version == 1) {
				t.Errorf("reply form does not follow the payload's")
			}
			if tc.version == 2 {
				if want := sealNike.PublicKeySize() + 16 + 1 + 1 + 3 + 2 + VoucherSaltSize; len(induct.SealedReply) != want {
					t.Errorf("sealed reply %d bytes, want %d", len(induct.SealedReply), want)
				}
			}
			opened, err := VoucherOpenReply(mint.VoucherSecretKey, induct.SealedReply, bob)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(opened.WhoReply, []byte("who")) || !bytes.Equal(opened.Salt, induct.Salt) {
				t.Error("reply did not round trip")
			}
		})
	}
}

func TestCompactPayloadRefusals(t *testing.T) {
	for _, bad := range [][]byte{{}, {0x00}, {0x82, 0x41, 0x78, 0x41, 0x79}, {0x83, 0x01, 0x02, 0x03}} {
		sum := hash.Sum256(bad)
		if _, err := VoucherInduct(sum[:], bad, []byte("who"), nil, nil); err == nil {
			t.Errorf("payload %x accepted", bad)
		}
	}
	bobWC, _ := bacap.NewWriteCap(rand.Reader)
	bob, _ := bobWC.MarshalBinary()
	mint, _ := VoucherMint(bob, "bob", nil)
	induct, _ := VoucherInduct(mint.Voucher, mint.VoucherPayload, []byte("who"), nil, nil)
	flipped := append([]byte(nil), induct.SealedReply...)
	flipped[len(flipped)-1] ^= 1
	if _, err := VoucherOpenReply(mint.VoucherSecretKey, flipped, bob); err != ErrSealOpenFailed {
		t.Errorf("tampered reply: %v", err)
	}
}
