// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	stded25519 "crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/edwards25519"

	"github.com/katzenpost/hpqc/bacap"
)

// ===== Wider BACAP vectors =====
//
// The original BACAP vectors all use one write cap starting at Idx64 = 1.
// The functions here add caps derived from fixed seeds whose indexes start
// at a random value, just below 2^63 and just below 2^64, and the files
// that pin byte layouts, tombstones, binding of an index to a cap, and the
// inputs every implementation must reject.

const pigeonholeCtx = "pigeonhole context"

type bacapExtraCap struct {
	name string
	blob []byte
	wc   *bacap.WriteCap
}

// extraCapStart returns the Idx64 a cap's seed index starts from. The
// returned cap's first index is one step further, as NewMessageBoxIndex
// does.
var extraCapStarts = []struct {
	name  string
	start func() uint64
}{
	{"cap_random_start", func() uint64 {
		// The Irwin-Hall sum NewMessageBoxIndex draws, from fixed bytes.
		b := deterministicBytes("bacap-start", "cap_random_start", 16)
		b[7] &= 0x3f
		b[15] &= 0x3f
		return binary.LittleEndian.Uint64(b[:8]) + binary.LittleEndian.Uint64(b[8:])
	}},
	{"cap_near_2_63", func() uint64 { return 1<<63 - 4 }},
	{"cap_near_2_64", func() uint64 { return ^uint64(0) - 9 }},
}

func extraCaps() []bacapExtraCap {
	caps := make([]bacapExtraCap, 0, len(extraCapStarts))
	for _, c := range extraCapStarts {
		seed := deterministicBytes("bacap-cap-seed", c.name, 32)
		priv := stded25519.NewKeyFromSeed(seed)
		var hk [32]byte
		copy(hk[:], deterministicBytes("bacap-cap-hkdf", c.name, 32))
		first, err := (&bacap.MessageBoxIndex{Idx64: c.start(), HKDFState: hk}).NextIndex()
		must(err)
		idxBytes, err := first.MarshalBinary()
		must(err)
		blob := append(append([]byte{}, priv...), idxBytes...)
		wc, err := bacap.NewWriteCapFromBytes(blob)
		must(err)
		caps = append(caps, bacapExtraCap{c.name, blob, wc})
	}
	return caps
}

// advancesFor keeps every advance inside the uint64 range: the cap near
// 2^64 is advanced to exactly 2^64 - 1 and no further.
func advancesFor(c bacapExtraCap, wide, near []uint64) []uint64 {
	if c.name == "cap_near_2_64" {
		return near
	}
	return wide
}

func advanced(idx *bacap.MessageBoxIndex, by uint64) *bacap.MessageBoxIndex {
	if by == 0 {
		return idx
	}
	out, err := idx.AdvanceIndexTo(idx.Idx64 + by)
	must(err)
	return out
}

func marshalIndex(idx *bacap.MessageBoxIndex) []byte {
	b, err := idx.MarshalBinary()
	must(err)
	return b
}

func extraMessageBoxIndexVectors() []bacapAdvanceVector {
	var vs []bacapAdvanceVector
	for _, c := range extraCaps() {
		idx := c.wc.GetMessageBoxIndex()
		for _, n := range advancesFor(c, []uint64{1, 17, 250}, []uint64{1, 4, 8}) {
			vs = append(vs, bacapAdvanceVector{
				Name:             fmt.Sprintf("%s_advance_by_%d", c.name, n),
				InitialIndexHex:  hex.EncodeToString(marshalIndex(idx)),
				AdvanceTo:        idx.Idx64 + n,
				ExpectedIndexHex: hex.EncodeToString(marshalIndex(advanced(idx, n))),
			})
		}
	}
	return vs
}

func extraBoxIDVectors() []bacapBoxIDVector {
	var vs []bacapBoxIDVector
	for _, c := range extraCaps() {
		rc := c.wc.ReadCap()
		for _, k := range []struct {
			by         uint64
			useContext bool
		}{{0, false}, {advancesFor(c, []uint64{4}, []uint64{4})[0], true}} {
			idx := advanced(c.wc.GetMessageBoxIndex(), k.by)
			var ctx, box []byte
			if k.useContext {
				ctx = []byte(pigeonholeCtx)
				pk, err := idx.BoxIDForContext(rc, ctx)
				must(err)
				box = pk.Bytes()
			} else {
				pk, err := idx.DeriveMessageBoxID(rc.RootPublicKey())
				must(err)
				box = pk.Bytes()
			}
			vs = append(vs, bacapBoxIDVector{
				Name:             fmt.Sprintf("%s_box_id_after_advance_%d", c.name, k.by),
				WriteCapHex:      hex.EncodeToString(c.blob),
				AdvanceBy:        k.by,
				CtxHex:           hex.EncodeToString(ctx),
				UseContext:       k.useContext,
				ExpectedBoxIDHex: hex.EncodeToString(box),
			})
		}
	}
	return vs
}

func extraEncryptVectors() []bacapEncryptVector {
	var vs []bacapEncryptVector
	for _, c := range extraCaps() {
		cases := []struct {
			name      string
			by        uint64
			plaintext []byte
		}{
			{"short", 0, []byte("hello from " + c.name)},
			{"empty_plaintext", 3, []byte{}},
			{"box_sized", 1, deterministicBytes("bacap-plaintext", c.name, 1530)},
		}
		for _, k := range cases {
			idx := advanced(c.wc.GetMessageBoxIndex(), k.by)
			ctx := []byte(pigeonholeCtx)
			box, ct, sig, err := idx.EncryptForContext(c.wc, ctx, k.plaintext)
			must(err)
			recovered, err := idx.DecryptForContext(box, ctx, ct, sig)
			must(err)
			if string(recovered) != string(k.plaintext) {
				panic("extra encrypt vector " + c.name + "_" + k.name + ": round-trip mismatch")
			}
			vs = append(vs, bacapEncryptVector{
				Name:                 c.name + "_encrypt_" + k.name,
				WriteCapHex:          hex.EncodeToString(c.blob),
				AdvanceBy:            k.by,
				CtxHex:               hex.EncodeToString(ctx),
				PlaintextHex:         hex.EncodeToString(k.plaintext),
				ExpectedBoxIDHex:     hex.EncodeToString(box[:]),
				ExpectedCiphertext:   hex.EncodeToString(ct),
				ExpectedSignatureHex: hex.EncodeToString(sig),
			})
		}
	}
	return vs
}

func extraMutateVectors() []bacapMutateVector {
	var vs []bacapMutateVector
	for _, c := range extraCaps() {
		rc := c.wc.ReadCap()
		for _, by := range []uint64{0, 2} {
			salt := deterministicBytes("bacap-salt", fmt.Sprintf("%s_%d", c.name, by), 32)
			mutated := advanced(c.wc.GetMessageBoxIndex(), by).MutateKDFState(salt)
			pk, err := mutated.BoxIDForContext(rc, []byte(pigeonholeCtx))
			must(err)
			vs = append(vs, bacapMutateVector{
				Name:             fmt.Sprintf("%s_mutate_after_advance_%d", c.name, by),
				WriteCapHex:      hex.EncodeToString(c.blob),
				AdvanceBy:        by,
				SaltHex:          hex.EncodeToString(salt),
				ReadCtxHex:       hex.EncodeToString([]byte(pigeonholeCtx)),
				ExpectedIndexHex: hex.EncodeToString(marshalIndex(mutated)),
				ExpectedBoxIDHex: hex.EncodeToString(pk.Bytes()),
			})
		}
	}
	return vs
}

// allCaps is the original fixed cap followed by the extra ones.
func allCaps() []bacapExtraCap {
	blob := fixedBACAPWriteCapBytes()
	wc, err := bacap.NewWriteCapFromBytes(blob)
	must(err)
	return append([]bacapExtraCap{{"cap_fixed", blob, wc}}, extraCaps()...)
}

// Layout vectors: the byte layouts of WriteCap, ReadCap and
// MessageBoxIndex, and the read cap derived from a write cap.

type bacapLayoutVector struct {
	Name                     string `json:"name"`
	WriteCapHex              string `json:"writecap_hex"`
	ExpectedRootPublicKeyHex string `json:"expected_root_public_key_hex"`
	ExpectedReadCapHex       string `json:"expected_readcap_hex"`
	ExpectedIndexHex         string `json:"expected_index_hex"`
	ExpectedIdx64            uint64 `json:"expected_idx64"`
}

func genBACAPLayout() vectorFile {
	var vs []bacapLayoutVector
	for _, c := range allCaps() {
		rc := c.wc.ReadCap()
		rcBytes, err := rc.MarshalBinary()
		must(err)
		idx := c.wc.GetMessageBoxIndex()
		vs = append(vs, bacapLayoutVector{
			Name:                     c.name,
			WriteCapHex:              hex.EncodeToString(c.blob),
			ExpectedRootPublicKeyHex: hex.EncodeToString(rc.RootPublicKey().Bytes()),
			ExpectedReadCapHex:       hex.EncodeToString(rcBytes),
			ExpectedIndexHex:         hex.EncodeToString(marshalIndex(idx)),
			ExpectedIdx64:            idx.Idx64,
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "bacap_layout",
		Description:   "Byte layouts. A 168-byte WriteCap is the 64-byte ed25519 private key (seed || public key) followed by the 104-byte MessageBoxIndex; a 136-byte ReadCap is the 32-byte root public key followed by the MessageBoxIndex; a MessageBoxIndex is Idx64 (8 bytes, little-endian), then the blinding factor, encryption key and HKDF state (32 bytes each). For each WriteCap: the root public key, the ReadCap derived from it, and its MessageBoxIndex and Idx64. Each blob must also round-trip through its parser.",
		Vectors:       vs,
	}
}

// Tombstone vectors: a box signed over the empty payload. Opening one
// verifies the signature and returns an empty plaintext without decrypting.

type bacapTombstoneVector struct {
	Name                 string `json:"name"`
	WriteCapHex          string `json:"writecap_hex"`
	AdvanceBy            uint64 `json:"advance_by"`
	CtxHex               string `json:"ctx_hex"`
	ExpectedBoxIDHex     string `json:"expected_box_id_hex"`
	ExpectedSignatureHex string `json:"expected_signature_hex"`
}

func genBACAPTombstone() vectorFile {
	var vs []bacapTombstoneVector
	for _, c := range allCaps() {
		for _, by := range advancesFor(c, []uint64{0, 6}, []uint64{0, 6}) {
			idx := advanced(c.wc.GetMessageBoxIndex(), by)
			ctx := []byte(pigeonholeCtx)
			box, sig, err := idx.SignBox(c.wc, ctx, []byte{})
			must(err)
			if pt, err := idx.DecryptForContext(box, ctx, []byte{}, sig); err != nil || len(pt) != 0 {
				panic("tombstone vector " + c.name + ": does not open")
			}
			vs = append(vs, bacapTombstoneVector{
				Name:                 fmt.Sprintf("%s_tombstone_after_advance_%d", c.name, by),
				WriteCapHex:          hex.EncodeToString(c.blob),
				AdvanceBy:            by,
				CtxHex:               hex.EncodeToString(ctx),
				ExpectedBoxIDHex:     hex.EncodeToString(box[:]),
				ExpectedSignatureHex: hex.EncodeToString(sig),
			})
		}
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "bacap_tombstone",
		Description:   "Tombstone vectors. For each vector, the WriteCap's first MessageBoxIndex is advanced by N and the empty payload signed with SignBox under the context. Records the box ID and the signature. Decrypting the box with an empty ciphertext and that signature must succeed and return an empty plaintext.",
		Vectors:       vs,
	}
}

// Binding vectors: whether an index lies on the stream a read cap
// starts, which is the case exactly when stepping the cap's own index
// forward reaches it.

type bacapPositionVector struct {
	Name        string `json:"name"`
	ReadCapHex  string `json:"readcap_hex"`
	IndexHex    string `json:"index_hex"`
	Reachable   bool   `json:"reachable"`
	Description string `json:"description"`
}

func genBACAPPosition() vectorFile {
	var vs []bacapPositionVector
	caps := allCaps()
	for i, c := range caps {
		rc := c.wc.ReadCap()
		rcBytes, err := rc.MarshalBinary()
		must(err)
		start := c.wc.GetMessageBoxIndex()
		add := func(name string, idx *bacap.MessageBoxIndex, reachable bool, why string) {
			vs = append(vs, bacapPositionVector{
				Name:        c.name + "_" + name,
				ReadCapHex:  hex.EncodeToString(rcBytes),
				IndexHex:    hex.EncodeToString(marshalIndex(idx)),
				Reachable:   reachable,
				Description: why,
			})
		}
		far := advancesFor(c, []uint64{37}, []uint64{8})[0]
		add("same_index", start, true, "the cap's own index")
		add("next_index", advanced(start, 1), true, "one step forward")
		add(fmt.Sprintf("advance_%d", far), advanced(start, far), true, "several steps forward")

		other := caps[(i+1)%len(caps)].wc.GetMessageBoxIndex()
		foreign := *other
		foreign.Idx64 = start.Idx64 + 1
		add("foreign_ratchet", &foreign, false, "another stream's ratchet state under this cap's next Idx64")

		add("mutated", advanced(start.MutateKDFState(deterministicBytes("bacap-salt", c.name+"_position", 32)), 1), false,
			"the same Idx64 as one step forward, on the sequence MutateKDFState re-seeds")

		tampered := *advanced(start, 1)
		tampered.HKDFState[0] ^= 0x01
		add("tampered_hkdf_state", &tampered, false, "one step forward with one bit of the HKDF state flipped")

		if c.name != "cap_near_2_64" {
			later := advanced(start, 5)
			laterCap := rc.WithMessageBoxIndex(later)
			laterBytes, err := laterCap.MarshalBinary()
			must(err)
			vs = append(vs, bacapPositionVector{
				Name:        c.name + "_behind_cap",
				ReadCapHex:  hex.EncodeToString(laterBytes),
				IndexHex:    hex.EncodeToString(marshalIndex(start)),
				Reachable:   false,
				Description: "an index five steps behind the cap's own index: the ratchet only moves forward",
			})
		}
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "bacap_position",
		Description:   "Binding of an index to a read cap. An index lies on the cap's stream exactly when advancing the cap's own MessageBoxIndex to the index's Idx64 yields the same 104 bytes. reachable records whether it does; an Idx64 below the cap's is never reachable.",
		Vectors:       vs,
	}
}

// Negative vectors: inputs every implementation must reject. category names
// the failure independently of any implementation's error type.

type bacapNegativeVector struct {
	Name          string  `json:"name"`
	Operation     string  `json:"operation"`
	Category      string  `json:"category"`
	Description   string  `json:"description"`
	BlobHex       string  `json:"blob_hex,omitempty"`
	IndexHex      string  `json:"index_hex,omitempty"`
	AdvanceTo     *uint64 `json:"advance_to,omitempty"`
	WriteCapHex   string  `json:"writecap_hex,omitempty"`
	AdvanceBy     uint64  `json:"advance_by"`
	CtxHex        string  `json:"ctx_hex,omitempty"`
	BoxIDHex      string  `json:"box_id_hex,omitempty"`
	CiphertextHex string  `json:"ciphertext_hex,omitempty"`
	SignatureHex  string  `json:"signature_hex,omitempty"`
}

func offCurvePoint() []byte {
	var b [32]byte
	for i := 0; i < 256; i++ {
		b[0] = byte(i)
		if _, err := new(edwards25519.Point).SetBytes(b[:]); err != nil {
			return b[:]
		}
	}
	panic("no off-curve encoding found")
}

func flipped(b []byte, i int) []byte {
	out := append([]byte{}, b...)
	out[i] ^= 0x01
	return out
}

func genBACAPNegative() vectorFile {
	var vs []bacapNegativeVector
	caps := allCaps()
	ctx := []byte(pigeonholeCtx)

	for _, c := range caps {
		start := c.wc.GetMessageBoxIndex()
		behind := start.Idx64 - 1
		vs = append(vs, bacapNegativeVector{
			Name: c.name + "_rewind", Operation: "advance_index_to", Category: "cannot_rewind",
			Description: "advancing to an Idx64 below the current one",
			IndexHex:    hex.EncodeToString(marshalIndex(start)), AdvanceTo: &behind,
		})
	}

	near := caps[len(caps)-1]
	last := advanced(near.wc.GetMessageBoxIndex(), 8)
	if last.Idx64 != ^uint64(0) {
		panic("near-2^64 cap does not reach 2^64 - 1")
	}
	vs = append(vs, bacapNegativeVector{
		Name: "next_index_at_max", Operation: "next_index", Category: "index_exhausted",
		Description: "the index after Idx64 = 2^64 - 1, which does not exist",
		IndexHex:    hex.EncodeToString(marshalIndex(last)),
	})

	for _, c := range caps[:2] {
		idx := advanced(c.wc.GetMessageBoxIndex(), 2)
		box, ct, sig, err := idx.EncryptForContext(c.wc, ctx, []byte("the original message"))
		must(err)
		base := func(name, op, cat, why string) bacapNegativeVector {
			return bacapNegativeVector{
				Name: c.name + "_" + name, Operation: op, Category: cat, Description: why,
				WriteCapHex: hex.EncodeToString(c.blob), AdvanceBy: 2, CtxHex: hex.EncodeToString(ctx),
				BoxIDHex: hex.EncodeToString(box[:]), CiphertextHex: hex.EncodeToString(ct), SignatureHex: hex.EncodeToString(sig),
			}
		}
		v := base("tampered_ciphertext", "decrypt", "signature_invalid", "one ciphertext bit flipped; the signature over the ciphertext no longer verifies")
		v.CiphertextHex = hex.EncodeToString(flipped(ct, 0))
		vs = append(vs, v)

		v = base("tampered_signature", "decrypt", "signature_invalid", "one signature bit flipped")
		v.SignatureHex = hex.EncodeToString(flipped(sig, 5))
		vs = append(vs, v)

		v = base("wrong_ctx", "decrypt", "decrypt_failed", "a valid box decrypted under another context: the signature verifies, the AEAD does not open")
		v.CtxHex = hex.EncodeToString([]byte("another context"))
		vs = append(vs, v)

		v = base("wrong_index", "decrypt", "decrypt_failed", "a valid box decrypted with the next index's keys: the signature verifies, the AEAD does not open")
		v.AdvanceBy = 3
		vs = append(vs, v)

		v = base("verify_tampered_signature", "verify_box", "signature_invalid", "VerifyBox on a signature with one bit flipped")
		v.SignatureHex = hex.EncodeToString(flipped(sig, 5))
		vs = append(vs, v)

		// A tombstone has no ciphertext to authenticate, so only the box
		// check tells a tombstone for one box from one for another.
		tomb := advanced(c.wc.GetMessageBoxIndex(), 3)
		tbox, tsig, err := tomb.SignBox(c.wc, ctx, []byte{})
		must(err)
		vs = append(vs, bacapNegativeVector{
			Name: c.name + "_open_tombstone_of_another_box", Operation: "open", Category: "box_mismatch",
			Description: "a valid tombstone for the box at advance 3, opened at advance 2: its signature verifies and there is nothing to decrypt, so only comparing the box ID with the one the read cap and index derive rejects it",
			WriteCapHex: hex.EncodeToString(c.blob), AdvanceBy: 2, CtxHex: hex.EncodeToString(ctx),
			BoxIDHex: hex.EncodeToString(tbox[:]), CiphertextHex: "", SignatureHex: hex.EncodeToString(tsig),
		})
	}

	good := caps[1]
	rc := good.wc.ReadCap()
	rcBytes, err := rc.MarshalBinary()
	must(err)
	idxBytes := marshalIndex(good.wc.GetMessageBoxIndex())
	parse := func(name, op, why string, blob []byte) {
		vs = append(vs, bacapNegativeVector{
			Name: name, Operation: op, Category: "malformed", Description: why,
			BlobHex: hex.EncodeToString(blob),
		})
	}
	parse("index_empty", "parse_message_box_index", "a MessageBoxIndex of 0 bytes", []byte{})
	parse("index_short", "parse_message_box_index", "a MessageBoxIndex one byte short", idxBytes[:len(idxBytes)-1])
	parse("index_long", "parse_message_box_index", "a MessageBoxIndex one byte long", append(append([]byte{}, idxBytes...), 0))
	parse("readcap_short", "parse_read_cap", "a ReadCap one byte short", rcBytes[:len(rcBytes)-1])
	parse("readcap_long", "parse_read_cap", "a ReadCap one byte long", append(append([]byte{}, rcBytes...), 0))
	offRC := append(append([]byte{}, offCurvePoint()...), rcBytes[32:]...)
	parse("readcap_off_curve_root_key", "parse_read_cap", "a ReadCap whose root public key is not a curve point", offRC)
	parse("writecap_short", "parse_write_cap", "a WriteCap one byte short", good.blob[:len(good.blob)-1])
	offWC := append(append(append([]byte{}, good.blob[:32]...), offCurvePoint()...), good.blob[64:]...)
	parse("writecap_off_curve_public_half", "parse_write_cap", "a WriteCap whose stored public key is not a curve point", offWC)
	otherPub := caps[2].blob[32:64]
	mismatch := append(append(append([]byte{}, good.blob[:32]...), otherPub...), good.blob[64:]...)
	parse("writecap_public_half_mismatch", "parse_write_cap", "a WriteCap whose stored public key is a valid point but not the one its seed derives", mismatch)

	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "bacap_negative",
		Description:   "Inputs every implementation must reject, by operation. advance_index_to and next_index take index_hex (and advance_to). decrypt advances the WriteCap's first index by advance_by and decrypts box_id_hex, ciphertext_hex and signature_hex under ctx_hex. open does the same after first comparing box_id_hex with the box ID the derived read cap and index give under ctx_hex. verify_box checks signature_hex over ciphertext_hex under box_id_hex. The parse_* operations parse blob_hex. category names the failure independently of any implementation's error type: cannot_rewind, index_exhausted, signature_invalid, decrypt_failed, box_mismatch, malformed.",
		Vectors:       vs,
	}
}

// genBundle gathers the primitive and BACAP sections a BACAP implementation
// needs into one file, bottom-up. It reads them back from the files under
// root, so it holds exactly what they hold. primitives/sha512.json is
// curated by hand rather than generated, and must already be there.
func genBundle(root string, rels []string) any {
	type section struct {
		Primitive   string          `json:"primitive"`
		Description string          `json:"description"`
		Vectors     json.RawMessage `json:"vectors"`
	}
	out := make([]section, 0, len(rels))
	for _, rel := range rels {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		must(err)
		var s section
		must(json.Unmarshal(raw, &s))
		out = append(out, s)
	}
	return struct {
		FormatVersion int       `json:"format_version"`
		Generator     string    `json:"generator"`
		Bundle        string    `json:"bundle"`
		Description   string    `json:"description"`
		Sections      []section `json:"sections"`
	}{
		formatVersion, generatorName, "bacap",
		"Every test vector needed to validate a BACAP implementation, from primitives upward, gathered into one file for consumers that vendor rather than symlink. Sections are ordered bottom-up so the first failing section localises the defect. Contents are identical to the correspondingly named files under testvectors/primitives/ and testvectors/bacap/; this file is generated from the same functions and cannot drift from them.",
		out,
	}
}
