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

	"github.com/katzenpost/hpqc/bacap"
)

// ===== BACAP vectors =====
//
// Every BACAP vector file is generated from testvectors/bacap/inputs.json,
// which describes each case by its inputs only. The Python port
// (py/hpqc/bacap/gen_vectors.py) and CryptWalker's Lean implementation
// generate the same files from the same inputs; see testvectors/README.md.

// bacapInputs is inputs.json.
type bacapInputs struct {
	Files           map[string]struct{ Primitive, Description string } `json:"files"`
	Caps            []capSpec                                          `json:"caps"`
	MessageBoxIndex []struct {
		Name      string `json:"name"`
		Cap       string `json:"cap"`
		AdvanceBy uint64 `json:"advance_by"`
	} `json:"message_box_index"`
	BoxID []struct {
		Name       string     `json:"name"`
		Cap        string     `json:"cap"`
		AdvanceBy  uint64     `json:"advance_by"`
		Ctx        *bytesSpec `json:"ctx"`
		UseContext bool       `json:"use_context"`
	} `json:"box_id"`
	Encrypt []struct {
		Name      string    `json:"name"`
		Cap       string    `json:"cap"`
		AdvanceBy uint64    `json:"advance_by"`
		Ctx       bytesSpec `json:"ctx"`
		Plaintext bytesSpec `json:"plaintext"`
	} `json:"encrypt"`
	MutateKDFState []struct {
		Name      string    `json:"name"`
		Cap       string    `json:"cap"`
		AdvanceBy uint64    `json:"advance_by"`
		Salt      bytesSpec `json:"salt"`
		ReadCtx   bytesSpec `json:"read_ctx"`
	} `json:"mutate_kdf_state"`
	Layout []struct {
		Name string `json:"name"`
		Cap  string `json:"cap"`
	} `json:"layout"`
	Tombstone []struct {
		Name      string    `json:"name"`
		Cap       string    `json:"cap"`
		AdvanceBy uint64    `json:"advance_by"`
		Ctx       bytesSpec `json:"ctx"`
	} `json:"tombstone"`
	Position []positionSpec `json:"position"`
	Negative []negativeSpec `json:"negative"`
}

// bytesSpec is one of: {"hex": ...}, {"utf8": ...}, {"repeat": {"byte", "count"}},
// or {"derive": {"label", "name", "length"}}, which is deterministicBytes.
type bytesSpec struct {
	Hex    *string `json:"hex"`
	UTF8   *string `json:"utf8"`
	Repeat *struct {
		Byte  byte `json:"byte"`
		Count int  `json:"count"`
	} `json:"repeat"`
	Derive *struct {
		Label  string `json:"label"`
		Name   string `json:"name"`
		Length int    `json:"length"`
	} `json:"derive"`
}

func (b *bytesSpec) bytes() []byte {
	switch {
	case b == nil:
		return nil
	case b.Hex != nil:
		return mustHex(*b.Hex)
	case b.UTF8 != nil:
		return []byte(*b.UTF8)
	case b.Repeat != nil:
		return bytesPattern(b.Repeat.Byte, b.Repeat.Count)
	case b.Derive != nil:
		return deterministicBytes(b.Derive.Label, b.Derive.Name, b.Derive.Length)
	}
	panic("empty bytes spec")
}

// capSpec is a write cap: either an explicit seed and index, or a seed, an
// HKDF state and a starting Idx64 from which the first index is one step on,
// as NewMessageBoxIndex does. start_idx64 is a number or {"irwin_hall": bytes},
// the sum NewMessageBoxIndex draws from 16 bytes.
type capSpec struct {
	Name       string          `json:"name"`
	Seed       bytesSpec       `json:"seed"`
	Index      *bytesSpec      `json:"index"`
	HKDFState  *bytesSpec      `json:"hkdf_state"`
	StartIdx64 json.RawMessage `json:"start_idx64"`
}

type bacapCap struct {
	blob []byte
	wc   *bacap.WriteCap
}

func (c capSpec) build() bacapCap {
	seed := c.Seed.bytes()
	priv := stded25519.NewKeyFromSeed(seed)
	var first *bacap.MessageBoxIndex
	if c.Index != nil {
		idx, err := bacap.NewEmptyMessageBoxIndexFromBytes(c.Index.bytes())
		must(err)
		first = idx
	} else {
		var start uint64
		var ih struct {
			IrwinHall bytesSpec `json:"irwin_hall"`
		}
		if err := json.Unmarshal(c.StartIdx64, &start); err != nil {
			must(json.Unmarshal(c.StartIdx64, &ih))
			b := ih.IrwinHall.bytes()
			b[7] &= 0x3f
			b[15] &= 0x3f
			start = binary.LittleEndian.Uint64(b[:8]) + binary.LittleEndian.Uint64(b[8:16])
		}
		seedIdx := &bacap.MessageBoxIndex{Idx64: start}
		copy(seedIdx.HKDFState[:], c.HKDFState.bytes())
		var err error
		first, err = seedIdx.NextIndex()
		must(err)
	}
	blob := append(append([]byte{}, priv...), marshalIndex(first)...)
	wc, err := bacap.NewWriteCapFromBytes(blob)
	must(err)
	return bacapCap{blob, wc}
}

type positionSpec struct {
	Name            string    `json:"name"`
	Cap             string    `json:"cap"`
	Kind            string    `json:"kind"`
	Description     string    `json:"description"`
	AdvanceBy       uint64    `json:"advance_by"`
	OtherCap        string    `json:"other_cap"`
	Idx64Offset     uint64    `json:"idx64_offset"`
	Salt            bytesSpec `json:"salt"`
	Field           string    `json:"field"`
	Byte            int       `json:"byte"`
	Xor             byte      `json:"xor"`
	RebaseAdvanceBy uint64    `json:"rebase_advance_by"`
}

type sourceSpec struct {
	Kind      string    `json:"kind"`
	AdvanceBy uint64    `json:"advance_by"`
	Ctx       bytesSpec `json:"ctx"`
	Plaintext bytesSpec `json:"plaintext"`
}

type negativeSpec struct {
	Name           string      `json:"name"`
	Operation      string      `json:"operation"`
	Category       string      `json:"category"`
	Description    string      `json:"description"`
	Cap            string      `json:"cap"`
	RewindBy       uint64      `json:"rewind_by"`
	IndexAdvanceBy uint64      `json:"index_advance_by"`
	Source         *sourceSpec `json:"source"`
	AdvanceBy      uint64      `json:"advance_by"`
	Ctx            *bytesSpec  `json:"ctx"`
	Flip           *struct {
		Field string `json:"field"`
		Byte  int    `json:"byte"`
	} `json:"flip"`
	Blob *struct {
		From string `json:"from"`
		Cap  string `json:"cap"`
		Edit struct {
			Kind        string     `json:"kind"`
			Count       int        `json:"count"`
			Offset      int        `json:"offset"`
			Bytes       *bytesSpec `json:"bytes"`
			PublicKeyOf string     `json:"public_key_of"`
		} `json:"edit"`
	} `json:"blob"`
}

// ----- output schemas -----

type bacapAdvanceVector struct {
	Name             string `json:"name"`
	InitialIndexHex  string `json:"initial_index_hex"`
	AdvanceTo        uint64 `json:"advance_to"`
	ExpectedIndexHex string `json:"expected_index_hex"`
}

type bacapBoxIDVector struct {
	Name             string `json:"name"`
	WriteCapHex      string `json:"writecap_hex"`
	AdvanceBy        uint64 `json:"advance_by"`
	CtxHex           string `json:"ctx_hex"`
	UseContext       bool   `json:"use_context"`
	ExpectedBoxIDHex string `json:"expected_box_id_hex"`
}

type bacapEncryptVector struct {
	Name                 string `json:"name"`
	WriteCapHex          string `json:"writecap_hex"`
	AdvanceBy            uint64 `json:"advance_by"`
	CtxHex               string `json:"ctx_hex"`
	PlaintextHex         string `json:"plaintext_hex"`
	ExpectedBoxIDHex     string `json:"expected_box_id_hex"`
	ExpectedCiphertext   string `json:"expected_ciphertext_hex"`
	ExpectedSignatureHex string `json:"expected_signature_hex"`
}

type bacapMutateVector struct {
	Name             string `json:"name"`
	WriteCapHex      string `json:"writecap_hex"`
	AdvanceBy        uint64 `json:"advance_by"`
	SaltHex          string `json:"salt_hex"`
	ReadCtxHex       string `json:"read_ctx_hex"`
	ExpectedIndexHex string `json:"expected_mutated_index_hex"`
	ExpectedBoxIDHex string `json:"expected_mutated_box_id_hex"`
}

type bacapLayoutVector struct {
	Name                     string `json:"name"`
	WriteCapHex              string `json:"writecap_hex"`
	ExpectedRootPublicKeyHex string `json:"expected_root_public_key_hex"`
	ExpectedReadCapHex       string `json:"expected_readcap_hex"`
	ExpectedIndexHex         string `json:"expected_index_hex"`
	ExpectedIdx64            uint64 `json:"expected_idx64"`
}

type bacapTombstoneVector struct {
	Name                 string `json:"name"`
	WriteCapHex          string `json:"writecap_hex"`
	AdvanceBy            uint64 `json:"advance_by"`
	CtxHex               string `json:"ctx_hex"`
	ExpectedBoxIDHex     string `json:"expected_box_id_hex"`
	ExpectedSignatureHex string `json:"expected_signature_hex"`
}

type bacapPositionVector struct {
	Name        string `json:"name"`
	ReadCapHex  string `json:"readcap_hex"`
	IndexHex    string `json:"index_hex"`
	Reachable   bool   `json:"reachable"`
	Description string `json:"description"`
}

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

// ----- generation -----

func loadBACAPInputs(path string) *bacapInputs {
	raw, err := os.ReadFile(path)
	must(err)
	in := new(bacapInputs)
	must(json.Unmarshal(raw, in))
	return in
}

func marshalIndex(idx *bacap.MessageBoxIndex) []byte {
	b, err := idx.MarshalBinary()
	must(err)
	return b
}

func advanced(idx *bacap.MessageBoxIndex, by uint64) *bacap.MessageBoxIndex {
	if by == 0 {
		return idx
	}
	out, err := idx.AdvanceIndexTo(idx.Idx64 + by)
	must(err)
	return out
}

// reachable reports whether stepping rc's own index forward reaches idx.
func reachable(rc *bacap.ReadCap, idx *bacap.MessageBoxIndex) bool {
	start := rc.GetMessageBoxIndex()
	if idx.Idx64 < start.Idx64 {
		return false
	}
	return string(marshalIndex(advanced(start, idx.Idx64-start.Idx64))) == string(marshalIndex(idx))
}

func flipped(b []byte, i int) []byte {
	out := append([]byte{}, b...)
	out[i] ^= 0x01
	return out
}

func h(b []byte) string { return hex.EncodeToString(b) }

// genBACAPFiles returns every BACAP vector file, keyed by its name in inputs.json.
func genBACAPFiles(in *bacapInputs) map[string]vectorFile {
	caps := make(map[string]bacapCap, len(in.Caps))
	for _, c := range in.Caps {
		caps[c.Name] = c.build()
	}
	cap := func(name string) bacapCap {
		c, ok := caps[name]
		if !ok {
			panic("unknown cap " + name)
		}
		return c
	}
	file := func(name string, vectors any) vectorFile {
		f := in.Files[name]
		return vectorFile{FormatVersion: formatVersion, Generator: generatorName,
			Primitive: f.Primitive, Description: f.Description, Vectors: vectors}
	}
	out := map[string]vectorFile{}

	var mbi []bacapAdvanceVector
	for _, v := range in.MessageBoxIndex {
		idx := cap(v.Cap).wc.GetMessageBoxIndex()
		mbi = append(mbi, bacapAdvanceVector{v.Name, h(marshalIndex(idx)), idx.Idx64 + v.AdvanceBy,
			h(marshalIndex(advanced(idx, v.AdvanceBy)))})
	}
	out["message_box_index"] = file("message_box_index", mbi)

	var box []bacapBoxIDVector
	for _, v := range in.BoxID {
		c := cap(v.Cap)
		idx := advanced(c.wc.GetMessageBoxIndex(), v.AdvanceBy)
		ctx := v.Ctx.bytes()
		var pk interface{ Bytes() []byte }
		var err error
		if v.UseContext {
			pk, err = idx.BoxIDForContext(c.wc.ReadCap(), ctx)
		} else {
			pk, err = idx.DeriveMessageBoxID(c.wc.ReadCap().RootPublicKey())
		}
		must(err)
		box = append(box, bacapBoxIDVector{v.Name, h(c.blob), v.AdvanceBy, h(ctx), v.UseContext, h(pk.Bytes())})
	}
	out["box_id"] = file("box_id", box)

	var enc []bacapEncryptVector
	for _, v := range in.Encrypt {
		c := cap(v.Cap)
		idx := advanced(c.wc.GetMessageBoxIndex(), v.AdvanceBy)
		ctx, pt := v.Ctx.bytes(), v.Plaintext.bytes()
		b, ct, sig, err := idx.EncryptForContext(c.wc, ctx, pt)
		must(err)
		got, err := idx.DecryptForContext(b, ctx, ct, sig)
		must(err)
		if string(got) != string(pt) {
			panic("encrypt vector " + v.Name + ": round trip mismatch")
		}
		enc = append(enc, bacapEncryptVector{v.Name, h(c.blob), v.AdvanceBy, h(ctx), h(pt), h(b[:]), h(ct), h(sig)})
	}
	out["encrypt"] = file("encrypt", enc)

	var mut []bacapMutateVector
	for _, v := range in.MutateKDFState {
		c := cap(v.Cap)
		salt, rctx := v.Salt.bytes(), v.ReadCtx.bytes()
		m := advanced(c.wc.GetMessageBoxIndex(), v.AdvanceBy).MutateKDFState(salt)
		pk, err := m.BoxIDForContext(c.wc.ReadCap(), rctx)
		must(err)
		mut = append(mut, bacapMutateVector{v.Name, h(c.blob), v.AdvanceBy, h(salt), h(rctx), h(marshalIndex(m)), h(pk.Bytes())})
	}
	out["mutate_kdf_state"] = file("mutate_kdf_state", mut)

	var lay []bacapLayoutVector
	for _, v := range in.Layout {
		c := cap(v.Cap)
		rc := c.wc.ReadCap()
		rcb, err := rc.MarshalBinary()
		must(err)
		idx := c.wc.GetMessageBoxIndex()
		lay = append(lay, bacapLayoutVector{v.Name, h(c.blob), h(rc.RootPublicKey().Bytes()), h(rcb), h(marshalIndex(idx)), idx.Idx64})
	}
	out["layout"] = file("layout", lay)

	var tomb []bacapTombstoneVector
	for _, v := range in.Tombstone {
		c := cap(v.Cap)
		idx := advanced(c.wc.GetMessageBoxIndex(), v.AdvanceBy)
		ctx := v.Ctx.bytes()
		b, sig, err := idx.SignBox(c.wc, ctx, []byte{})
		must(err)
		if pt, err := idx.DecryptForContext(b, ctx, []byte{}, sig); err != nil || len(pt) != 0 {
			panic("tombstone vector " + v.Name + ": does not open")
		}
		tomb = append(tomb, bacapTombstoneVector{v.Name, h(c.blob), v.AdvanceBy, h(ctx), h(b[:]), h(sig)})
	}
	out["tombstone"] = file("tombstone", tomb)

	var pos []bacapPositionVector
	for _, v := range in.Position {
		c := cap(v.Cap)
		rc := c.wc.ReadCap()
		start := c.wc.GetMessageBoxIndex()
		var idx *bacap.MessageBoxIndex
		switch v.Kind {
		case "advance":
			idx = advanced(start, v.AdvanceBy)
		case "foreign":
			f := *cap(v.OtherCap).wc.GetMessageBoxIndex()
			f.Idx64 = start.Idx64 + v.Idx64Offset
			idx = &f
		case "mutated":
			idx = advanced(start.MutateKDFState(v.Salt.bytes()), v.AdvanceBy)
		case "tampered":
			t := *advanced(start, v.AdvanceBy)
			if v.Field != "hkdf_state" {
				panic("tampered: unknown field " + v.Field)
			}
			t.HKDFState[v.Byte] ^= v.Xor
			idx = &t
		case "behind":
			rc = rc.WithMessageBoxIndex(advanced(start, v.RebaseAdvanceBy))
			idx = start
		default:
			panic("unknown position kind " + v.Kind)
		}
		rcb, err := rc.MarshalBinary()
		must(err)
		pos = append(pos, bacapPositionVector{v.Name, h(rcb), h(marshalIndex(idx)), reachable(rc, idx), v.Description})
	}
	out["position"] = file("position", pos)

	var neg []bacapNegativeVector
	for _, v := range in.Negative {
		n := bacapNegativeVector{Name: v.Name, Operation: v.Operation, Category: v.Category, Description: v.Description}
		switch v.Operation {
		case "advance_index_to":
			idx := cap(v.Cap).wc.GetMessageBoxIndex()
			to := idx.Idx64 - v.RewindBy
			n.IndexHex, n.AdvanceTo = h(marshalIndex(idx)), &to
		case "next_index":
			n.IndexHex = h(marshalIndex(advanced(cap(v.Cap).wc.GetMessageBoxIndex(), v.IndexAdvanceBy)))
		case "decrypt", "verify_box", "open":
			c := cap(v.Cap)
			src := advanced(c.wc.GetMessageBoxIndex(), v.Source.AdvanceBy)
			var b [bacap.BoxIDSize]byte
			var ct, sig []byte
			var err error
			switch v.Source.Kind {
			case "encrypt":
				b, ct, sig, err = src.EncryptForContext(c.wc, v.Source.Ctx.bytes(), v.Source.Plaintext.bytes())
			case "tombstone":
				b, sig, err = src.SignBox(c.wc, v.Source.Ctx.bytes(), []byte{})
			default:
				panic("unknown source kind " + v.Source.Kind)
			}
			must(err)
			if v.Flip != nil {
				switch v.Flip.Field {
				case "ciphertext":
					ct = flipped(ct, v.Flip.Byte)
				case "signature":
					sig = flipped(sig, v.Flip.Byte)
				default:
					panic("unknown flip field " + v.Flip.Field)
				}
			}
			n.WriteCapHex, n.AdvanceBy, n.CtxHex = h(c.blob), v.AdvanceBy, h(v.Ctx.bytes())
			n.BoxIDHex, n.CiphertextHex, n.SignatureHex = h(b[:]), h(ct), h(sig)
		case "parse_message_box_index", "parse_read_cap", "parse_write_cap":
			n.BlobHex = h(editBlob(v, cap))
		default:
			panic("unknown operation " + v.Operation)
		}
		neg = append(neg, n)
	}
	out["negative"] = file("negative", neg)
	return out
}

func editBlob(v negativeSpec, cap func(string) bacapCap) []byte {
	c := cap(v.Blob.Cap)
	var blob []byte
	switch v.Blob.From {
	case "index":
		blob = marshalIndex(c.wc.GetMessageBoxIndex())
	case "readcap":
		b, err := c.wc.ReadCap().MarshalBinary()
		must(err)
		blob = b
	case "writecap":
		blob = append([]byte{}, c.blob...)
	default:
		panic("unknown blob source " + v.Blob.From)
	}
	e := v.Blob.Edit
	switch e.Kind {
	case "empty":
		return []byte{}
	case "truncate":
		return blob[:len(blob)-e.Count]
	case "append_zero":
		return append(blob, make([]byte, e.Count)...)
	case "replace":
		var with []byte
		if e.PublicKeyOf != "" {
			with = cap(e.PublicKeyOf).blob[32:64]
		} else {
			with = e.Bytes.bytes()
		}
		copy(blob[e.Offset:], with)
		return blob
	}
	panic(fmt.Sprintf("unknown blob edit %q", e.Kind))
}

// bacapFileOrder is the order the vector files are written and bundled in.
var bacapFileOrder = []string{
	"message_box_index", "box_id", "encrypt", "mutate_kdf_state",
	"layout", "tombstone", "position", "negative",
}

// writeBACAPFiles writes every BACAP vector file under root, then bundle.json
// from them and the primitive files under root.
func writeBACAPFiles(root string, in *bacapInputs) {
	files := genBACAPFiles(in)
	bundle := []string{
		"primitives/sha512.json", "primitives/sha512_256.json", "primitives/blake2b_512.json",
		"primitives/hkdf_blake2b.json", "primitives/aes_gcm_siv.json", "primitives/ed25519.json",
		"primitives/blinded_ed25519.json",
	}
	for _, name := range bacapFileOrder {
		rel := "bacap/" + name + ".json"
		writeFile(root, rel, files[name])
		bundle = append(bundle, rel)
	}
	writeJSON(root, "bacap/bundle.json", genBundle(root, bundle))
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
