// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// generate emits the JSON test-vector files under testvectors/ from the
// canonical Go primitives. Both the Go and Python test suites consume
// the resulting files via per-file symlinks: Go packages have a testdata/
// directory and Python tests have a vectors/ directory, each containing
// one symlink per file the package depends on.
//
// Usage:
//
//	go run ./testvectors/cmd/generate          # writes to ./testvectors/
//	go run ./testvectors/cmd/generate -out X   # writes to X/
package main

import (
	stded25519 "crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"os"
	"path/filepath"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"github.com/agl/gcmsiv"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/sign/ed25519"
)

const (
	formatVersion = 1
	generatorName = "github.com/katzenpost/hpqc/testvectors/cmd/generate"
)

type vectorFile struct {
	FormatVersion int    `json:"format_version"`
	Generator     string `json:"generator"`
	Primitive     string `json:"primitive"`
	Description   string `json:"description"`
	Vectors       any    `json:"vectors"`
}

func main() {
	out := flag.String("out", "testvectors", "output directory (must contain primitives/ and bacap/)")
	flag.Parse()

	must(os.MkdirAll(filepath.Join(*out, "primitives"), 0o755))
	must(os.MkdirAll(filepath.Join(*out, "bacap"), 0o755))

	writeFile(*out, "primitives/sha512_256.json", genSHA512_256())
	writeFile(*out, "primitives/blake2b_512.json", genBLAKE2b512())
	writeFile(*out, "primitives/hkdf_blake2b.json", genHKDFBlake2b())
	writeFile(*out, "primitives/aes_gcm_siv.json", genAESGCMSIV())
	writeFile(*out, "primitives/blinded_ed25519.json", genBlindedEd25519())

	writeFile(*out, "bacap/message_box_index.json", genBACAPMessageBoxIndex())
	writeFile(*out, "bacap/box_id.json", genBACAPBoxID())
	writeFile(*out, "bacap/encrypt.json", genBACAPEncrypt())

	fmt.Println("ok")
}

// SHA-512/256 (FIPS 180-4 §6.7). Distinct from truncated SHA-512: it has its
// own initial hash values. Used by BACAP indirectly via blinded25519, where
// blinding factors are first hashed with sha512_256 before scalar reduction.

type sha512_256Vector struct {
	Name      string `json:"name"`
	InputHex  string `json:"input_hex"`
	OutputHex string `json:"output_hex"`
}

func genSHA512_256() vectorFile {
	cases := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"abc", []byte("abc")},
		{"32_zero_bytes", make([]byte, 32)},
		{"hpqc_bacap_factor_example_1", []byte("BACAP blinding factor example one")},
		{"hpqc_bacap_factor_example_2", []byte("BACAP blinding factor example two")},
	}
	vs := make([]sha512_256Vector, 0, len(cases))
	for _, c := range cases {
		sum := sha512.Sum512_256(c.input)
		vs = append(vs, sha512_256Vector{
			Name:      c.name,
			InputHex:  hex.EncodeToString(c.input),
			OutputHex: hex.EncodeToString(sum[:]),
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "sha512_256",
		Description:   "SHA-512/256 (FIPS 180-4 §6.7). 32-byte output. Note: NOT the same as SHA-512 truncated to 256 bits; it has a distinct initial hash value.",
		Vectors:       vs,
	}
}

// BLAKE2b-512. Used by BACAP as the underlying hash for HKDF in
// MessageBoxIndex.AdvanceIndexTo and the deriveK/E helpers.

type blake2bVector struct {
	Name      string `json:"name"`
	InputHex  string `json:"input_hex"`
	OutputHex string `json:"output_hex"`
}

func genBLAKE2b512() vectorFile {
	cases := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"abc", []byte("abc")},
		{"32_zero_bytes", make([]byte, 32)},
		{"hpqc_bacap_hkdf_state_example", []byte("HKDF state example for BACAP")},
	}
	vs := make([]blake2bVector, 0, len(cases))
	for _, c := range cases {
		h, err := blake2b.New512(nil)
		must(err)
		h.Write(c.input)
		out := h.Sum(nil)
		vs = append(vs, blake2bVector{
			Name:      c.name,
			InputHex:  hex.EncodeToString(c.input),
			OutputHex: hex.EncodeToString(out),
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "blake2b_512",
		Description:   "BLAKE2b-512 (RFC 7693), unkeyed, 64-byte output. Used by BACAP as the underlying hash for HKDF.",
		Vectors:       vs,
	}
}

// HKDF using BLAKE2b-512 as the hash. The Go signature is
// hkdf.New(hash, secret, salt, info). BACAP calls it with ctx as salt and
// either an empty info or the little-endian 8-byte index as info; this catches
// any Python port that swaps salt and info.

type hkdfBlake2bVector struct {
	Name      string `json:"name"`
	SecretHex string `json:"secret_hex"`
	SaltHex   string `json:"salt_hex"`
	InfoHex   string `json:"info_hex"`
	Length    int    `json:"length"`
	OkmHex    string `json:"okm_hex"`
}

func genHKDFBlake2b() vectorFile {
	hashFn := func() hash.Hash { h, _ := blake2b.New512(nil); return h }
	cases := []struct {
		name   string
		secret []byte
		salt   []byte
		info   []byte
		length int
	}{
		{
			name:   "empty_salt_empty_info_32",
			secret: bytesPattern(0x01, 32),
			salt:   nil,
			info:   nil,
			length: 32,
		},
		{
			name:   "ctx_as_salt_empty_info_32",
			secret: bytesPattern(0x02, 32),
			salt:   []byte("BACAP context example"),
			info:   nil,
			length: 32,
		},
		{
			name:   "ctx_as_salt_index_as_info_96",
			secret: bytesPattern(0x03, 32),
			salt:   nil,
			info:   []byte{0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			length: 96,
		},
		{
			name:   "long_okm_to_catch_streaming_bugs",
			secret: bytesPattern(0x04, 32),
			salt:   []byte("salt-X"),
			info:   []byte("info-Y"),
			length: 200,
		},
	}
	vs := make([]hkdfBlake2bVector, 0, len(cases))
	for _, c := range cases {
		r := hkdf.New(hashFn, c.secret, c.salt, c.info)
		out := make([]byte, c.length)
		_, err := r.Read(out)
		must(err)
		vs = append(vs, hkdfBlake2bVector{
			Name:      c.name,
			SecretHex: hex.EncodeToString(c.secret),
			SaltHex:   hex.EncodeToString(c.salt),
			InfoHex:   hex.EncodeToString(c.info),
			Length:    c.length,
			OkmHex:    hex.EncodeToString(out),
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "hkdf_blake2b",
		Description:   "HKDF-BLAKE2b-512 (RFC 5869 with BLAKE2b-512 as the hash). Go's signature is hkdf.New(hash, secret, salt, info); BACAP passes ctx as salt and the index as info, so the parameter ordering is the most common porting hazard.",
		Vectors:       vs,
	}
}

// AES-256-GCM-SIV per RFC 8452. Used by BACAP for box payload encryption.
// BACAP passes box_id[:12] as the nonce and the full 32-byte box_id as the
// AAD; the BACAP-shaped vectors below mirror that. (Earlier the nonce was
// box_id[:16], which agl/gcmsiv silently accepted but no standards-
// conformant AES-GCM-SIV implementation does. See issue #96.)

type aesGCMSIVVector struct {
	Name          string `json:"name"`
	KeyHex        string `json:"key_hex"`
	NonceHex      string `json:"nonce_hex"`
	AADHex        string `json:"aad_hex"`
	PlaintextHex  string `json:"plaintext_hex"`
	CiphertextHex string `json:"ciphertext_hex"`
}

func genAESGCMSIV() vectorFile {
	cases := []struct {
		name      string
		key       []byte
		nonce     []byte
		aad       []byte
		plaintext []byte
	}{
		{
			name:      "rfc8452_appendix_c_2_example_1",
			key:       mustHex("0100000000000000000000000000000000000000000000000000000000000000"),
			nonce:     mustHex("030000000000000000000000"),
			aad:       []byte{},
			plaintext: []byte{},
		},
		{
			name:      "bacap_shape_box_id_as_nonce_and_aad",
			key:       bytesPattern(0xaa, 32),
			nonce:     bytesPattern(0xbb, 12),
			aad:       bytesPattern(0xbb, 32),
			plaintext: []byte("Hello, BACAP."),
		},
		{
			name:      "bacap_shape_long_plaintext",
			key:       bytesPattern(0xcc, 32),
			nonce:     bytesPattern(0xdd, 12),
			aad:       bytesPattern(0xdd, 32),
			plaintext: bytesPattern(0xee, 512),
		},
	}
	vs := make([]aesGCMSIVVector, 0, len(cases))
	for _, c := range cases {
		siv, err := gcmsiv.NewGCMSIV(c.key)
		must(err)
		ct := siv.Seal(nil, c.nonce, c.plaintext, c.aad)
		vs = append(vs, aesGCMSIVVector{
			Name:          c.name,
			KeyHex:        hex.EncodeToString(c.key),
			NonceHex:      hex.EncodeToString(c.nonce),
			AADHex:        hex.EncodeToString(c.aad),
			PlaintextHex:  hex.EncodeToString(c.plaintext),
			CiphertextHex: hex.EncodeToString(ct),
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "aes_gcm_siv",
		Description:   "AES-256-GCM-SIV (RFC 8452). The vectors include both an RFC reference and BACAP-shaped cases where nonce = box_id[:16] and AAD = box_id[:32].",
		Vectors:       vs,
	}
}

// Blinded Ed25519 per hpqc/sign/ed25519/blinded25519.go.
//
// Each vector is (private_key, message, ordered list of blind factors) →
// (blinded_pubkey, signature). The factors are applied in order so a vector
// with N factors records the cumulative result of N successive blindings,
// covering both the single-blinding and the chained-blinding cases under
// one schema.

type blindedEd25519Vector struct {
	Name              string   `json:"name"`
	Provenance        string   `json:"provenance"`         // where the inputs came from
	PrivateKeyHex     string   `json:"private_key_hex"`    // 64-byte Ed25519 private key (seed || pub)
	MessageHex        string   `json:"message_hex"`        // message to sign
	BlindFactorsHex   []string `json:"blind_factors_hex"`  // one or more 32-byte factors, applied in order
	BlindedPubKeyHex  string   `json:"blinded_pubkey_hex"` // 32-byte blinded public key after all factors applied
	BlindedSigHex     string   `json:"blinded_signature_hex"` // 64-byte signature under the blinded private key
}

const (
	provenanceHpqcGo = "Originally hardcoded in sign/ed25519/blinded25519_test.go::TestBlindedSignatureVectors in the katzenpost/hpqc Go implementation."
	provenanceLeif   = "Originally from Leif Ryge's misc/kat.csv in the python-kat branch, merged into add_python_bacap via commit b02c707."
)

func genBlindedEd25519() vectorFile {
	vs := []blindedEd25519Vector{}

	// Three vectors lifted from blinded25519_test.go's
	// TestBlindedSignatureVectors. Single-factor, smoke-test triplet.
	hpqcCases := []struct {
		name       string
		privateKey string
		factor     string
		message    string
	}{
		{
			name:       "hpqc_vector_1_seed_12345",
			privateKey: "1ae969564b34a33ecd1af05fe6923d6de71870997d38ef60155c325957214c425d8ca057866bdee02b63464f587aa75fdad4694c5c05db72323f3928722286cf",
			factor:     "59d74b863e2fba93aeceb05d2fdcde0c9688d21d95aa7bedefc7f31b35731a3d",
			message:    "297611a6b583a5c30587d4e530c948f013e96d5a4e653f0791899d6270c6f3c0",
		},
		{
			name:       "hpqc_vector_2_seed_0",
			privateKey: "0194fdc2fa2ffcc041d3ff12045b73c86e4ff95ff662a5eee82abdf44a2d0b7597f3bd871315281e8b83edc7a9fd0541066154449070ccdb3cdd42cf69ccde88",
			factor:     "fb180daf48a79ee0b10d394651850fd4a178892ee285ece1511455780875d64e",
			message:    "e2d3d0d0de6bf8f9b44ce85ff044c6b1f83b8e883bbf857aab99c5b252c7429c",
		},
		{
			name:       "hpqc_vector_3_seed_max_int64",
			privateKey: "52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c6496f1581709bb7b1ef030d210db18e3b0ba1c776fba65d8cdaad05415142d189f8",
			factor:     "81855ad8681d0d86d1e91e00167939cb6694d2c422acd208a0072939487f6999",
			message:    "eb9d18a44784045d87f3c67cf22746e995af5a25367951baa2ff6cd471c483f1",
		},
	}
	for _, c := range hpqcCases {
		vs = append(vs, computeBlindedEd25519Vector(c.name, provenanceHpqcGo,
			mustHex(c.privateKey), mustHex(c.message), [][]byte{mustHex(c.factor)}))
	}

	// Leif's KAT chain from misc/kat.csv. The seed is a 32-byte ASCII string;
	// from it we derive the standard Ed25519 64-byte private key and then
	// apply three successive blinding factors. We unroll the chain into three
	// vectors so that each cumulative step (one, two, three factors) is its
	// own line in the consolidated set.
	leifSeed := []byte("seed0000000000000000000000000000")
	leifMessage := []byte("Message One")
	leifFactors := [][]byte{
		[]byte("factor1_________________________"),
		[]byte("factor2_________________________"),
		[]byte("factor3_________________________"),
	}
	if len(leifSeed) != stded25519.SeedSize {
		panic("leif seed wrong length")
	}
	leifPriv := stded25519.NewKeyFromSeed(leifSeed)
	for i := range leifFactors {
		factors := leifFactors[: i+1]
		vs = append(vs, computeBlindedEd25519Vector(
			fmt.Sprintf("leif_chain_step_%d", i+1),
			provenanceLeif,
			[]byte(leifPriv),
			leifMessage,
			factors,
		))
	}

	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "blinded_ed25519",
		Description:   "Blinded Ed25519 per hpqc/sign/ed25519/blinded25519.go. Each vector applies an ordered list of blind factors to a private key and records the resulting blinded public key and a signature over the message under the blinded private key. Single-factor and chain (multi-factor) cases use the same schema; vector names and per-vector provenance distinguish the two sources.",
		Vectors:       vs,
	}
}

// computeBlindedEd25519Vector applies the blind factors to privKeyBytes in
// order, signs message under the resulting blinded private key, and returns
// a vector with the recorded outputs. It panics if the resulting signature
// fails to self-verify under standard Ed25519 against the blinded pubkey.
func computeBlindedEd25519Vector(name, provenance string, privKeyBytes, message []byte, factors [][]byte) blindedEd25519Vector {
	if len(factors) == 0 {
		panic("computeBlindedEd25519Vector: at least one factor required")
	}
	priv := new(ed25519.PrivateKey)
	must(priv.FromBytes(privKeyBytes))

	blinded := priv.Blind(factors[0])
	for _, f := range factors[1:] {
		blinded = blinded.Blind(f)
	}
	blindedPub := blinded.PublicKey()
	sig := blinded.Sign(message)

	if !blindedPub.Verify(sig, message) {
		panic("vector " + name + ": signature failed self-verification")
	}

	factorsHex := make([]string, len(factors))
	for i, f := range factors {
		factorsHex[i] = hex.EncodeToString(f)
	}
	return blindedEd25519Vector{
		Name:             name,
		Provenance:       provenance,
		PrivateKeyHex:    hex.EncodeToString(privKeyBytes),
		MessageHex:       hex.EncodeToString(message),
		BlindFactorsHex:  factorsHex,
		BlindedPubKeyHex: hex.EncodeToString(blindedPub.Bytes()),
		BlindedSigHex:    hex.EncodeToString(sig),
	}
}

func writeFile(root, rel string, v vectorFile) {
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	b = append(b, '\n')
	must(os.WriteFile(filepath.Join(root, rel), b, 0o644))
	fmt.Println("wrote", filepath.Join(root, rel))
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	must(err)
	return b
}

func bytesPattern(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// ===== BACAP vectors =====
//
// BACAP-level vectors layered on top of the primitive vectors. They use a
// fixed root ed25519 keypair and a fixed initial MessageBoxIndex so that
// every step of the chain (HKDF advancement, blinded box-id derivation,
// AES-GCM-SIV encryption, blinded ed25519 signature) is deterministic and
// byte-comparable across implementations.

// fixedBACAPSeed is the 32-byte ed25519 seed used to derive the root
// keypair for every BACAP vector below. The bytes are 0x00..0x1f so a
// reader can recognise them immediately.
var fixedBACAPSeed = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}()

// fixedBACAPInitialIndex is the initial MessageBoxIndex used by every
// BACAP vector. The non-zero values make divergent state easy to spot.
var fixedBACAPInitialIndex = bacap.MessageBoxIndex{
	Idx64:             1,
	CurBlindingFactor: bytesPattern32(0xaa),
	CurEncryptionKey:  bytesPattern32(0xbb),
	HKDFState:         bytesPattern32(0xcc),
}

func bytesPattern32(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

// fixedBACAPWriteCapBytes constructs a deterministic 168-byte WriteCap
// blob from fixedBACAPSeed and fixedBACAPInitialIndex.
func fixedBACAPWriteCapBytes() []byte {
	priv := stded25519.NewKeyFromSeed(fixedBACAPSeed) // 64 bytes seed||pub
	idxBytes, err := fixedBACAPInitialIndex.MarshalBinary()
	must(err)
	out := make([]byte, 0, len(priv)+len(idxBytes))
	out = append(out, priv...)
	out = append(out, idxBytes...)
	return out
}

// MessageBoxIndex.AdvanceIndexTo vectors. Pin the HKDF chain that derives
// blinding factors and encryption keys from the HKDF state.

type bacapAdvanceVector struct {
	Name             string `json:"name"`
	InitialIndexHex  string `json:"initial_index_hex"`
	AdvanceTo        uint64 `json:"advance_to"`
	ExpectedIndexHex string `json:"expected_index_hex"`
}

func genBACAPMessageBoxIndex() vectorFile {
	initial := fixedBACAPInitialIndex
	initialBytes, err := initial.MarshalBinary()
	must(err)

	steps := []uint64{1, 2, 5, 100, 1000}
	vs := make([]bacapAdvanceVector, 0, len(steps))
	for _, n := range steps {
		target := initial.Idx64 + n
		advanced, err := initial.AdvanceIndexTo(target)
		must(err)
		advancedBytes, err := advanced.MarshalBinary()
		must(err)
		vs = append(vs, bacapAdvanceVector{
			Name:             fmt.Sprintf("advance_by_%d", n),
			InitialIndexHex:  hex.EncodeToString(initialBytes),
			AdvanceTo:        target,
			ExpectedIndexHex: hex.EncodeToString(advancedBytes),
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "bacap_message_box_index",
		Description:   "MessageBoxIndex.AdvanceIndexTo vectors. The initial 104-byte MessageBoxIndex blob is advanced by N steps via the HKDF-BLAKE2b-512 chain; the expected 104-byte resulting blob is recorded.",
		Vectors:       vs,
	}
}

// Box-ID derivation vectors. Cover both DeriveMessageBoxID (blinding by
// the index's CurBlindingFactor) and BoxIDForContext (which first runs
// CurBlindingFactor through HKDF with the context as salt).

type bacapBoxIDVector struct {
	Name              string `json:"name"`
	WriteCapHex       string `json:"writecap_hex"`
	AdvanceBy         uint64 `json:"advance_by"`
	CtxHex            string `json:"ctx_hex"`
	UseContext        bool   `json:"use_context"`
	ExpectedBoxIDHex  string `json:"expected_box_id_hex"`
}

func genBACAPBoxID() vectorFile {
	wcBytes := fixedBACAPWriteCapBytes()
	wc, err := bacap.NewWriteCapFromBytes(wcBytes)
	must(err)
	rc := wc.ReadCap()
	rootPub := fixedBACAPRootPubKey()

	cases := []struct {
		name       string
		advanceBy  uint64
		ctx        []byte
		useContext bool
	}{
		{"derive_at_first_index", 0, nil, false},
		{"derive_after_advance_5", 5, nil, false},
		{"box_id_for_context_at_first_index", 0, []byte("hpqc-bacap-vector-context"), true},
		{"box_id_for_context_after_advance_3", 3, []byte("alternate context"), true},
	}

	vs := make([]bacapBoxIDVector, 0, len(cases))
	for _, c := range cases {
		idx := wc.GetFirstMessageBoxIndex()
		if c.advanceBy > 0 {
			advanced, err := idx.AdvanceIndexTo(idx.Idx64 + c.advanceBy)
			must(err)
			idx = advanced
		}
		var boxID []byte
		if c.useContext {
			boxID = idx.BoxIDForContext(rc, c.ctx).Bytes()
		} else {
			boxID = idx.DeriveMessageBoxID(rootPub).Bytes()
		}
		vs = append(vs, bacapBoxIDVector{
			Name:             c.name,
			WriteCapHex:      hex.EncodeToString(wcBytes),
			AdvanceBy:        c.advanceBy,
			CtxHex:           hex.EncodeToString(c.ctx),
			UseContext:       c.useContext,
			ExpectedBoxIDHex: hex.EncodeToString(boxID),
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "bacap_box_id",
		Description:   "Box-ID derivation vectors. For each vector, advance the WriteCap's first MessageBoxIndex by N, then derive the box ID. If use_context is true, BoxIDForContext is used (HKDFs the context into the blinding); otherwise DeriveMessageBoxID is used (blinds the root pubkey with the index's CurBlindingFactor directly).",
		Vectors:       vs,
	}
}

// fixedBACAPRootPubKey returns the ed25519 public key derived from
// fixedBACAPSeed. Used for DeriveMessageBoxID vectors which take a
// root pubkey directly rather than going through the WriteCap.
func fixedBACAPRootPubKey() *ed25519.PublicKey {
	priv := stded25519.NewKeyFromSeed(fixedBACAPSeed) // 64 bytes seed||pub
	pk := new(ed25519.PublicKey)
	must(pk.FromBytes(priv[32:64]))
	return pk
}

// Encrypt-for-context vectors. End-to-end check of the BACAP encrypt
// path, including HKDF, ed25519 blinding, AES-GCM-SIV, and blinded
// ed25519 signing.

type bacapEncryptVector struct {
	Name                string `json:"name"`
	WriteCapHex         string `json:"writecap_hex"`
	AdvanceBy           uint64 `json:"advance_by"`
	CtxHex              string `json:"ctx_hex"`
	PlaintextHex        string `json:"plaintext_hex"`
	ExpectedBoxIDHex    string `json:"expected_box_id_hex"`
	ExpectedCiphertext  string `json:"expected_ciphertext_hex"`
	ExpectedSignatureHex string `json:"expected_signature_hex"`
}

func genBACAPEncrypt() vectorFile {
	wcBytes := fixedBACAPWriteCapBytes()
	wc, err := bacap.NewWriteCapFromBytes(wcBytes)
	must(err)

	cases := []struct {
		name      string
		advanceBy uint64
		ctx       []byte
		plaintext []byte
	}{
		{"encrypt_short_at_first", 0, []byte("ctx-A"), []byte("hello")},
		{"encrypt_short_after_advance", 7, []byte("ctx-B"), []byte("after advance")},
		{"encrypt_long_payload", 0, []byte("ctx-C"), repeatByte(0x55, 1024)},
	}

	vs := make([]bacapEncryptVector, 0, len(cases))
	for _, c := range cases {
		idx := wc.GetFirstMessageBoxIndex()
		if c.advanceBy > 0 {
			advanced, err := idx.AdvanceIndexTo(idx.Idx64 + c.advanceBy)
			must(err)
			idx = advanced
		}
		boxID, ct, sig := idx.EncryptForContext(wc, c.ctx, c.plaintext)

		// Sanity: round-trip decrypts to the original plaintext.
		recovered, err := idx.DecryptForContext(boxID, c.ctx, ct, sig)
		must(err)
		if string(recovered) != string(c.plaintext) {
			panic("vector " + c.name + ": decrypt round-trip mismatch")
		}

		vs = append(vs, bacapEncryptVector{
			Name:                 c.name,
			WriteCapHex:          hex.EncodeToString(wcBytes),
			AdvanceBy:            c.advanceBy,
			CtxHex:               hex.EncodeToString(c.ctx),
			PlaintextHex:         hex.EncodeToString(c.plaintext),
			ExpectedBoxIDHex:     hex.EncodeToString(boxID[:]),
			ExpectedCiphertext:   hex.EncodeToString(ct),
			ExpectedSignatureHex: hex.EncodeToString(sig),
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "bacap_encrypt",
		Description:   "BACAP MessageBoxIndex.EncryptForContext vectors. For each vector, the WriteCap is deserialized, its first MessageBoxIndex advanced by N, and the plaintext encrypted under the given context. Records the box ID, ciphertext (AES-256-GCM-SIV with 12-byte nonce), and signature (blinded ed25519 over the ciphertext).",
		Vectors:       vs,
	}
}

func repeatByte(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
