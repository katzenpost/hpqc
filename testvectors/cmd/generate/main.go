//go:build !thinclient

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
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"github.com/agl/gcmsiv"
	"github.com/katzenpost/falcon/padded1024"
	"github.com/katzenpost/falcon/padded512"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem/adapter"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/hybrid"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/ed25519"
	signhybrid "github.com/katzenpost/hpqc/sign/hybrid"
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
	must(os.MkdirAll(filepath.Join(*out, "kem"), 0o755))

	writeFile(*out, "primitives/sha512_256.json", genSHA512_256())
	writeFile(*out, "primitives/blake2b_512.json", genBLAKE2b512())
	writeFile(*out, "primitives/hkdf_blake2b.json", genHKDFBlake2b())
	writeFile(*out, "primitives/aes_gcm_siv.json", genAESGCMSIV())
	writeFile(*out, "primitives/blinded_ed25519.json", genBlindedEd25519())
	writeFile(*out, "primitives/ed25519.json", genEd25519())
	writeFile(*out, "primitives/falcon_padded_512.json", genFalconPadded512())
	writeFile(*out, "primitives/falcon_padded_512_ed25519.json", genFalconPadded512Ed25519())
	writeFile(*out, "primitives/falcon_padded_1024_ed25519.json", genFalconPadded1024Ed25519())

	writeFile(*out, "bacap/message_box_index.json", genBACAPMessageBoxIndex())
	writeFile(*out, "bacap/box_id.json", genBACAPBoxID())
	writeFile(*out, "bacap/encrypt.json", genBACAPEncrypt())
	writeFile(*out, "bacap/mutate_kdf_state.json", genBACAPMutateKDFState())

	writeFile(*out, "kem/mkem.json", genKEMMkem())
	writeFile(*out, "kem/adapter_test_vectors.json", genKEMAdapter())

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
	Name             string   `json:"name"`
	Provenance       string   `json:"provenance"`            // where the inputs came from
	PrivateKeyHex    string   `json:"private_key_hex"`       // 64-byte Ed25519 private key (seed || pub)
	MessageHex       string   `json:"message_hex"`           // message to sign
	BlindFactorsHex  []string `json:"blind_factors_hex"`     // one or more 32-byte factors, applied in order
	BlindedPubKeyHex string   `json:"blinded_pubkey_hex"`    // 32-byte blinded public key after all factors applied
	BlindedSigHex    string   `json:"blinded_signature_hex"` // 64-byte signature under the blinded private key
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
		factors := leifFactors[:i+1]
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

// Plain Ed25519, Falcon-padded-512, and the Falcon-padded-{512,1024}-Ed25519
// hybrid sign/verify vectors share the same shape: a verifier consumes
// (public_key, message, signature) and asserts true. Vectors are produced
// deterministically so re-running the generator yields byte-identical output.

type signVerifyVector struct {
	Name         string `json:"name"`
	PublicKeyHex string `json:"public_key_hex"`
	MessageHex   string `json:"message_hex"`
	SignatureHex string `json:"signature_hex"`
}

// signVerifyCase is the deterministic input set for the sign-verify generators.
// Every vector below derives its keys and (where applicable) per-signature
// randomness from a BLAKE2b-512-keyed HKDF stream over (label, name), so the
// emitted bytes are stable across regenerations.
type signVerifyCase struct {
	name string
	msg  []byte
}

var signVerifyCases = []signVerifyCase{
	{"vec_1_empty_msg", []byte{}},
	{"vec_2_short_ascii", []byte("the quick brown fox jumps over the lazy dog")},
	{"vec_3_thirty_two_bytes", bytesPattern(0x5a, 32)},
	{"vec_4_one_kilobyte", bytesPattern(0xa5, 1024)},
	{"vec_5_random_short", deterministicBytes("sign_verify_msg", "vec_5_random_short", 17)},
	{"vec_6_random_long", deterministicBytes("sign_verify_msg", "vec_6_random_long", 4096)},
}

// deterministicReader returns an HKDF-BLAKE2b-512 stream keyed on (label,
// vectorName). Two readers built with the same arguments produce the same
// bytes, which is what lets the Falcon vectors be deterministic despite
// PQClean Falcon keygen and signing both consuming randomness internally.
func deterministicReader(label, vectorName string) io.Reader {
	h := func() hash.Hash { hh, _ := blake2b.New512(nil); return hh }
	secret := append([]byte("hpqc-vector-seed-"), []byte(label)...)
	info := []byte(vectorName)
	return hkdf.New(h, secret, nil, info)
}

func deterministicBytes(label, vectorName string, n int) []byte {
	out := make([]byte, n)
	_, err := io.ReadFull(deterministicReader(label, vectorName), out)
	must(err)
	return out
}

// genEd25519 emits plain Ed25519 sign/verify vectors. Each vector's seed is
// taken from a deterministic HKDF stream so the recorded outputs are stable.

func genEd25519() vectorFile {
	vs := make([]signVerifyVector, 0, len(signVerifyCases))
	for _, c := range signVerifyCases {
		seed := deterministicBytes("ed25519_seed", c.name, stded25519.SeedSize)
		priv := stded25519.NewKeyFromSeed(seed)
		pub := priv.Public().(stded25519.PublicKey)
		sig := stded25519.Sign(priv, c.msg)
		if !stded25519.Verify(pub, c.msg, sig) {
			panic("ed25519 vector " + c.name + ": self-verify failed")
		}
		vs = append(vs, signVerifyVector{
			Name:         c.name,
			PublicKeyHex: hex.EncodeToString(pub),
			MessageHex:   hex.EncodeToString(c.msg),
			SignatureHex: hex.EncodeToString(sig),
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "ed25519",
		Description:   "Plain Ed25519 (RFC 8032) sign/verify vectors. Each seed is deterministically derived via HKDF-BLAKE2b-512 over the vector name; the 32-byte public key is recorded along with a 64-byte signature over the message.",
		Vectors:       vs,
	}
}

// genFalconPadded512 emits Falcon-padded-512 sign/verify vectors. Falcon
// keygen and signing both draw from PQClean's internal SHAKE256 PRNG, which
// in our wrapper reads from a Go io.Reader (rng.go). SetTestRNG installs a
// deterministic source for the duration of each vector so the recorded
// (pub, sig) bytes are stable across regenerations.

func genFalconPadded512() vectorFile {
	vs := make([]signVerifyVector, 0, len(signVerifyCases))
	for _, c := range signVerifyCases {
		restore := padded512.SetTestRNG(deterministicReader("falcon_padded_512", c.name))
		pk, sk, err := padded512.GenerateKey()
		must(err)
		sig, err := padded512.Sign(&sk, c.msg)
		must(err)
		restore()
		if !padded512.Verify(&pk, c.msg, sig) {
			panic("falcon-padded-512 vector " + c.name + ": self-verify failed")
		}
		vs = append(vs, signVerifyVector{
			Name:         c.name,
			PublicKeyHex: hex.EncodeToString(pk[:]),
			MessageHex:   hex.EncodeToString(c.msg),
			SignatureHex: hex.EncodeToString(sig),
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "falcon_padded_512",
		Description:   "Falcon-padded-512 sign/verify vectors. Falcon keygen and signing both consume randomness, so each vector pins the deterministic HKDF stream that feeds PQClean's PRNG via katzenpost/falcon's SetTestRNG. Recorded fields: 897-byte public key and 666-byte fixed-length signature.",
		Vectors:       vs,
	}
}

// genFalconPadded512Ed25519 emits hybrid sign/verify vectors. The hybrid
// public key is falcon_pub || ed25519_pub and the hybrid signature is
// falcon_sig || ed25519_sig; the recorded bytes are constructed manually
// here and then round-tripped through the registered hpqc hybrid scheme to
// confirm the on-wire layout matches what UnmarshalBinaryPublicKey + Verify
// expect.

func genFalconPadded512Ed25519() vectorFile {
	return genFalconHybrid(
		"falcon_padded_512_ed25519",
		"Falcon-padded-512-Ed25519 hybrid sign/verify vectors. The hybrid public key is the concatenation of the 897-byte Falcon-padded-512 public key and the 32-byte Ed25519 public key (929 bytes total); the hybrid signature is the concatenation of the 666-byte Falcon signature and the 64-byte Ed25519 signature (730 bytes total). Both halves are deterministic.",
		signhybrid.FalconPadded512Ed25519,
		func(r io.Reader, msg []byte) (pub, sig []byte) {
			restore := padded512.SetTestRNG(r)
			pk, sk, err := padded512.GenerateKey()
			must(err)
			s, err := padded512.Sign(&sk, msg)
			must(err)
			restore()
			return pk[:], s
		},
	)
}

// genFalconPadded1024Ed25519 mirrors the 512-variant generator using the
// padded-1024 Falcon parameter set.

func genFalconPadded1024Ed25519() vectorFile {
	return genFalconHybrid(
		"falcon_padded_1024_ed25519",
		"Falcon-padded-1024-Ed25519 hybrid sign/verify vectors. The hybrid public key is the concatenation of the 1793-byte Falcon-padded-1024 public key and the 32-byte Ed25519 public key (1825 bytes total); the hybrid signature is the concatenation of the 1280-byte Falcon signature and the 64-byte Ed25519 signature (1344 bytes total). Both halves are deterministic.",
		signhybrid.FalconPadded1024Ed25519,
		func(r io.Reader, msg []byte) (pub, sig []byte) {
			restore := padded1024.SetTestRNG(r)
			pk, sk, err := padded1024.GenerateKey()
			must(err)
			s, err := padded1024.Sign(&sk, msg)
			must(err)
			restore()
			return pk[:], s
		},
	)
}

func genFalconHybrid(primitive, description string, scheme sign.Scheme, falconHalf func(io.Reader, []byte) ([]byte, []byte)) vectorFile {
	vs := make([]signVerifyVector, 0, len(signVerifyCases))
	for _, c := range signVerifyCases {
		fPub, fSig := falconHalf(deterministicReader(primitive+"_falcon", c.name), c.msg)

		edSeed := deterministicBytes(primitive+"_ed25519", c.name, stded25519.SeedSize)
		edPriv := stded25519.NewKeyFromSeed(edSeed)
		edPub := edPriv.Public().(stded25519.PublicKey)
		edSig := stded25519.Sign(edPriv, c.msg)

		pub := append(append([]byte{}, fPub...), edPub...)
		sig := append(append([]byte{}, fSig...), edSig...)

		hpk, err := scheme.UnmarshalBinaryPublicKey(pub)
		must(err)
		if !scheme.Verify(hpk, c.msg, sig, nil) {
			panic("hybrid vector " + c.name + ": self-verify failed via " + scheme.Name())
		}
		vs = append(vs, signVerifyVector{
			Name:         c.name,
			PublicKeyHex: hex.EncodeToString(pub),
			MessageHex:   hex.EncodeToString(c.msg),
			SignatureHex: hex.EncodeToString(sig),
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     primitive,
		Description:   description,
		Vectors:       vs,
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
	Name             string `json:"name"`
	WriteCapHex      string `json:"writecap_hex"`
	AdvanceBy        uint64 `json:"advance_by"`
	CtxHex           string `json:"ctx_hex"`
	UseContext       bool   `json:"use_context"`
	ExpectedBoxIDHex string `json:"expected_box_id_hex"`
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
		idx := wc.GetMessageBoxIndex()
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
	Name                 string `json:"name"`
	WriteCapHex          string `json:"writecap_hex"`
	AdvanceBy            uint64 `json:"advance_by"`
	CtxHex               string `json:"ctx_hex"`
	PlaintextHex         string `json:"plaintext_hex"`
	ExpectedBoxIDHex     string `json:"expected_box_id_hex"`
	ExpectedCiphertext   string `json:"expected_ciphertext_hex"`
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
		idx := wc.GetMessageBoxIndex()
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

// MutateKDFState vectors. Pin the re-seed operation behind the Contact
// Voucher's VoucherSalt: a WriteCap's first MessageBoxIndex is advanced by N,
// re-seeded by the salt, and the resulting 104-byte index recorded along with
// the box ID derived from it under a read context. The box ID is taken through
// the read cap, so a consumer that mis-derives either the mutation or the
// downstream blinding is caught.

type bacapMutateVector struct {
	Name             string `json:"name"`
	WriteCapHex      string `json:"writecap_hex"`
	AdvanceBy        uint64 `json:"advance_by"`
	SaltHex          string `json:"salt_hex"`
	ReadCtxHex       string `json:"read_ctx_hex"`
	ExpectedIndexHex string `json:"expected_mutated_index_hex"`
	ExpectedBoxIDHex string `json:"expected_mutated_box_id_hex"`
}

func genBACAPMutateKDFState() vectorFile {
	wcBytes := fixedBACAPWriteCapBytes()
	wc, err := bacap.NewWriteCapFromBytes(wcBytes)
	must(err)
	rc := wc.ReadCap()

	cases := []struct {
		name      string
		advanceBy uint64
		salt      []byte
		readCtx   []byte
	}{
		{"mutate_at_first_index", 0, bytesPattern(0x11, 32), []byte("pigeonhole context")},
		{"mutate_after_advance_5", 5, bytesPattern(0x22, 32), []byte("pigeonhole context")},
		{"mutate_distinct_salt", 0, bytesPattern(0x33, 32), []byte("alternate context")},
	}

	vs := make([]bacapMutateVector, 0, len(cases))
	for _, c := range cases {
		idx := wc.GetMessageBoxIndex()
		if c.advanceBy > 0 {
			advanced, err := idx.AdvanceIndexTo(idx.Idx64 + c.advanceBy)
			must(err)
			idx = advanced
		}
		mutated := idx.MutateKDFState(c.salt)
		mutatedBytes, err := mutated.MarshalBinary()
		must(err)
		boxID := mutated.BoxIDForContext(rc, c.readCtx).Bytes()
		vs = append(vs, bacapMutateVector{
			Name:             c.name,
			WriteCapHex:      hex.EncodeToString(wcBytes),
			AdvanceBy:        c.advanceBy,
			SaltHex:          hex.EncodeToString(c.salt),
			ReadCtxHex:       hex.EncodeToString(c.readCtx),
			ExpectedIndexHex: hex.EncodeToString(mutatedBytes),
			ExpectedBoxIDHex: hex.EncodeToString(boxID),
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "bacap_mutate_kdf_state",
		Description:   "MessageBoxIndex.MutateKDFState vectors. For each vector, the WriteCap's first MessageBoxIndex is advanced by N, then re-seeded by the salt via HKDF-BLAKE2b-512 under the domain label \"bacap-mutate-kdf-state-v1\" (salt slot = the salt, read order H,E,K, Idx64 preserved). Records the resulting 104-byte mutated index and the box ID derived from it under the read context. This is the BACAP primitive behind the Contact Voucher VoucherSalt.",
		Vectors:       vs,
	}
}

// ===== MKEM vectors =====
//
// Multi-recipient KEM over the CTIDH1024-X25519 hybrid NIKE. Each
// vector is non-deterministic (ephemeral keys, msg keys, and AEAD
// nonces are all random), so re-running the generator produces a
// different mkem.json. The recorded vector exercises the wire-
// format compatibility of the Python port: the Python side loads
// the recipient private keys and the CBOR-marshaled ciphertext, then
// decapsulates and confirms the recovered plaintext. A pass means
// CBOR field naming, ChaCha20-Poly1305 framing (12-byte nonce + tag),
// BLAKE2b-256 hashing of the NIKE shared secret, and the underlying
// hybrid NIKE shared-secret bytes all agree between Go and Python.

type mkemVector struct {
	Name                    string   `json:"name"`
	NikeName                string   `json:"nike_name"`
	RecipientPrivateKeysHex []string `json:"recipient_private_keys_hex"`
	CiphertextHex           string   `json:"ciphertext_hex"`
	PlaintextHex            string   `json:"plaintext_hex"`
}

func genKEMMkem() vectorFile {
	nikeScheme := hybrid.CTIDH1024X25519
	scheme := mkem.NewScheme(nikeScheme)

	cases := []struct {
		name      string
		nRecips   int
		plaintext []byte
	}{
		{"single_recipient_short", 1, []byte("hello")},
		{"two_recipients", 2, []byte("multicast payload across two recipients")},
		{"three_recipients_long", 3, repeatByte(0x42, 1024)},
	}

	vs := make([]mkemVector, 0, len(cases))
	for _, c := range cases {
		pubs := make([]nike.PublicKey, c.nRecips)
		privs := make([]nike.PrivateKey, c.nRecips)
		privsHex := make([]string, c.nRecips)
		for i := 0; i < c.nRecips; i++ {
			pub, priv, err := scheme.GenerateKeyPair()
			must(err)
			pubs[i] = pub
			privs[i] = priv
			privBytes, err := priv.MarshalBinary()
			must(err)
			privsHex[i] = hex.EncodeToString(privBytes)
		}

		_, ct := scheme.Encapsulate(pubs, c.plaintext)
		ctBytes := ct.Marshal()

		// Self-check: every recipient must decapsulate to the same
		// plaintext under this very ciphertext.
		for i := 0; i < c.nRecips; i++ {
			got, err := scheme.Decapsulate(privs[i], ct)
			must(err)
			if string(got) != string(c.plaintext) {
				panic("mkem vector " + c.name + ": self-decap mismatch")
			}
		}

		vs = append(vs, mkemVector{
			Name:                    c.name,
			NikeName:                nikeScheme.Name(),
			RecipientPrivateKeysHex: privsHex,
			CiphertextHex:           hex.EncodeToString(ctBytes),
			PlaintextHex:            hex.EncodeToString(c.plaintext),
		})
	}

	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "kem_mkem",
		Description:   "MKEM ciphertexts over the CTIDH1024-X25519 hybrid NIKE. Each vector records the recipient private keys (hex, MarshalBinary form) and a CBOR-marshaled MKEM ciphertext; consumers must recover the recorded plaintext when decapsulating with any of the recorded private keys. Outputs are non-deterministic, so re-running the generator changes every vector.",
		Vectors:       vs,
	}
}

// NIKE-to-KEM adapter (hashed ElGamal) over X25519. The adapter's ciphertext is
// exactly the encoded ephemeral public key, and its shared secret is a keyed
// BLAKE2b XOF over the static recipient key followed by the ephemeral key,
// keyed by the raw X25519 shared secret. See kem/adapter/kem.go.

type adapterVector struct {
	Name                   string `json:"name"`
	NikeName               string `json:"nike_name"`
	PRFName                string `json:"prf"`
	StaticPrivateKeyHex    string `json:"static_private_key_hex"`
	StaticPublicKeyHex     string `json:"static_public_key_hex"`
	EphemeralPrivateKeyHex string `json:"ephemeral_private_key_hex"`
	CiphertextHex          string `json:"ciphertext_hex"`
	SharedSecretHex        string `json:"shared_secret_hex"`
}

// clampX25519 applies the RFC 7748 clamping. Recorded private keys are stored
// already clamped, so implementations that clamp on load and implementations
// that clamp at use time agree on the scalar; clamping is idempotent.
func clampX25519(k []byte) []byte {
	out := make([]byte, len(k))
	copy(out, k)
	out[0] &= 248
	out[31] &= 127
	out[31] |= 64
	return out
}

// adapterScalar derives a fixed, clamped X25519 scalar from a label, so the
// vectors are stable across regeneration.
func adapterScalar(label string) []byte {
	sum := sha512.Sum512_256([]byte(label))
	return clampX25519(sum[:])
}

func genKEMAdapter() vectorFile {
	nikeScheme := ecdh.Scheme(rand.Reader)

	cases := []struct{ name, staticLabel, ephemeralLabel string }{
		{"x25519_distinct_keys_1", "hpqc adapter static 1", "hpqc adapter ephemeral 1"},
		{"x25519_distinct_keys_2", "hpqc adapter static 2", "hpqc adapter ephemeral 2"},
		{"x25519_same_scalar_both_sides", "hpqc adapter static 3", "hpqc adapter static 3"},
	}

	// Both the deployed PRF and the portable one, so a consumer that has only
	// SHA-256 still has vectors it can check, and one that has BLAKE2b can
	// check the configuration actually shipped.
	prfs := []adapter.PRF{adapter.BLAKE2bXOF, adapter.SHA256v1}

	vs := make([]adapterVector, 0, len(cases)*len(prfs))
	for _, prf := range prfs {
		scheme := adapter.FromNIKEWithPRF(nikeScheme, prf)
		for _, c := range cases {
			staticPrivBytes := adapterScalar(c.staticLabel)
			ephPrivBytes := adapterScalar(c.ephemeralLabel)

			staticPriv, err := scheme.UnmarshalBinaryPrivateKey(staticPrivBytes)
			must(err)
			ephPriv, err := scheme.UnmarshalBinaryPrivateKey(ephPrivBytes)
			must(err)

			staticPubBytes, err := staticPriv.Public().MarshalBinary()
			must(err)
			ephPubBytes, err := ephPriv.Public().MarshalBinary()
			must(err)

			// The adapter ciphertext is the encoded ephemeral public key, so
			// decapsulating it under the static private key yields exactly the
			// shared secret Encapsulate would produce with this ephemeral.
			// Encapsulate itself draws its ephemeral from crypto/rand and
			// EncapsulateDeterministically is unimplemented, so this is the
			// only deterministic way to record the value.
			ss, err := scheme.Decapsulate(staticPriv, ephPubBytes)
			must(err)

			vs = append(vs, adapterVector{
				Name:                   c.name + "_" + prf.Name(),
				NikeName:               nikeScheme.Name(),
				PRFName:                prf.Name(),
				StaticPrivateKeyHex:    hex.EncodeToString(staticPrivBytes),
				StaticPublicKeyHex:     hex.EncodeToString(staticPubBytes),
				EphemeralPrivateKeyHex: hex.EncodeToString(ephPrivBytes),
				CiphertextHex:          hex.EncodeToString(ephPubBytes),
				SharedSecretHex:        hex.EncodeToString(ss),
			})
		}
	}

	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "kem_adapter",
		Description:   "NIKE-to-KEM adapter (hashed ElGamal) over X25519. Each vector fixes a static recipient keypair and an ephemeral keypair; the ciphertext is the encoded ephemeral public key and the shared secret is what both Encapsulate (with that ephemeral) and Decapsulate produce. The \"prf\" field names the shared-key derivation: \"blake2b-xof\" is the deployed one, \"sha256-v1\" is a portable fixed-width alternative for implementations without BLAKE2b. Consumers must dispatch on it rather than assume. Private keys are recorded already clamped per RFC 7748 so implementations clamping on load and at use time agree. Vectors are deterministic: regenerating does not change the bytes.",
		Vectors:       vs,
	}
}
