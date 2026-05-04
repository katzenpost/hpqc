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
// In BACAP the nonce is box_id[:16] and the AAD is box_id[:32]; the vectors
// here mirror that shape.

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
			nonce:     bytesPattern(0xbb, 16),
			aad:       bytesPattern(0xbb, 32),
			plaintext: []byte("Hello, BACAP."),
		},
		{
			name:      "bacap_shape_long_plaintext",
			key:       bytesPattern(0xcc, 32),
			nonce:     bytesPattern(0xdd, 16),
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

// Blinded Ed25519 per hpqc/sign/ed25519/blinded25519.go. Each vector locks
// down both the blinded public key and the signature: a Python port that
// gets the SHA-512/256 factor hashing wrong, the scalar clamping wrong, or
// the [33:64] off-by-one in the nonce derivation will fail one of these.

type blindedEd25519Vector struct {
	Name             string `json:"name"`
	PrivateKeyHex    string `json:"private_key_hex"`    // 64-byte Ed25519 private key (seed || pub)
	BlindFactorHex   string `json:"blind_factor_hex"`   // 32-byte raw factor (will be sha512_256-hashed inside Blind)
	MessageHex       string `json:"message_hex"`        // message to sign
	BlindedPubKeyHex string `json:"blinded_pubkey_hex"` // 32-byte blinded public key
	SignatureHex     string `json:"signature_hex"`      // 64-byte custom-routine signature
}

func genBlindedEd25519() vectorFile {
	// Three vectors lifted directly from sign/ed25519/blinded25519_test.go's
	// TestBlindedSignatureVectors. They are deterministic given the inputs
	// and serve as the smoke-test triplet for any port of Blind+Sign.
	cases := []struct {
		name       string
		privateKey string
		factor     string
		message    string
	}{
		{
			name:       "vector_1_seed_12345",
			privateKey: "1ae969564b34a33ecd1af05fe6923d6de71870997d38ef60155c325957214c425d8ca057866bdee02b63464f587aa75fdad4694c5c05db72323f3928722286cf",
			factor:     "59d74b863e2fba93aeceb05d2fdcde0c9688d21d95aa7bedefc7f31b35731a3d",
			message:    "297611a6b583a5c30587d4e530c948f013e96d5a4e653f0791899d6270c6f3c0",
		},
		{
			name:       "vector_2_seed_0",
			privateKey: "0194fdc2fa2ffcc041d3ff12045b73c86e4ff95ff662a5eee82abdf44a2d0b7597f3bd871315281e8b83edc7a9fd0541066154449070ccdb3cdd42cf69ccde88",
			factor:     "fb180daf48a79ee0b10d394651850fd4a178892ee285ece1511455780875d64e",
			message:    "e2d3d0d0de6bf8f9b44ce85ff044c6b1f83b8e883bbf857aab99c5b252c7429c",
		},
		{
			name:       "vector_3_seed_max_int64",
			privateKey: "52fdfc072182654f163f5f0f9a621d729566c74d10037c4d7bbb0407d1e2c6496f1581709bb7b1ef030d210db18e3b0ba1c776fba65d8cdaad05415142d189f8",
			factor:     "81855ad8681d0d86d1e91e00167939cb6694d2c422acd208a0072939487f6999",
			message:    "eb9d18a44784045d87f3c67cf22746e995af5a25367951baa2ff6cd471c483f1",
		},
	}
	vs := make([]blindedEd25519Vector, 0, len(cases))
	for _, c := range cases {
		privBytes := mustHex(c.privateKey)
		factor := mustHex(c.factor)
		message := mustHex(c.message)

		priv := new(ed25519.PrivateKey)
		must(priv.FromBytes(privBytes))
		blinded := priv.Blind(factor)
		blindedPub := blinded.PublicKey()
		sig := blinded.Sign(message)

		// Sanity: the resulting signature must verify under standard Ed25519
		// against the blinded public key. This is the property that lets a
		// Python sender interoperate with any Ed25519 verifier.
		if !blindedPub.Verify(sig, message) {
			panic("vector " + c.name + ": signature failed self-verification")
		}

		vs = append(vs, blindedEd25519Vector{
			Name:             c.name,
			PrivateKeyHex:    c.privateKey,
			BlindFactorHex:   c.factor,
			MessageHex:       c.message,
			BlindedPubKeyHex: hex.EncodeToString(blindedPub.Bytes()),
			SignatureHex:     hex.EncodeToString(sig),
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "blinded_ed25519",
		Description:   "Blinded Ed25519 per hpqc/sign/ed25519/blinded25519.go. Inputs: (private_key, raw blind_factor, message). Outputs: (blinded_pubkey, signature). Each signature is verifiable under standard Ed25519 against the blinded pubkey.",
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
