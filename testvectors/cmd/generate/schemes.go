package main

import (
	"crypto/sha256"
	"encoding/hex"

	"filippo.io/mldsa"
	circlschemes "github.com/katzenpost/circl/kem/schemes"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign/ed25519"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
)

type signSchemeVector struct {
	Name          string `json:"name"`
	Scheme        string `json:"scheme"`
	SeedHex       string `json:"seed_hex"`
	PublicKeyHex  string `json:"public_key_hex"`
	PrivateKeyHex string `json:"private_key_hex"`
	MessageHex    string `json:"message_hex"`
	SignatureHex  string `json:"signature_hex"`
}

var mldsaParams = map[string]*mldsa.Parameters{
	"ML-DSA-44": mldsa.MLDSA44(),
	"ML-DSA-65": mldsa.MLDSA65(),
	"ML-DSA-87": mldsa.MLDSA87(),
}

// signDeterministic signs with the deterministic variant of each component:
// hpqc's ML-DSA signs hedged, which would make the vectors change on every
// run. Hybrid signatures are the concatenation of the halves.
func signDeterministic(scheme string, seed, msg []byte) []byte {
	if scheme == "Ed25519" {
		_, sk := ed25519.Scheme().DeriveKey(seed)
		sig, err := sk.Sign(nil, msg, nil)
		must(err)
		return sig
	}
	if params, ok := mldsaParams[scheme]; ok {
		sk, err := mldsa.NewPrivateKey(params, seed)
		must(err)
		sig, err := sk.SignDeterministic(msg, nil)
		must(err)
		return sig
	}
	pq := scheme[:len("ML-DSA-xx")]
	return append(signDeterministic(pq, seed[:32], msg), signDeterministic("Ed25519", seed[32:], msg)...)
}

func genSignSchemes() vectorFile {
	names := []string{
		"Ed25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
		"ML-DSA-44-Ed25519", "ML-DSA-65-Ed25519", "ML-DSA-87-Ed25519",
	}
	var vs []signSchemeVector
	for _, name := range names {
		scheme := signschemes.ByName(name)
		for _, c := range signVerifyCases[:3] {
			vname := name + "/" + c.name
			seed := deterministicBytes("sign_scheme_seed", vname, scheme.SeedSize())
			pk, sk := scheme.DeriveKey(seed)
			sig := signDeterministic(name, seed, c.msg)
			if !scheme.Verify(pk, c.msg, sig, nil) {
				panic("sign scheme vector " + vname + ": verify failed")
			}
			pkb, err := pk.MarshalBinary()
			must(err)
			skb, err := sk.MarshalBinary()
			must(err)
			vs = append(vs, signSchemeVector{
				Name:          vname,
				Scheme:        name,
				SeedHex:       hex.EncodeToString(seed),
				PublicKeyHex:  hex.EncodeToString(pkb),
				PrivateKeyHex: hex.EncodeToString(skb),
				MessageHex:    hex.EncodeToString(c.msg),
				SignatureHex:  hex.EncodeToString(sig),
			})
		}
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "sign_schemes",
		Description: "Key derivation and encodings of the registered signature schemes. For each " +
			"vector the keys are sign.Scheme.DeriveKey(seed) of the named scheme, encoded with " +
			"MarshalBinary. The signature is the deterministic variant (FIPS 204 deterministic " +
			"ML-DSA with an empty context, RFC 8032 Ed25519); a hybrid signature concatenates its " +
			"halves, each signed with its half of the seed. hpqc itself signs ML-DSA hedged, so its " +
			"signatures differ but verify the same way. Vectors are deterministic.",
		Vectors: vs,
	}
}

type nikeSchemeVector struct {
	Name               string `json:"name"`
	Scheme             string `json:"scheme"`
	AlicePrivateKeyHex string `json:"alice_private_key_hex"`
	AlicePublicKeyHex  string `json:"alice_public_key_hex"`
	BobPrivateKeyHex   string `json:"bob_private_key_hex"`
	BobPublicKeyHex    string `json:"bob_public_key_hex"`
	SharedSecretHex    string `json:"shared_secret_hex"`
	BlindingFactorHex  string `json:"blinding_factor_hex"`
	BlindedAlicePubHex string `json:"blinded_alice_public_key_hex"`
}

func nikeKeyPair(s nike.Scheme, label, vname string) (nike.PublicKey, nike.PrivateKey) {
	pk, sk, err := s.GenerateKeyPairFromEntropy(deterministicReader(label, vname))
	must(err)
	return pk, sk
}

func genNIKESchemes() vectorFile {
	var vs []nikeSchemeVector
	for _, name := range []string{"x25519", "x448"} {
		scheme := nikeschemes.ByName(name)
		for i := 1; i <= 3; i++ {
			vname := name + "/case_" + string(rune('0'+i))
			alicePub, alice := nikeKeyPair(scheme, "nike_alice", vname)
			bobPub, bob := nikeKeyPair(scheme, "nike_bob", vname)
			_, factor := nikeKeyPair(scheme, "nike_blinding_factor", vname)
			ss := scheme.DeriveSecret(alice, bobPub)
			if hex.EncodeToString(ss) != hex.EncodeToString(scheme.DeriveSecret(bob, alicePub)) {
				panic("nike vector " + vname + ": secrets differ")
			}
			vs = append(vs, nikeSchemeVector{
				Name:               vname,
				Scheme:             name,
				AlicePrivateKeyHex: hex.EncodeToString(alice.Bytes()),
				AlicePublicKeyHex:  hex.EncodeToString(alicePub.Bytes()),
				BobPrivateKeyHex:   hex.EncodeToString(bob.Bytes()),
				BobPublicKeyHex:    hex.EncodeToString(bobPub.Bytes()),
				SharedSecretHex:    hex.EncodeToString(ss),
				BlindingFactorHex:  hex.EncodeToString(factor.Bytes()),
				BlindedAlicePubHex: hex.EncodeToString(scheme.Blind(alicePub, factor).Bytes()),
			})
		}
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "nike_schemes",
		Description: "Key pairs, shared secrets and blinding for the registered elliptic-curve NIKEs. " +
			"Private keys are the raw scalars read from a deterministic HKDF stream, unclamped; " +
			"clamping happens at use. The blinded key is Scheme.Blind(alice public key, blinding " +
			"factor). Vectors are deterministic.",
		Vectors: vs,
	}
}

type mcelieceVector struct {
	Name             string `json:"name"`
	Scheme           string `json:"scheme"`
	SeedHex          string `json:"seed_hex"`
	PublicKeySHA256  string `json:"public_key_sha256_hex"`
	PrivateKeySHA256 string `json:"private_key_sha256_hex"`
	CiphertextHex    string `json:"ciphertext_hex"`
	SharedSecretHex  string `json:"shared_secret_hex"`
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func genMcEliece() vectorFile {
	names := []string{
		"mceliece348864", "mceliece348864f", "mceliece460896", "mceliece460896f",
		"mceliece6688128", "mceliece6688128f", "mceliece6960119", "mceliece6960119f",
		"mceliece8192128", "mceliece8192128f",
	}
	var vs []mcelieceVector
	for _, name := range names {
		scheme := kemschemes.ByName(name)
		seed := deterministicBytes("mceliece_seed", name, scheme.SeedSize())
		pk, sk := scheme.DeriveKeyPair(seed)
		pkb, err := pk.MarshalBinary()
		must(err)
		skb, err := sk.MarshalBinary()
		must(err)

		circl := circlschemes.ByName(name)
		cpk, err := circl.UnmarshalBinaryPublicKey(pkb)
		must(err)
		eseed := deterministicBytes("mceliece_encapsulation_seed", name, circl.EncapsulationSeedSize())
		ct, ss, err := circl.EncapsulateDeterministically(cpk, eseed)
		must(err)
		ss2, err := scheme.Decapsulate(sk, ct)
		must(err)
		if hex.EncodeToString(ss) != hex.EncodeToString(ss2) {
			panic("mceliece vector " + name + ": decapsulation mismatch")
		}
		vs = append(vs, mcelieceVector{
			Name:             name,
			Scheme:           name,
			SeedHex:          hex.EncodeToString(seed),
			PublicKeySHA256:  sha256Hex(pkb),
			PrivateKeySHA256: sha256Hex(skb),
			CiphertextHex:    hex.EncodeToString(ct),
			SharedSecretHex:  hex.EncodeToString(ss),
		})
	}
	return vectorFile{
		FormatVersion: formatVersion,
		Generator:     generatorName,
		Primitive:     "mceliece",
		Description: "Classic McEliece key derivation, encodings and decapsulation. The keys are " +
			"kem.Scheme.DeriveKeyPair(seed) of the named scheme, encoded with MarshalBinary; the " +
			"public and private keys are recorded as SHA-256 digests of those encodings because " +
			"they are large. The ciphertext and shared secret come from circl's " +
			"EncapsulateDeterministically with a fixed encapsulation seed. Vectors are deterministic.",
		Vectors: vs,
	}
}
