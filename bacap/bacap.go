// SPDX-FileCopyrightText: © 2025 Threebit Hacker
// SPDX-License-Identifier: AGPL-3.0-only

// Package bacap provides the Blinded Cryptographic Capability system (BACAP).
//
// BACAP is the Blinded Cryptographic Capability system with
// some resistance against quantum adversaries whose design
// is expounded upon in section 4 of our paper:
//
//	BACAP (Blinding-and-Capability scheme) allows us
//	to deterministically derive a sequence of key pairs using
//	blinding, built upon Ed25519, and suitable for un-
//	linkable messaging. It enables participants to derive box
//	IDs and corresponding encryption keys for independent,
//	single-use boxes using shared symmetric keys.
//
//	A box consists of an ID, a message payload, and a
//	signature over the payload. There are two basic capabili-
//	ties - one that lets a party derive the box IDs and decrypt
//	the messages, and one that additionally lets the holder
//	derive private keys to sign the messages. The signatures
//	are universally veriﬁable, as the box ID for each box
//	doubles as the public key for the signatures.
//
//	In the context of a messaging system, the protocol is
//	used by Alice to send an inﬁnite sequence of messages
//	to Bob, one per box, with Bob using a separate, second
//	instance of the protocol to send messages to Alice.
//
// # Our paper
//
// Echomix: a Strong Anonymity System with Messaging
//
// https://arxiv.org/abs/2501.02933
// https://arxiv.org/pdf/2501.02933
//
// # API Design
//
// Two Capability types:
//
// 1. ReadCap: The Read Capability allows the bearer
// to generate an infinite sequence of verification and decryption keys
// for message boxes in a deterministic sequence.
//
// 2. WriteCap: The Write Capability allows the bearer to
// generate an infinite sequence of signing and encryption keys for
// messages boxes in a deterministic sequence.
//
// Each of the above two capabilities are used with the MessageBoxIndex
// to perform their respective encrypt and sign vs verify and decrypt operations.
//
// Beyond that we have two high-level types: StatefulReader and StatefulWriter,
// which encapsulate all the operational details of advancing state
// after message processing.
//
// # TODOs
//
// This BACAP implementation could possibly be improved, here's a ticket for
// completing the TODO tasks written by its original author:
//
// https://github.com/katzenpost/hpqc/issues/55
package bacap

import (
	"bytes"
	"encoding/binary"

	"github.com/katzenpost/hpqc/sign/ed25519"
)

const (
	// MessageBoxIndexSize is the size in bytes of one MessageBoxIndex struct.
	MessageBoxIndexSize = 8 + 32 + 32 + 32

	// BoxIDSize is the size in bytes of our Box IDs.
	BoxIDSize = ed25519.PublicKeySize

	// SignatureSize is the size in bytes of our signatures.
	SignatureSize = ed25519.SignatureSize

	// Error message constants
	errNextIndexIsNil                   = "next index is nil"
	errNextIndexIsNilCannotParseReply   = "next index is nil, cannot parse reply"
	errInvalidMessageBoxIndexBinarySize = "invalid MessageBoxIndex binary size"

	// mutateKDFStateLabel is the HKDF info (domain-separation) label used by
	// MutateKDFState. It keeps a re-seeded ratchet state from ever colliding
	// with a state produced by ordinary chain advancement (which uses an empty
	// salt and the index as info).
	mutateKDFStateLabel = "bacap-mutate-kdf-state-v1"
)

// MessageBoxIndex type encapsulates all the various low level cryptographic operations
// such as progressing the HKDF hash object states, encryption/decryption
// of messages, signing and verifying messages.
type MessageBoxIndex struct {
	// i_{0..2^64}: the message counter / index
	Idx64 uint64

	// K_i: blinding value used to derive mailboxID by blinding ed25519 keys
	CurBlindingFactor [32]byte

	// E_i: for encryption message payloads
	CurEncryptionKey [32]byte

	// H_{i+1}, the HKDF key used to calculate MessageBoxIndex for Idx61 + 1
	HKDFState [32]byte // H_i, for computing the next mailbox
}

// ReadCap is a read capability can be used to compute BACAP boxes
// and decrypt their message payloads for indices >= messageBoxIndex
type ReadCap struct {
	rootPublicKey *ed25519.PublicKey

	messageBoxIndex *MessageBoxIndex
}

// ReadCapSize is the size in bytes of the ReadCap struct type.
const ReadCapSize = ed25519.PublicKeySize + MessageBoxIndexSize

// WriteCap is used by the creator of the message box. It encapsulates
// private key material.
type WriteCap struct {
	// on-disk:
	rootPrivateKey *ed25519.PrivateKey

	// in-memory only:
	rootPublicKey *ed25519.PublicKey

	messageBoxIndex *MessageBoxIndex
}

// WriteCapSize is the size in bytes of a serialized BoxOwnerCap
// not counting it's rootPublicKey field.
const WriteCapSize = ed25519.PrivateKeySize + MessageBoxIndexSize

// MarshalBinary returns a binary blob of the BoxOwnerCap type.
// Only serialize the rootPrivateKey. We do not serialize the rootPublicKey
// because it can be derived from the private key.
func (o *WriteCap) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.Write(o.rootPrivateKey.Bytes()); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, o.messageBoxIndex); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
