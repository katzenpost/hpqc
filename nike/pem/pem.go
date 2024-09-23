// SPDX-FileCopyrightText: Copyright (c) 2023-2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pem

import (
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/util"
)

func ToPublicPEMString(key nike.PublicKey, scheme nike.Scheme) string {
	return string(ToPublicPEMBytes(key, scheme))
}

func ToPublicPEMBytes(key nike.PublicKey, scheme nike.Scheme) []byte {
	keyType := fmt.Sprintf("%s PUBLIC KEY", strings.ToUpper(scheme.Name()))
	blob, err := key.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if util.CtIsZero(blob) {
		panic(fmt.Sprintf("ToPEMString/%s: attempted to serialize scrubbed key", keyType))
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: blob,
	}
	return pem.EncodeToMemory(blk)
}

func PublicKeyToFile(f string, key nike.PublicKey, scheme nike.Scheme) error {
	out, err := os.OpenFile(f, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	outBuf := ToPublicPEMBytes(key, scheme)
	writeCount, err := out.Write(outBuf)
	if err != nil {
		return err
	}
	if writeCount != len(outBuf) {
		return errors.New("partial write failure")
	}
	err = out.Sync()
	if err != nil {
		return err
	}
	return out.Close()
}

func FromPublicPEMString(s string, scheme nike.Scheme) (nike.PublicKey, error) {
	return FromPublicPEMBytes([]byte(s), scheme)
}

func FromPublicPEMBytes(b []byte, scheme nike.Scheme) (nike.PublicKey, error) {
	keyType := fmt.Sprintf("%s PUBLIC KEY", strings.ToUpper(scheme.Name()))
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("failed to decode PEM data from %s PEM", keyType)
	}
	if strings.ToUpper(blk.Type) != keyType {
		return nil, fmt.Errorf("attempted to decode PEM file with wrong key type %v != %v", blk.Type, keyType)
	}
	return scheme.UnmarshalBinaryPublicKey(blk.Bytes)
}

func FromPublicPEMToBytes(b []byte, scheme nike.Scheme) ([]byte, error) {
	keyType := fmt.Sprintf("%s PUBLIC KEY", strings.ToUpper(scheme.Name()))
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("failed to decode PEM data from %s PEM", keyType)
	}
	if strings.ToUpper(blk.Type) != keyType {
		return nil, fmt.Errorf("attempted to decode PEM file with wrong key type %v != %v", blk.Type, keyType)
	}
	return blk.Bytes, nil
}

func FromPublicPEMFile(f string, scheme nike.Scheme) (nike.PublicKey, error) {
	buf, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("pem.FromFile error: %s", err)
	}
	return FromPublicPEMBytes(buf, scheme)
}

// private key

func ToPrivatePEMString(key nike.PrivateKey, scheme nike.Scheme) string {
	return string(ToPrivatePEMBytes(key, scheme))
}

func ToPrivatePEMBytes(key nike.PrivateKey, scheme nike.Scheme) []byte {
	keyType := fmt.Sprintf("%s PRIVATE KEY", strings.ToUpper(scheme.Name()))
	blob, err := key.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if util.CtIsZero(blob) {
		panic(fmt.Sprintf("ToPEMString/%s: attempted to serialize scrubbed key", keyType))
	}
	blk := &pem.Block{
		Type:  keyType,
		Bytes: blob,
	}
	return pem.EncodeToMemory(blk)
}

func PrivateKeyToFile(f string, key nike.PrivateKey, scheme nike.Scheme) error {
	out, err := os.OpenFile(f, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	outBuf := ToPrivatePEMBytes(key, scheme)
	writeCount, err := out.Write(outBuf)
	if err != nil {
		return err
	}
	if writeCount != len(outBuf) {
		return errors.New("partial write failure")
	}
	err = out.Sync()
	if err != nil {
		return err
	}
	return out.Close()
}

func FromPrivatePEMString(s string, scheme nike.Scheme) (nike.PrivateKey, error) {
	return FromPrivatePEMBytes([]byte(s), scheme)
}

func FromPrivatePEMBytes(b []byte, scheme nike.Scheme) (nike.PrivateKey, error) {
	keyType := fmt.Sprintf("%s PRIVATE KEY", strings.ToUpper(scheme.Name()))
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("failed to decode PEM data from %s PEM", keyType)
	}
	if strings.ToUpper(blk.Type) != keyType {
		return nil, fmt.Errorf("attempted to decode PEM file with wrong key type %v != %v", blk.Type, keyType)
	}
	return scheme.UnmarshalBinaryPrivateKey(blk.Bytes)
}

func FromPrivatePEMFile(f string, scheme nike.Scheme) (nike.PrivateKey, error) {
	buf, err := os.ReadFile(f)
	if err != nil {
		return nil, fmt.Errorf("pem.FromFile error: %s", err)
	}
	return FromPrivatePEMBytes(buf, scheme)
}
