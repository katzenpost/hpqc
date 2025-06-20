// SPDX-FileCopyrightText: © 2025 Katzenpost dev team
// SPDX-License-Identifier: AGPL-3.0-only

package bacap

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/util"
)

func TestMarshalUnmarshalStatefulReader(t *testing.T) {
	t.Parallel()

	ctx := []byte("test-session")
	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)

	uread := owner.ReadCap()

	reader, err := NewStatefulReader(uread, ctx)
	require.NoError(t, err)

	blob, err := reader.Marshal()
	require.NoError(t, err)

	reader2, err := NewStatefulReaderFromBytes(blob)
	require.NoError(t, err)

	require.Equal(t, reader, reader2)
}

func TestMarshalUnmarshalStatefulWriter(t *testing.T) {
	t.Parallel()

	ctx := []byte("test-session")
	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)

	writer, err := NewStatefulWriter(owner, ctx)
	require.NoError(t, err)

	blob, err := writer.Marshal()
	require.NoError(t, err)

	writer2, err := NewStatefulWriterFromBytes(blob)
	require.NoError(t, err)

	require.Equal(t, writer, writer2)
}

// Check that advancing mailbox states:
// - increment Idx by 1
// - changes CurBlindingFactor
// - changes HKDFState
// - advancing the same independently produces the same new state (hoping to detect accidental mutation)
func TestAdvanceIndex(t *testing.T) {
	t.Parallel()

	mb_r, err := NewMessageBoxIndex(rand.Reader)
	require.NoError(t, err)

	blob, err := mb_r.MarshalBinary()
	require.NoError(t, err)

	mb_r2, _ := NewMessageBoxIndex(rand.Reader)
	err = mb_r2.UnmarshalBinary(blob)
	require.NoError(t, err)

	mb_1a, err := mb_r.NextIndex()
	require.NoError(t, err)
	mb_1b, err := mb_r.NextIndex()
	require.NoError(t, err)
	require.Equal(t, mb_1a, mb_1b)
	require.Equal(t, 1+mb_r.Idx64, mb_1a.Idx64)
	require.NotEqual(t, mb_r.CurBlindingFactor, mb_1b.CurBlindingFactor)
	require.NotEqual(t, mb_r.HKDFState, mb_1b.HKDFState)

	mb_2a, err := mb_1a.NextIndex()
	require.NoError(t, err)
	mb_2b, err := mb_1b.NextIndex()
	require.NoError(t, err)
	require.Equal(t, mb_2a, mb_2b)
	require.NotEqual(t, mb_1a, mb_2a)
	require.NotEqual(t, mb_1a, mb_2b)
	require.Equal(t, 1+mb_1a.Idx64, mb_2a.Idx64)
	require.NotEqual(t, mb_1a.CurBlindingFactor[:], mb_2b.CurBlindingFactor[:])
	require.NotEqual(t, mb_1a.HKDFState[:], mb_2b.HKDFState[:])

	require.Equal(t, 2+mb_r.Idx64, mb_2a.Idx64)
	mb_1c, err := mb_r.NextIndex()
	require.NoError(t, err)
	require.Equal(t, mb_1c, mb_1a)
	mb_2c, err := mb_1c.NextIndex()
	require.NoError(t, err)
	require.Equal(t, mb_2c, mb_2a)
	require.Equal(t, 1+mb_r.Idx64, mb_1c.Idx64)
	require.Equal(t, 2+mb_r.Idx64, mb_2c.Idx64)

	mb_2c_plus_0, err := mb_2c.AdvanceIndexTo(mb_2c.Idx64)
	require.NoError(t, err)
	require.Equal(t, mb_2c, mb_2c_plus_0)

	mb_cur := mb_r
	// 45: sum(i) for i = 0..10
	mb_adv, err := mb_cur.AdvanceIndexTo(mb_cur.Idx64 + uint64(45))
	require.NoError(t, err)
	// x := 0 exercises AdvanceIndexTo as a no-op and that we can proceed from there:
	for x := 0; x < 10; x += 1 {
		mb_step, err := mb_cur.AdvanceIndexTo(mb_cur.Idx64 + uint64(x))
		require.NoError(t, err)
		for y := 0; y < x; y += 1 {
			var err error
			mb_cur, err = mb_cur.NextIndex()
			require.NoError(t, err)
		}
		require.Equal(t, mb_step, mb_cur)
	}
	require.Equal(t, mb_adv, mb_cur)

	// rewind prohibited and should cause an error
	_, err = mb_2c.AdvanceIndexTo(mb_2c.Idx64 - 1)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot rewind index")

	// check that NextIndex is the same as AdvanceIndexTo with +1
	mb_single_step, err := mb_r.AdvanceIndexTo(mb_r.Idx64 + 1)
	require.NoError(t, err)
	mb_manual, err := mb_r.NextIndex()
	require.NoError(t, err)
	require.Equal(t, mb_single_step, mb_manual)
}

func TestReadCap(t *testing.T) {
	t.Parallel()

	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)

	blob, err := owner.MarshalBinary()
	require.NoError(t, err)
	owner2, _ := NewWriteCap(rand.Reader)
	err = owner2.UnmarshalBinary(blob)
	require.NoError(t, err)

	uread := owner.ReadCap()

	blob, err = uread.MarshalBinary()
	require.NoError(t, err)
	_, err = ReadCapFromBytes(blob)
	require.NoError(t, err)

	require.Equal(t, owner.firstMessageBoxIndex.Idx64, uread.firstMessageBoxIndex.Idx64)
	require.Equal(t, owner.rootPublicKey, uread.rootPublicKey)

	mb1 := uread.firstMessageBoxIndex
	mb2, err := mb1.NextIndex()
	require.NoError(t, err)
	mb2_id := mb2.DeriveMessageBoxID(uread.rootPublicKey)
	require.False(t, util.CtIsZero(mb2_id.Bytes()))
}

func TestMake1000(t *testing.T) {
	t.Parallel()

	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	uread := owner.ReadCap()
	mb_cur := uread.firstMessageBoxIndex
	for i := 0; i < 1000; i++ {
		mb_cur, err = mb_cur.NextIndex()
		require.NoError(t, err)
		mb2_id := mb_cur.DeriveMessageBoxID(uread.rootPublicKey)
		require.False(t, util.CtIsZero(mb2_id.Bytes()))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	t.Parallel()

	ctx1 := []byte("ctx1")
	ctx2 := []byte("ctx2")

	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	uread := owner.ReadCap()

	boxCurrent := uread.firstMessageBoxIndex
	for i := 0; i < 3; i++ {
		boxCurrent, err = boxCurrent.NextIndex()
		require.NoError(t, err)

		boxDerived := boxCurrent.BoxIDForContext(uread, ctx1)

		// encrypt a new message:
		msg := []byte(fmt.Sprintf("message %d", i))
		box, ciphertext1, sig1 := boxCurrent.EncryptForContext(owner, ctx1, msg)
		require.Equal(t, boxDerived.Bytes(), box[:])
		require.NotEqual(t, msg, ciphertext1)

		// decrypt the BACAP message
		plaintext1, err := boxCurrent.DecryptForContext(box, ctx1, ciphertext1, sig1)
		require.Equal(t, nil, err)
		require.Equal(t, msg, plaintext1)

		// wrong cryptographic context
		plaintext2, err := boxCurrent.DecryptForContext(box, ctx2, ciphertext1, sig1)
		require.Error(t, err)
		require.NotEqual(t, msg, plaintext2)

		// corrupt signature
		_, err = boxCurrent.DecryptForContext(box, ctx1, ciphertext1, sig1[:len(sig1)-1])
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature verification failed")
	}
}

func TestStatefulReaderWriter(t *testing.T) {
	t.Parallel()

	ctx := []byte("test-session")
	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)

	uread := owner.ReadCap()

	writer, err := NewStatefulWriter(owner, ctx)
	require.NoError(t, err)

	reader, err := NewStatefulReader(uread, ctx)
	require.NoError(t, err)

	// Encrypt and decrypt n messages sequentially
	n := 40
	for i := 0; i < n; i++ {
		msg := []byte(fmt.Sprintf("message %d", i))

		// Writer encrypts the next message

		// writer prepares given box ID for writing
		box, err := writer.NextBoxID()
		require.NoError(t, err)
		require.NotNil(t, box)

		boxID, ciphertext, sigraw, err := writer.EncryptNext(msg)
		require.NoError(t, err)

		// Reader retrieves the next expected box ID
		expectedBoxID, err := reader.NextBoxID()
		require.NoError(t, err)
		require.Equal(t, expectedBoxID[:], boxID[:])

		// Reader decrypts the received message
		sig := [64]byte{}
		copy(sig[:], sigraw)
		plaintext, err := reader.DecryptNext(ctx, boxID, ciphertext, sig)
		require.NoError(t, err)
		require.Equal(t, msg, plaintext)
	}
}

// badRNG simulates an RNG that fails after a specified number of reads.
type badRNG struct {
	failAfter int
	readCount int
}

func (b *badRNG) Read(p []byte) (int, error) {
	if b.readCount >= b.failAfter {
		return 0, errors.New("forced read error")
	}
	b.readCount++
	for i := range p {
		p[i] = 0xFF
	}
	return len(p), nil
}

// catchPanic runs f and recovers from panics, returning any recovered error.
func catchPanic(f func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("panic occurred")
		}
	}()
	f()
	return nil
}

func TestNewMessageBoxIndexFailures(t *testing.T) {
	t.Parallel()

	// Fail on HKDFState read (expect panic)
	rng := &badRNG{failAfter: 0}
	err := catchPanic(func() { _, _ = NewMessageBoxIndex(rng) })
	require.Error(t, err, "expected panic when rng fails on HKDFState")

	// Fail on idx64B read (expect panic)
	rng = &badRNG{failAfter: 1}
	err = catchPanic(func() { _, _ = NewMessageBoxIndex(rng) })
	require.Error(t, err, "expected panic when rng fails on idx64B")
}

func TestMessageBoxIndexUnmarshalBinaryFailures(t *testing.T) {
	t.Parallel()

	var m MessageBoxIndex

	// Invalid size
	err := m.UnmarshalBinary([]byte{})
	require.Error(t, err)
	require.Contains(t, err.Error(), errInvalidMessageBoxIndexBinarySize)
}

func TestBoxOwnerCapUnmarshalBinaryFailures(t *testing.T) {
	t.Parallel()

	var o WriteCap

	// Invalid size
	err := o.UnmarshalBinary([]byte{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid BoxOwnerCap binary size")
}

func TestReadCapUnmarshalBinaryFailures(t *testing.T) {
	t.Parallel()

	var u ReadCap

	// Invalid size
	err := u.UnmarshalBinary([]byte{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid ReadCap binary size")
}

func TestMessageBoxIndexAdvanceIndexToFailures(t *testing.T) {
	t.Parallel()

	m := MessageBoxIndex{Idx64: 10}

	// Rewinding index should fail
	_, err := m.AdvanceIndexTo(5)
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot rewind index")
}

func TestMessageBoxIndexDeriveMessageBoxIDFailures(t *testing.T) {
	t.Parallel()

	var m MessageBoxIndex
	var pk ed25519.PublicKey

	// Catch panic when calling DeriveMessageBoxID with an uninitialized public key
	err := catchPanic(func() { _ = m.DeriveMessageBoxID(&pk) })
	require.Error(t, err, "expected panic when calling DeriveMessageBoxID with an uninitialized public key")
}

func TestStatefulReaderFailures(t *testing.T) {
	t.Parallel()

	ownercap, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)
	urcap := ownercap.ReadCap()

	// Missing context
	_, err = NewStatefulReader(urcap, nil)
	require.Error(t, err, "expected error when initializing StatefulReader with nil context")

	reader, _ := NewStatefulReader(urcap, []byte("test"))

	reader.Ctx = nil
	_, err = reader.NextBoxID()
	require.Error(t, err, "expected error when ctx is nil")

	// Empty box
	_, err = reader.DecryptNext([]byte("test"), [32]byte{}, []byte("ciphertext"), [64]byte{})
	require.Error(t, err, "expected error when attempting to decrypt empty box")
}

func TestStatefulWriterFailures(t *testing.T) {
	t.Parallel()

	owner := &WriteCap{
		rootPrivateKey:       new(ed25519.PrivateKey),
		rootPublicKey:        new(ed25519.PublicKey),
		firstMessageBoxIndex: &MessageBoxIndex{},
	}

	// Missing context
	_, err := NewStatefulWriter(owner, nil)
	require.Error(t, err, "expected error when initializing StatefulWriter with nil context")

	writer, _ := NewStatefulWriter(owner, []byte("test"))

	// Missing nextIndex
	writer.NextIndex = nil
	_, err = writer.NextBoxID()
	require.Error(t, err, "expected error when nextIndex is nil")

	// Encrypt with nil nextIndex
	writer.NextIndex = nil
	_, _, _, err = writer.EncryptNext([]byte("message"))
	require.Error(t, err, "expected error when nextIndex is nil during EncryptNext")
}

func TestStatefulWriterNextBoxIDFailures(t *testing.T) {
	t.Parallel()

	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)

	// Test case: NextBoxID fails when nextIndex is nil
	writer, err := NewStatefulWriter(owner, []byte("test"))
	require.NoError(t, err)

	writer.Ctx = nil
	_, err = writer.NextBoxID()
	require.Error(t, err)

	writer.NextIndex = nil

	_, err = writer.NextBoxID()
	require.Error(t, err)
	require.Contains(t, err.Error(), errNextIndexIsNil)

	writer.Ctx = nil
	_, err = writer.NextBoxID()
	require.Error(t, err)

	// Test case: NextBoxID fails when ctx is nil
	_, err = NewStatefulWriter(owner, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "ctx is nil")
}

func TestStatefulWriterEncryptNextFailures(t *testing.T) {
	t.Parallel()

	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)

	// Test case: EncryptNext fails when nextIndex is nil
	writer, err := NewStatefulWriter(owner, []byte("test"))
	require.NoError(t, err)
	writer.NextIndex = nil

	_, _, _, err = writer.EncryptNext([]byte("message"))
	require.Error(t, err)
	require.Contains(t, err.Error(), errNextIndexIsNil)

	// Test case: EncryptNext fails when advancing state fails
	writer, err = NewStatefulWriter(owner, []byte("test"))
	require.NoError(t, err)

	// Simulate failure in NextIndex
	writer.NextIndex = &MessageBoxIndex{Idx64: ^uint64(0)} // Max uint64, next would overflow
	_, _, _, err = writer.EncryptNext([]byte("message"))
	require.Error(t, err)
}

func TestStatefulReaderDecryptNextFailures(t *testing.T) {
	t.Parallel()

	ctx := []byte("test-session")
	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)

	uread := owner.ReadCap()
	reader, err := NewStatefulReader(uread, ctx)
	require.NoError(t, err)

	// Generate a valid box ID for comparison
	validBoxID := reader.NextIndex.BoxIDForContext(uread, ctx)
	require.NotNil(t, validBoxID)

	// Mock encrypted message and signature
	ciphertext := []byte("ciphertext")
	sig := [64]byte{}

	// Failure case: Empty box
	_, err = reader.DecryptNext(ctx, [32]byte{}, ciphertext, sig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty box, no message received")

	// Failure case: nextIndex is nil
	reader.NextIndex = nil
	_, err = reader.DecryptNext(ctx, [32]byte(validBoxID.Bytes()), ciphertext, sig)
	require.Error(t, err)
	require.Contains(t, err.Error(), errNextIndexIsNilCannotParseReply)

	// Restore nextIndex for further tests
	reader, err = NewStatefulReader(uread, ctx)
	require.NoError(t, err)

	// Failure case: Box ID mismatch
	wrongBox := [32]byte{}
	copy(wrongBox[:], bytes.Repeat([]byte{0x01}, 32)) // Simulate a different box ID
	_, err = reader.DecryptNext(ctx, wrongBox, ciphertext, sig)
	require.Error(t, err)
	require.Contains(t, err.Error(), "reply does not match expected box ID")

	// Failure case: DecryptForContext fails (simulated)
	_, err = reader.DecryptNext([]byte("wrong-context"), [32]byte(validBoxID.Bytes()), ciphertext, sig)
	require.Error(t, err)

	// Failure case: NextIndex fails (simulate max uint64 overflow)
	reader.NextIndex.Idx64 = ^uint64(0) // Max uint64, next will overflow
	_, err = reader.DecryptNext(ctx, [32]byte(validBoxID.Bytes()), ciphertext, sig)
	require.Error(t, err)
}

func TestStatefulReaderNextBoxIDFailureNextIndex(t *testing.T) {
	t.Parallel()

	ctx := []byte("test-session")
	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)

	uread := owner.ReadCap()
	reader, err := NewStatefulReader(uread, ctx)
	require.NoError(t, err)

	// Simulate failure in NextIndex
	reader.LastInboxRead.Idx64 = ^uint64(0) // Max uint64, next would overflow

	reader.NextIndex = nil
	_, err = reader.NextBoxID()
	require.Error(t, err)
}

func TestReadCapFromBytesFailures(t *testing.T) {
	t.Parallel()

	// Failure case: Input data is too short
	_, err := ReadCapFromBytes([]byte{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid ReadCap binary size")
}

func TestNewEmptyMessageBoxIndexFromBytesErrorHandling(t *testing.T) {
	t.Parallel()

	// Test successful case
	validIndex := NewEmptyMessageBoxIndex()
	validIndex.Idx64 = 42
	validIndex.CurBlindingFactor = [32]byte{1, 2, 3}
	validIndex.CurEncryptionKey = [32]byte{4, 5, 6}
	validIndex.HKDFState = [32]byte{7, 8, 9}

	data, err := validIndex.MarshalBinary()
	require.NoError(t, err)

	result, err := NewEmptyMessageBoxIndexFromBytes(data)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, validIndex.Idx64, result.Idx64)
	require.Equal(t, validIndex.CurBlindingFactor, result.CurBlindingFactor)
	require.Equal(t, validIndex.CurEncryptionKey, result.CurEncryptionKey)
	require.Equal(t, validIndex.HKDFState, result.HKDFState)

	// Test error case: invalid data size
	_, err = NewEmptyMessageBoxIndexFromBytes([]byte{1, 2, 3})
	require.Error(t, err)
	require.Contains(t, err.Error(), errInvalidMessageBoxIndexBinarySize)

	// Test error case: empty data
	_, err = NewEmptyMessageBoxIndexFromBytes([]byte{})
	require.Error(t, err)
	require.Contains(t, err.Error(), errInvalidMessageBoxIndexBinarySize)

	// Test error case: nil data
	_, err = NewEmptyMessageBoxIndexFromBytes(nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), errInvalidMessageBoxIndexBinarySize)
}

func TestNewStatefulReaderWithIndexStateConsistency(t *testing.T) {
	t.Parallel()

	ctx := []byte("test-session")
	owner, err := NewWriteCap(rand.Reader)
	require.NoError(t, err)

	uread := owner.ReadCap()

	// Create a specific index to start from (advance from the first index)
	startIndex, err := uread.firstMessageBoxIndex.NextIndex()
	require.NoError(t, err)
	startIndex, err = startIndex.NextIndex()
	require.NoError(t, err)

	// Create reader with specific index
	reader, err := NewStatefulReaderWithIndex(uread, ctx, startIndex)
	require.NoError(t, err)

	// Verify NextBoxID works correctly even with nil LastInboxRead
	boxID, err := reader.NextBoxID()
	require.NoError(t, err)
	require.NotNil(t, boxID)

	// This is the intended behavior: LastInboxRead is nil because this reader instance
	// has no history of previously read messages. It's starting fresh from the given index.
	// This is semantically correct for resuming from a checkpoint.
	require.Nil(t, reader.LastInboxRead)
	require.NotNil(t, reader.NextIndex)
	// Verify the index is what we expect (original + 2)
	require.Equal(t, uread.firstMessageBoxIndex.Idx64+2, reader.NextIndex.Idx64)

	// Verify that after reading a message, LastInboxRead gets properly set
	// First, let's create a writer to generate a message
	writer, err := NewStatefulWriter(owner, ctx)
	require.NoError(t, err)

	// Advance writer to the same index as our reader
	for writer.NextIndex.Idx64 < reader.NextIndex.Idx64 {
		err = writer.AdvanceState()
		require.NoError(t, err)
	}

	// Generate a message
	plaintext := []byte("test message")
	boxID2, ciphertext, sig, err := writer.EncryptNext(plaintext)
	require.NoError(t, err)

	// Now decrypt with our reader
	var sigArray [SignatureSize]byte
	copy(sigArray[:], sig)
	decrypted, err := reader.DecryptNext(ctx, boxID2, ciphertext, sigArray)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	// After successful decryption, LastInboxRead should now be set
	require.NotNil(t, reader.LastInboxRead)
	require.Equal(t, startIndex.Idx64, reader.LastInboxRead.Idx64)
}
