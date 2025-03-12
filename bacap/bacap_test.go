// SPDX-FileCopyrightText: © 2025 Katzenpost dev team
// SPDX-License-Identifier: AGPL-3.0-only

package bacap

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/util"
)

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

	owner, err := NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)

	blob, err := owner.MarshalBinary()
	require.NoError(t, err)
	owner2, _ := NewBoxOwnerCap(rand.Reader)
	err = owner2.UnmarshalBinary(blob)
	require.NoError(t, err)

	uread := owner.UniversalReadCap()
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

	owner, err := NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)
	uread := owner.UniversalReadCap()
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

	owner, err := NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)
	uread := owner.UniversalReadCap()

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
	owner, err := NewBoxOwnerCap(rand.Reader)
	require.NoError(t, err)

	uread := owner.UniversalReadCap()

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
		require.Equal(t, expectedBoxID.Bytes(), boxID[:])

		// Reader decrypts the received message
		sig := [64]byte{}
		copy(sig[:], sigraw)
		plaintext, err := reader.DecryptNext(ctx, boxID, ciphertext, sig)
		require.NoError(t, err)
		require.Equal(t, msg, plaintext)
	}
}
