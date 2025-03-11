// SPDX-FileCopyrightText: © 2025 Katzenpost dev team
// SPDX-License-Identifier: AGPL-3.0-only

package bacap

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/util"
)

// Check that advancing mailbox states:
// - increment Idx by 1
// - changes CurBlindingFactor
// - changes HKDFState
// - advancing the same independently produces the same new state (hoping to detect accidental mutation)
func TestAdvanceIndex(t *testing.T) {
	t.Parallel()
	test_seed := time.Now().UnixNano()
	t.Log("TestAdvanceIndex test_seed", test_seed)
	rng := rand.New(rand.NewSource(test_seed))

	mb_r, err := NewMailboxIndex(rng)
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
}

func TestReadCap(t *testing.T) {
	t.Parallel()
	test_seed := time.Now().UnixNano()
	t.Log("TestReadCap test_seed", test_seed)
	rng := rand.New(rand.NewSource(test_seed))

	owner, err := NewOwner(rng)
	require.NoError(t, err)
	uread := owner.NewUniversalReadCap()
	require.Equal(t, owner.firstMailboxIndex.Idx64, uread.firstMailboxIndex.Idx64)
	require.Equal(t, owner.rootPublicKey, uread.rootPublicKey)

	mb1 := uread.firstMailboxIndex
	mb2, err := mb1.NextIndex()
	require.NoError(t, err)
	mb2_id := mb2.DeriveMailboxID(uread.rootPublicKey)
	require.False(t, util.CtIsZero(mb2_id.Bytes()))
}

func TestMake1000(t *testing.T) {
	t.Parallel()
	test_seed := time.Now().UnixNano()
	t.Log("TestReadCap test_seed", test_seed)
	rng := rand.New(rand.NewSource(test_seed))

	owner, err := NewOwner(rng)
	require.NoError(t, err)
	uread := owner.NewUniversalReadCap()
	mb_cur := uread.firstMailboxIndex
	for i := 0; i < 1000; i++ {
		mb_cur, err = mb_cur.NextIndex()
		require.NoError(t, err)
		mb2_id := mb_cur.DeriveMailboxID(uread.rootPublicKey)
		require.False(t, util.CtIsZero(mb2_id.Bytes()))
	}
}

func TestEncryptDecrypt(t *testing.T) {
	t.Parallel()
	test_seed := time.Now().UnixNano()
	rng := rand.New(rand.NewSource(test_seed))

	ctx1 := []byte("ctx1")

	owner, err := NewOwner(rng)
	require.NoError(t, err)
	uread := owner.NewUniversalReadCap()

	boxCurrent := uread.firstMailboxIndex
	for i := 0; i < 1000; i++ {
		boxCurrent, err = boxCurrent.NextIndex()
		require.NoError(t, err)

		boxDerived := boxCurrent.BoxIDForContext(uread, ctx1)

		// Encrypt a new message:
		msg := []byte(fmt.Sprintf("message %d", i))
		box, ciphertext1, sig1 := boxCurrent.EncryptForContext(owner, ctx1, msg)
		require.Equal(t, boxDerived.Bytes(), box[:])
		require.NotEqual(t, msg, ciphertext1)

		// Now we attempt to decrypt the BACAP message:
		plaintext1, err := boxCurrent.DecryptForContext(box, ctx1, ciphertext1, sig1)
		require.Equal(t, nil, err)
		require.Equal(t, msg, plaintext1)
	}

}
