package bacap

import (
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
	"time"
	// "encoding/hex"
	// "fmt"
	//
	//	"github.com/stretchr/testify/require"
)

// Check that advancing mailbox states:
// - increment Idx by 1
// - changes CurBlindingFactor
// - changes HKDFState
// - advancing the same independently produces the same new state (hoping to detect accidental mutation)
func TestAdvanceIndex(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	test_seed := time.Now().UnixNano()
	t.Log("TestAdvanceIndex test_seed", test_seed)
	rng := rand.New(rand.NewSource(test_seed))

	mb_r := NewMailboxIndex(rng)
	mb_1a := mb_r.NextIndex()
	mb_1b := mb_r.NextIndex()
	assert.Equal(mb_1a, mb_1b)
	assert.Equal(1+mb_r.Idx64, mb_1a.Idx64)
	assert.NotEqual(mb_r.CurBlindingFactor, mb_1b.CurBlindingFactor)
	assert.NotEqual(mb_r.HKDFState, mb_1b.HKDFState)

	mb_2a := mb_1a.NextIndex()
	mb_2b := mb_1b.NextIndex()
	assert.Equal(mb_2a, mb_2b)
	assert.NotEqual(mb_1a, mb_2a)
	assert.NotEqual(mb_1a, mb_2b)
	assert.Equal(1+mb_1a.Idx64, mb_2a.Idx64)
	assert.NotEqual(mb_1a.CurBlindingFactor[:], mb_2b.CurBlindingFactor[:])
	assert.NotEqual(mb_1a.HKDFState[:], mb_2b.HKDFState[:])

	assert.Equal(2+mb_r.Idx64, mb_2a.Idx64)
	mb_1c := mb_r.NextIndex()
	assert.Equal(mb_1c, mb_1a)
	mb_2c := mb_1c.NextIndex()
	assert.Equal(mb_2c, mb_2a)
	assert.Equal(1+mb_r.Idx64, mb_1c.Idx64)
	assert.Equal(2+mb_r.Idx64, mb_2c.Idx64)

	mb_2c_plus_0 := mb_2c.AdvanceIndexTo(mb_2c.Idx64)
	assert.Equal(mb_2c, mb_2c_plus_0)

	mb_cur := *mb_r
	// 45: sum(i) for i = 0..10
	mb_adv := mb_cur.AdvanceIndexTo(mb_cur.Idx64 + uint64(45))
	// x := 0 exercises AdvanceIndexTo as a no-op and that we can proceed from there:
	for x := 0; x < 10; x += 1 {
		mb_step := mb_cur.AdvanceIndexTo(mb_cur.Idx64 + uint64(x))
		for y := 0; y < x; y += 1 {
			mb_cur = mb_cur.NextIndex()
		}
		assert.Equal(mb_step, mb_cur)
	}
	assert.Equal(mb_adv, mb_cur)
}

func TestReadCap(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	test_seed := time.Now().UnixNano()
	t.Log("TestReadCap test_seed", test_seed)
	rng := rand.New(rand.NewSource(test_seed))

	msg1 := []byte("abc")
	_ = msg1

	owner := NewOwner(rng)
	uread := owner.NewUniversalReadCap()
	assert.Equal(owner.firstMailboxIndex.Idx64, uread.firstMailboxIndex.Idx64)
	assert.Equal(owner.rootPublicKey, uread.rootPublicKey)
	// These next 3 lines we take a detour to ensure that the blinding works
	// (universal secrets should never be used directly), hence the private
	// key is unexported:
	//u_sig := uread.Sign(msg1)
	//u_read_pk := uread.universalReadSecret.PublicKey()
	//assert.Equal(true, u_read_pk.Verify(u_sig, msg1))

	// We pick a mailbox index:
	mb1 := uread.firstMailboxIndex
	// Reader computes read cap private key:
	//mb1_read_sk := uread.Specialize(mb1)
	// Reader computes mailbox ID:
	//mb1_id := mb1.DeriveMailboxID(&uread.rootPublicKey)
	// Reader signs the read request, excercising the capability:
	//sig1 := mb1_read_sk.Sign(msg1)
	// Unit test: We check that the corresponding public key works:
	//mb1_read_topk := mb1_read_sk.PublicKey()
	//assert.Equal(true, mb1_read_topk.Verify(sig1, msg1))

	// Now Reader uploads to server: mb1_id, sig1, msg1

	// Server derives read cap verifier from the mailbox ID:
	//mb1_read_pk := mb1_id //DeriveCapVerifier(mb1_id, readCapString)
	// Server validates the cap signature:
	//assert.Equal(true, mb1_read_pk.Verify(sig1, msg1))
	// Unit test: Server should have derived same key as we did before:
	//assert.Equal(mb1_read_pk, mb1_read_topk)

	mb2 := mb1.NextIndex()
	mb2_id := mb2.DeriveMailboxID(&uread.rootPublicKey)
	_ = mb2_id
	//mb2_read_sk := uread.Specialize(&mb2)
	//mb2_sig := mb2_read_sk.Sign(msg1)
	//mb2_read_pk := DeriveCapVerifier(mb2_id, readCapString)
	//assert.Equal(true, mb2_read_pk.Verify(mb2_id, msg1))
}

func TestMake1000(t *testing.T) {
	t.Parallel()
	test_seed := time.Now().UnixNano()
	t.Log("TestReadCap test_seed", test_seed)
	rng := rand.New(rand.NewSource(test_seed))

	owner := NewOwner(rng)
	uread := owner.NewUniversalReadCap()
	mb_cur := *uread.firstMailboxIndex
	for i := 0; i < 1000; i++ {
		mb_cur = mb_cur.NextIndex()
		mb2_id := mb_cur.DeriveMailboxID(&uread.rootPublicKey)
		_ = mb2_id
		//fmt.Printf("mailbox:%v:%s\n",mb_cur.Idx64, hex.EncodeToString(mb2_id.Bytes()))
	}
}

func TestEncryptForContext(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	test_seed := time.Now().UnixNano()
	t.Log("TestEncryptForContext test_seed", test_seed)
	rng := rand.New(rand.NewSource(test_seed))

	ctx1 := []byte{'c', 't', 'x', '1'}

	msg1 := []byte("abc")
	_ = msg1

	owner := NewOwner(rng)
	uread := owner.NewUniversalReadCap()
	mbox1 := *uread.firstMailboxIndex
	box_derived := mbox1.BoxIDForContext(uread, ctx1)

	// Encrypt a new message:
	box, ciphertext1, sig1 := mbox1.EncryptForContext(owner, ctx1, msg1)
	assert.Equal(box_derived.Bytes(), box[:])
	assert.NotEqual(msg1, ciphertext1)

	// Now we attempt to decrypt the BACAP message:
	plaintext1, err := mbox1.DecryptForContext(box, ctx1, ciphertext1, sig1)
	assert.Equal(nil, err)
	assert.Equal(msg1, plaintext1)
}
