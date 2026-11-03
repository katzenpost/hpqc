//! BACAP, the Blinding-and-Capability scheme of section 4 of
//! [Echomix](https://arxiv.org/abs/2501.02933), byte compatible with hpqc's
//! Go `bacap` package.
//!
//! A [`WriteCap`] derives an endless sequence of boxes, each with its own
//! blinded Ed25519 key pair and AES-256-GCM-SIV key; its [`ReadCap`] derives
//! the same box IDs and decryption keys but cannot sign. A
//! [`MessageBoxIndex`] is one step in the sequence. Positions
//! ([`ReadPosition`], [`WritePosition`]) pair a capability with an index on
//! its own stream and are the recommended way to read and write boxes.

mod position;

pub use position::{ReadPosition, WritePosition};

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use rand_core::CryptoRng;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::hash::hkdf_blake2b;
use crate::sign::blinded_ed25519::{BlindedSigningKey, blind_verifying_key};
use crate::util::{check_len, ct_is_zero, to_array};
use crate::{Error, Result, SecretBytes};

pub const MESSAGE_BOX_INDEX_SIZE: usize = 8 + 32 + 32 + 32;
pub const BOX_ID_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 64;
pub const READ_CAP_SIZE: usize = 32 + MESSAGE_BOX_INDEX_SIZE;
pub const WRITE_CAP_SIZE: usize = 64 + MESSAGE_BOX_INDEX_SIZE;

/// How many ratchet steps the on-stream check takes at most.
pub const MAX_CONTAINS_WALK: u64 = 1 << 18;

const MUTATE_KDF_STATE_LABEL: &[u8] = b"bacap-mutate-kdf-state-v1";

pub type BoxId = [u8; BOX_ID_SIZE];

/// One box in a BACAP sequence: its 64-bit index, blinding factor,
/// encryption key and the KDF state that derives the next box. Encodes as
/// 104 bytes in that order, the index little-endian. Zeroed on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MessageBoxIndex {
    idx64: u64,
    blinding_factor: [u8; 32],
    encryption_key: [u8; 32],
    hkdf_state: [u8; 32],
}

impl MessageBoxIndex {
    /// A fresh index with a random KDF state, starting one step past a
    /// random point in `[0, 2^63 - 2]` drawn as a sum of two 62-bit halves,
    /// so the first index reveals little about how many came before.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut seed = Self::empty();
        rng.fill_bytes(&mut seed.hkdf_state);
        let mut halves = Zeroizing::new([0u8; 16]);
        rng.fill_bytes(&mut *halves);
        halves[7] &= 0x3f;
        halves[15] &= 0x3f;
        let lo = u64::from_le_bytes(halves[..8].try_into().expect("8 bytes"));
        let hi = u64::from_le_bytes(halves[8..].try_into().expect("8 bytes"));
        seed.idx64 = lo + hi;
        seed.next_index().expect("start is below 2^63")
    }

    fn empty() -> Self {
        Self {
            idx64: 0,
            blinding_factor: [0; 32],
            encryption_key: [0; 32],
            hkdf_state: [0; 32],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_len(bytes, MESSAGE_BOX_INDEX_SIZE)?;
        Ok(Self {
            idx64: u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")),
            blinding_factor: bytes[8..40].try_into().expect("32 bytes"),
            encryption_key: bytes[40..72].try_into().expect("32 bytes"),
            hkdf_state: bytes[72..].try_into().expect("32 bytes"),
        })
    }

    pub fn to_bytes(&self) -> SecretBytes {
        let mut out = Zeroizing::new(Vec::with_capacity(MESSAGE_BOX_INDEX_SIZE));
        out.extend_from_slice(&self.idx64.to_le_bytes());
        out.extend_from_slice(&self.blinding_factor);
        out.extend_from_slice(&self.encryption_key);
        out.extend_from_slice(&self.hkdf_state);
        out
    }

    pub fn idx64(&self) -> u64 {
        self.idx64
    }

    /// Reads the next KDF state, encryption key and blinding factor, in that
    /// order, from HKDF-BLAKE2b-512.
    fn ratchet(idx64: u64, secret: &[u8], salt: &[u8], info: &[u8]) -> Self {
        let mut okm = Zeroizing::new([0u8; 96]);
        hkdf_blake2b(secret, salt, info, &mut *okm).expect("96 bytes");
        Self {
            idx64,
            hkdf_state: okm[..32].try_into().expect("32 bytes"),
            encryption_key: okm[32..64].try_into().expect("32 bytes"),
            blinding_factor: okm[64..].try_into().expect("32 bytes"),
        }
    }

    /// The index of box `to`, which must not be behind this one.
    pub fn advance_to(&self, to: u64) -> Result<Self> {
        if to < self.idx64 {
            return Err(Error::InvalidInput("cannot rewind index"));
        }
        let mut cur = self.clone();
        while cur.idx64 < to {
            cur = Self::ratchet(
                cur.idx64 + 1,
                &cur.hkdf_state,
                &[],
                &cur.idx64.to_le_bytes(),
            );
        }
        Ok(cur)
    }

    /// The index of the following box. Fails once the 64-bit index is
    /// exhausted.
    pub fn next_index(&self) -> Result<Self> {
        let to = self
            .idx64
            .checked_add(1)
            .ok_or(Error::InvalidInput("index exhausted"))?;
        self.advance_to(to)
    }

    /// A copy whose KDF state is re-seeded by `ctx`, keeping the index
    /// number. Writer and readers that mutate by the same `ctx` land on the
    /// same fresh sequence, which cannot be found without `ctx`.
    pub fn mutate_kdf_state(&self, ctx: &[u8]) -> Self {
        Self::ratchet(self.idx64, &self.hkdf_state, ctx, MUTATE_KDF_STATE_LABEL)
    }

    /// The box's ID without a context: `root` blinded by the blinding
    /// factor.
    pub fn derive_box_id(&self, root: &VerifyingKey) -> Result<BoxId> {
        Ok(blind_verifying_key(root, &self.blinding_factor)?.to_bytes())
    }

    fn derive_for_context(secret: &[u8; 32], ctx: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        hkdf_blake2b(secret, ctx, &[], &mut *out).expect("32 bytes");
        out
    }

    fn box_id_with_root(&self, root: &VerifyingKey, ctx: &[u8]) -> Result<BoxId> {
        let k = Self::derive_for_context(&self.blinding_factor, ctx);
        Ok(blind_verifying_key(root, &*k)?.to_bytes())
    }

    /// The box's ID under `ctx`.
    pub fn box_id(&self, read_cap: &ReadCap, ctx: &[u8]) -> Result<BoxId> {
        self.box_id_with_root(&read_cap.root, ctx)
    }

    /// Signs `payload` with the box's blinded private key under `ctx`,
    /// returning the box ID, which verifies the signature, and the
    /// signature. For use with an encryption other than BACAP's own.
    pub fn sign_box(
        &self,
        owner: &WriteCap,
        ctx: &[u8],
        payload: &[u8],
    ) -> Result<(BoxId, [u8; SIGNATURE_SIZE])> {
        let k = Self::derive_for_context(&self.blinding_factor, ctx);
        let box_id = blind_verifying_key(&owner.key.verifying_key(), &*k)?.to_bytes();
        let sig = BlindedSigningKey::new(&owner.key, &*k)?.sign(payload);
        Ok((box_id, sig.to_bytes()))
    }

    /// Checks `sig` over `payload` under `box_id`.
    pub fn verify_box(box_id: &BoxId, payload: &[u8], sig: &[u8]) -> Result<()> {
        let key = VerifyingKey::from_bytes(box_id).map_err(|_| Error::InvalidKey)?;
        let sig = Signature::from_bytes(&to_array(sig)?);
        // Cofactorless with canonical S, as Go's crypto/ed25519.Verify.
        key.verify(payload, &sig)
            .map_err(|_| Error::InvalidSignature)
    }

    fn cipher(&self, ctx: &[u8]) -> Aes256GcmSiv {
        let e = Self::derive_for_context(&self.encryption_key, ctx);
        Aes256GcmSiv::new_from_slice(&*e).expect("32-byte key")
    }

    /// Encrypts `plaintext` with AES-256-GCM-SIV under `ctx`, the nonce the
    /// first 12 bytes of the box ID and the AAD all of it, and signs the
    /// ciphertext. Returns the box ID, ciphertext and signature.
    pub fn encrypt(
        &self,
        owner: &WriteCap,
        ctx: &[u8],
        plaintext: &[u8],
    ) -> Result<(BoxId, Vec<u8>, [u8; SIGNATURE_SIZE])> {
        let k = Self::derive_for_context(&self.blinding_factor, ctx);
        let box_id = blind_verifying_key(&owner.key.verifying_key(), &*k)?.to_bytes();
        let ciphertext = self
            .cipher(ctx)
            .encrypt(
                &nonce(&box_id),
                Payload {
                    msg: plaintext,
                    aad: &box_id,
                },
            )
            .map_err(|_| Error::InvalidInput("plaintext too long"))?;
        let sig = BlindedSigningKey::new(&owner.key, &*k)?.sign(&ciphertext);
        Ok((box_id, ciphertext, sig.to_bytes()))
    }

    /// Verifies the signature, then decrypts. An empty ciphertext is a
    /// tombstone: its signature is checked and the plaintext is empty. This
    /// does not check that `box_id` is this index's box; [`open`] does.
    ///
    /// [`open`]: Self::open
    pub fn decrypt(
        &self,
        box_id: &BoxId,
        ctx: &[u8],
        ciphertext: &[u8],
        sig: &[u8],
    ) -> Result<Vec<u8>> {
        Self::verify_box(box_id, ciphertext, sig)?;
        if ciphertext.is_empty() {
            return Ok(Vec::new());
        }
        self.cipher(ctx)
            .decrypt(
                &nonce(box_id),
                Payload {
                    msg: ciphertext,
                    aad: box_id,
                },
            )
            .map_err(|_| Error::DecryptionFailed)
    }

    /// Checks that `box_id` is the box `read_cap` and this index derive
    /// under `ctx`, then verifies and decrypts it. Without that check a
    /// tombstone signed for any box would be accepted.
    pub fn open(
        &self,
        read_cap: &ReadCap,
        ctx: &[u8],
        box_id: &BoxId,
        ciphertext: &[u8],
        sig: &[u8],
    ) -> Result<Vec<u8>> {
        if ct_is_zero(box_id) {
            return Err(Error::EmptyBox);
        }
        if !bool::from(self.box_id(read_cap, ctx)?.ct_eq(box_id)) {
            return Err(Error::BoxMismatch);
        }
        self.decrypt(box_id, ctx, ciphertext, sig)
    }

    /// Signs the empty payload for this box under `ctx`, returning the box
    /// ID and signature. Written with an empty payload, it deletes the box.
    pub fn tombstone(&self, owner: &WriteCap, ctx: &[u8]) -> Result<(BoxId, [u8; SIGNATURE_SIZE])> {
        self.sign_box(owner, ctx, &[])
    }
}

fn nonce(box_id: &BoxId) -> Nonce {
    Nonce::from(<[u8; 12]>::try_from(&box_id[..12]).expect("12 bytes"))
}

impl ConstantTimeEq for MessageBoxIndex {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.idx64.ct_eq(&other.idx64)
            & self.blinding_factor.ct_eq(&other.blinding_factor)
            & self.encryption_key.ct_eq(&other.encryption_key)
            & self.hkdf_state.ct_eq(&other.hkdf_state)
    }
}

impl PartialEq for MessageBoxIndex {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for MessageBoxIndex {}

impl std::fmt::Debug for MessageBoxIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageBoxIndex")
            .field("idx64", &self.idx64)
            .finish_non_exhaustive()
    }
}

/// Whether stepping `start` forward reaches `idx`.
fn contains(start: &MessageBoxIndex, idx: &MessageBoxIndex) -> Result<()> {
    if idx.idx64 < start.idx64 {
        return Err(Error::IndexNotInStream);
    }
    if idx.idx64 - start.idx64 > MAX_CONTAINS_WALK {
        return Err(Error::IndexTooFar);
    }
    if start.advance_to(idx.idx64)? != *idx {
        return Err(Error::IndexNotInStream);
    }
    Ok(())
}

/// Derives box IDs and decryption keys for a stream of boxes. Encodes as the
/// 32-byte root public key followed by its first index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadCap {
    root: VerifyingKey,
    index: MessageBoxIndex,
}

impl ReadCap {
    /// Rejects a root key that is not a point on the curve.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_len(bytes, READ_CAP_SIZE)?;
        let root =
            VerifyingKey::from_bytes(&to_array(&bytes[..32])?).map_err(|_| Error::InvalidKey)?;
        Ok(Self {
            root,
            index: MessageBoxIndex::from_bytes(&bytes[32..])?,
        })
    }

    pub fn to_bytes(&self) -> SecretBytes {
        let mut out = Zeroizing::new(Vec::with_capacity(READ_CAP_SIZE));
        out.extend_from_slice(self.root.as_bytes());
        out.extend_from_slice(&self.index.to_bytes());
        out
    }

    pub fn root_public_key(&self) -> &VerifyingKey {
        &self.root
    }

    /// The first index this cap reads.
    pub fn index(&self) -> &MessageBoxIndex {
        &self.index
    }

    /// The same cap starting at `index`, so its holder cannot step back to
    /// count earlier boxes.
    pub fn with_index(&self, index: &MessageBoxIndex) -> Self {
        Self {
            root: self.root,
            index: index.clone(),
        }
    }

    /// See [`MessageBoxIndex::mutate_kdf_state`].
    pub fn mutate_kdf_state(&self, ctx: &[u8]) -> Self {
        self.with_index(&self.index.mutate_kdf_state(ctx))
    }

    /// Checks that `idx` lies on this cap's stream, by stepping the cap's
    /// own index forward to it, at most [`MAX_CONTAINS_WALK`] steps.
    pub fn contains(&self, idx: &MessageBoxIndex) -> Result<()> {
        contains(&self.index, idx)
    }
}

/// Derives signing and encryption keys for a stream of boxes. Encodes as the
/// 64-byte Ed25519 private key (seed then public key) followed by its first
/// index. Zeroed on drop.
#[derive(Clone)]
pub struct WriteCap {
    key: SigningKey,
    index: MessageBoxIndex,
}

impl WriteCap {
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *seed);
        Self {
            key: SigningKey::from_bytes(&seed),
            index: MessageBoxIndex::generate(rng),
        }
    }

    /// Rejects an encoding whose public key does not match its seed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        check_len(bytes, WRITE_CAP_SIZE)?;
        let seed = Zeroizing::new(to_array::<32>(&bytes[..32])?);
        let key = SigningKey::from_bytes(&seed);
        if !bool::from(key.verifying_key().as_bytes().ct_eq(&bytes[32..64])) {
            return Err(Error::InvalidKey);
        }
        Ok(Self {
            key,
            index: MessageBoxIndex::from_bytes(&bytes[64..])?,
        })
    }

    pub fn to_bytes(&self) -> SecretBytes {
        let mut out = Zeroizing::new(Vec::with_capacity(WRITE_CAP_SIZE));
        out.extend_from_slice(&*Zeroizing::new(self.key.to_keypair_bytes()));
        out.extend_from_slice(&self.index.to_bytes());
        out
    }

    pub fn root_public_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// The first index this cap writes.
    pub fn index(&self) -> &MessageBoxIndex {
        &self.index
    }

    /// The read cap of the same stream, from the same first index.
    pub fn read_cap(&self) -> ReadCap {
        ReadCap {
            root: self.key.verifying_key(),
            index: self.index.clone(),
        }
    }

    /// The same cap starting at `index`.
    pub fn with_index(&self, index: &MessageBoxIndex) -> Self {
        Self {
            key: self.key.clone(),
            index: index.clone(),
        }
    }

    /// See [`MessageBoxIndex::mutate_kdf_state`].
    pub fn mutate_kdf_state(&self, ctx: &[u8]) -> Self {
        self.with_index(&self.index.mutate_kdf_state(ctx))
    }

    /// See [`ReadCap::contains`].
    pub fn contains(&self, idx: &MessageBoxIndex) -> Result<()> {
        contains(&self.index, idx)
    }
}

impl std::fmt::Debug for WriteCap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WriteCap")
            .field("root_public_key", &self.key.verifying_key())
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::rng;

    #[test]
    fn caps_and_index_round_trip() {
        let wc = WriteCap::generate(&mut rng());
        assert!(wc.index().idx64() <= 1 << 63);
        let wc2 = WriteCap::from_bytes(&wc.to_bytes()).unwrap();
        assert_eq!(*wc2.to_bytes(), *wc.to_bytes());
        let rc = ReadCap::from_bytes(&wc.read_cap().to_bytes()).unwrap();
        assert_eq!(rc, wc.read_cap());
        assert_eq!(
            MessageBoxIndex::from_bytes(&wc.index().to_bytes()).unwrap(),
            *wc.index()
        );
    }

    #[test]
    fn positions_write_then_read() {
        let wc = WriteCap::generate(&mut rng());
        let rc = wc.read_cap();
        let (mut w, mut r) = (wc.start(), rc.start());
        for i in 0..3u8 {
            let (bx, ct, sig) = w.encrypt(b"ctx", &[i; 40]).unwrap();
            assert_eq!(bx, r.box_id(b"ctx").unwrap());
            assert_eq!(bx, w.box_id(b"ctx").unwrap());
            assert_eq!(r.open(b"ctx", &bx, &ct, &sig).unwrap(), [i; 40]);
            let (tb, tsig) = w.tombstone(b"ctx").unwrap();
            assert!(r.open(b"ctx", &tb, &[], &tsig).unwrap().is_empty());
            w = w.next().unwrap();
            r = r.next().unwrap();
        }
        assert_eq!(
            w.advance_to(w.index().idx64() + 4).unwrap().index(),
            r.advance_to(r.index().idx64() + 4).unwrap().index()
        );
    }

    #[test]
    fn refuses_wrong_key_and_tampering() {
        let wc = WriteCap::generate(&mut rng());
        let other = WriteCap::generate(&mut rng());
        let idx = wc.index();
        let (bx, ct, sig) = idx.encrypt(&wc, b"ctx", b"secret").unwrap();

        let next = idx.next_index().unwrap();
        assert_eq!(
            next.decrypt(&bx, b"ctx", &ct, &sig),
            Err(Error::DecryptionFailed)
        );
        assert_eq!(
            idx.decrypt(&bx, b"other", &ct, &sig),
            Err(Error::DecryptionFailed)
        );
        assert_eq!(
            idx.open(&other.read_cap(), b"ctx", &bx, &ct, &sig),
            Err(Error::BoxMismatch)
        );
        assert_eq!(
            idx.open(&wc.read_cap(), b"ctx", &[0; 32], &ct, &sig),
            Err(Error::EmptyBox)
        );

        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        assert_eq!(
            idx.decrypt(&bx, b"ctx", &bad_ct, &sig),
            Err(Error::InvalidSignature)
        );
        let mut bad_sig = sig;
        bad_sig[10] ^= 1;
        assert_eq!(
            idx.decrypt(&bx, b"ctx", &ct, &bad_sig),
            Err(Error::InvalidSignature)
        );

        // Another cap's signature over the same ciphertext.
        let (_, other_sig) = idx.sign_box(&other, b"ctx", &ct).unwrap();
        assert_eq!(
            idx.decrypt(&bx, b"ctx", &ct, &other_sig),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn position_at_refuses_another_stream() {
        let wc = WriteCap::generate(&mut rng());
        let rc = wc.read_cap();
        let ahead = wc.index().advance_to(wc.index().idx64() + 5).unwrap();
        assert_eq!(rc.position_at(&ahead).unwrap().index(), &ahead);
        assert_eq!(wc.position_at(&ahead).unwrap().index(), &ahead);

        let other = WriteCap::generate(&mut rng());
        let foreign = other.index().clone();
        assert_eq!(
            rc.position_at(&foreign).unwrap_err(),
            Error::IndexNotInStream
        );
        assert_eq!(
            wc.position_at(&foreign).unwrap_err(),
            Error::IndexNotInStream
        );

        let mut same_number = foreign.clone();
        same_number.idx64 = ahead.idx64;
        assert_eq!(
            rc.position_at(&same_number).unwrap_err(),
            Error::IndexNotInStream
        );

        let mutated = wc.index().mutate_kdf_state(b"salt");
        assert_eq!(
            rc.position_at(&mutated).unwrap_err(),
            Error::IndexNotInStream
        );

        let rebased = rc.with_index(&ahead);
        assert_eq!(
            rebased.position_at(wc.index()).unwrap_err(),
            Error::IndexNotInStream
        );

        let mut far = wc.index().clone();
        far.idx64 += MAX_CONTAINS_WALK + 1;
        assert_eq!(rc.position_at(&far).unwrap_err(), Error::IndexTooFar);
    }

    #[test]
    fn mutated_caps_stay_in_lockstep() {
        let wc = WriteCap::generate(&mut rng());
        let (mw, mr) = (
            wc.mutate_kdf_state(b"salt"),
            wc.read_cap().mutate_kdf_state(b"salt"),
        );
        assert_eq!(mw.read_cap(), mr);
        assert_ne!(mr.index(), wc.index());
        let (bx, ct, sig) = mw.start().encrypt(b"c", b"hi").unwrap();
        assert_eq!(mr.start().open(b"c", &bx, &ct, &sig).unwrap(), b"hi");
    }

    #[test]
    fn index_ends_at_u64_max() {
        let mut idx = MessageBoxIndex::empty();
        idx.idx64 = u64::MAX;
        assert!(idx.next_index().is_err());
        assert!(idx.advance_to(u64::MAX - 1).is_err());
    }
}
