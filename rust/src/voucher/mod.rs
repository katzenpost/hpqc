//! The cryptography of the Contact Voucher, the way a newcomer joins a
//! Pigeonhole group, byte compatible with hpqc's Go `voucher` package and
//! the Python `hpqc.voucher`.
//!
//! The joiner mints a voucher, a 32-byte code it hands to a member of the
//! group out of band. Both sides derive the same rendezvous BACAP stream
//! from the voucher: the joiner publishes its request in box 0, and the
//! member answering (the inductor) publishes a sealed reply from box 1 on.
//! The reply carries the group's members and a salt that moves the joiner's
//! stream to a fresh, unpredictable position.
//!
//! # Flow
//!
//! ```no_run
//! # use hpqc::bacap::WriteCap;
//! # use hpqc::voucher::{self, VoucherStream};
//! # fn main() -> hpqc::Result<()> {
//! # let rng = &mut hpqc::voucher::ShakeRng::new(b"example");
//! # let (write_cap, payload, who_reply, reply) = (WriteCap::generate(rng), vec![], vec![], vec![]);
//! // Joiner: publish `minted.payload` in box 0 of `minted.stream`, hand
//! // `minted.voucher` to a member, keep `minted.secret_key`.
//! let minted = voucher::mint(&write_cap, "alice", rng);
//!
//! // Inductor: read box 0 of the stream the voucher names, answer it, write
//! // `inducted.sealed_reply` from box 1 on and give the group
//! // `inducted.mutated_read_cap`.
//! let stream = VoucherStream::derive(&minted.voucher);
//! let inducted = voucher::induct(&minted.voucher, &payload, &who_reply, rng)?;
//!
//! // Joiner: read the reply from box 1 on, then write to the group with
//! // `opened.mutated_write_cap`.
//! let opened = voucher::open_reply(&minted.secret_key, &reply, &write_cap)?;
//! # Ok(())
//! # }
//! ```
//!
//! # Forms
//!
//! A voucher comes in two [`Form`]s, chosen when it is minted.
//!
//! - [`Form::Compact`] ([`mint_compact`], the default of [`mint`]): box 0 is
//!   the CBOR array `[read_cap, voucher_pub_key, display_name, signature]`.
//!   The reply is a [`SealedBox`] written framed over boxes 1, 2, …: pieces
//!   of the box size less one byte, each behind `'C'`, the last behind
//!   `'F'`.
//! - [`Form::Long`] ([`mint_long`]): box 0 is the signed CBOR map that
//!   clients before the compact form read. The reply is an [`Mkem`]
//!   ciphertext, written unframed in box 1 alone.
//!
//! [`induct`] answers a payload in the form it was minted in, and
//! [`open_reply`] opens either. Framing a compact reply over boxes is the
//! caller's to do; this module only seals and opens.
//!
//! Both forms are authenticated twice. The voucher is the BLAKE2b-256 of
//! box 0, so the inductor detects any change to it. The payload is signed by
//! the joiner's stream root key, so the joiner holds the stream it names.
//!
//! # Determinism
//!
//! Every function is pure apart from the random bytes it draws from the
//! `rng` it is given. Seeding a [`ShakeRng`] as the Go and Python
//! implementations seed their SHAKE256 readers reproduces their bytes
//! exactly; the shared vectors are `voucher/testdata/voucher_vectors.json`
//! (long form) and `voucher_vectors_v2.json` (compact form).

use std::sync::{Arc, LazyLock};

use ed25519_dalek::{Signature, Signer, Verifier};
use rand_core::{CryptoRng, TryCryptoRng, TryRng};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use subtle::ConstantTimeEq;

use crate::bacap::{ReadCap, WriteCap};
use crate::cbor::Value;
use crate::hash::blake2b_256;
use crate::nike::{Scheme, schemes};
use crate::protocols::mkem::{Ciphertext, Mkem};
use crate::protocols::sealedbox::SealedBox;
use crate::{Error, Result, SecretBytes};

/// The size of a voucher.
pub const VOUCHER_SIZE: usize = 32;

/// The size of the salt that re-seeds the joiner's stream (see
/// [`WriteCap::mutate_kdf_state`]).
pub const SALT_SIZE: usize = 32;

const MALFORMED: Error = Error::InvalidInput("malformed voucher message");

/// The voucher keypair's NIKE, X25519 then CTIDH-1024 under its legacy name
/// `CTIDH1024-X25519`, which the sealed box binds into its key derivation.
static SEAL_NIKE: LazyLock<Arc<dyn Scheme>> =
    LazyLock::new(|| schemes::by_name("CTIDH1024-X25519").expect("registered"));

/// SHAKE256 of a seed as a deterministic [`CryptoRng`], the stream Go's and
/// Python's voucher code read their seeded randomness from.
///
/// Use it only to reproduce test vectors: anyone who knows the seed knows
/// every key drawn from it.
pub struct ShakeRng(<Shake256 as ExtendableOutput>::Reader);

impl ShakeRng {
    pub fn new(seed: &[u8]) -> Self {
        let mut shake = Shake256::default();
        shake.update(seed);
        Self(shake.finalize_xof())
    }
}

impl TryRng for ShakeRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> core::result::Result<u32, Self::Error> {
        let mut b = [0; 4];
        self.0.read(&mut b);
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> core::result::Result<u64, Self::Error> {
        let mut b = [0; 8];
        self.0.read(&mut b);
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> core::result::Result<(), Self::Error> {
        self.0.read(dst);
        Ok(())
    }
}

impl TryCryptoRng for ShakeRng {}

/// The two encodings of a voucher payload and its reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// The signed CBOR map, answered with an MKEM ciphertext in box 1.
    Long = 1,
    /// The CBOR array, answered with a sealed box framed over boxes 1 on.
    Compact = 2,
}

impl Form {
    /// The form of a payload, from its first byte's CBOR major type: a map
    /// is [`Form::Long`], an array [`Form::Compact`].
    pub fn of_payload(payload: &[u8]) -> Result<Self> {
        match payload.first().map(|b| b >> 5) {
            Some(5) => Ok(Form::Long),
            Some(4) => Ok(Form::Compact),
            _ => Err(MALFORMED),
        }
    }

    /// The version number Go and Python report: 1 for long, 2 for compact.
    pub fn version(self) -> u8 {
        self as u8
    }
}

/// The rendezvous stream's capabilities, which both sides compute from the
/// voucher alone. Box 0 holds the payload; the reply starts at the next.
#[derive(Clone, Debug)]
pub struct VoucherStream {
    pub write_cap: WriteCap,
    pub read_cap: ReadCap,
}

impl VoucherStream {
    pub fn derive(voucher: &[u8; VOUCHER_SIZE]) -> Self {
        let write_cap = WriteCap::generate(&mut ShakeRng::new(voucher));
        let read_cap = write_cap.read_cap();
        Self {
            write_cap,
            read_cap,
        }
    }
}

/// What minting returns.
#[derive(Debug)]
pub struct Minted {
    pub form: Form,
    /// The code handed to the inductor out of band.
    pub voucher: [u8; VOUCHER_SIZE],
    /// What goes in box 0 of [`stream`](Self::stream).
    pub payload: Vec<u8>,
    pub stream: VoucherStream,
    /// The voucher private key, kept to open the reply.
    pub secret_key: SecretBytes,
    pub public_key: Vec<u8>,
}

/// What [`induct`] returns.
#[derive(Debug)]
pub struct Inducted {
    /// The form of the payload, and so of the reply.
    pub form: Form,
    /// The name the joiner asked to be shown by.
    pub display_name: String,
    /// The joiner's stream moved by [`salt`](Self::salt): where the group
    /// reads the joiner from now on.
    pub mutated_read_cap: ReadCap,
    /// Written from box 1 on, framed for [`Form::Compact`] and unframed in
    /// box 1 for [`Form::Long`].
    pub sealed_reply: Vec<u8>,
    pub stream: VoucherStream,
    pub salt: [u8; SALT_SIZE],
}

/// What [`open_reply`] returns.
#[derive(Debug)]
pub struct OpenedReply {
    /// The group membership the inductor sent, opaque here.
    pub who_reply: Vec<u8>,
    pub salt: [u8; SALT_SIZE],
    /// The joiner's stream moved by [`salt`](Self::salt): where the joiner
    /// writes to the group from now on.
    pub mutated_write_cap: WriteCap,
}

/// Mints a voucher in the compact form, the form new clients use. It is
/// [`mint_compact`]; see [`mint_long`] for an inductor that reads only the
/// long form.
pub fn mint(write_cap: &WriteCap, display_name: &str, rng: &mut dyn CryptoRng) -> Minted {
    mint_compact(write_cap, display_name, rng)
}

/// Mints a voucher in the compact form.
///
/// `write_cap` is the joiner's own stream, `display_name` the name the group
/// will show. The voucher keypair is drawn from `rng`.
pub fn mint_compact(write_cap: &WriteCap, display_name: &str, rng: &mut dyn CryptoRng) -> Minted {
    let read_cap = write_cap.read_cap().to_bytes().to_vec();
    let secret = SEAL_NIKE.generate_key(rng);
    let public_key = secret.public_key().to_bytes();
    let mut fields = vec![
        Value::Bytes(read_cap),
        Value::Bytes(public_key.clone()),
        Value::Text(display_name.into()),
    ];
    let signature = write_cap
        .root_signing_key()
        .sign(&Value::Array(fields.clone()).to_bytes());
    fields.push(Value::Bytes(signature.to_bytes().to_vec()));
    finish_mint(
        Form::Compact,
        Value::Array(fields).to_bytes(),
        secret.to_bytes(),
        public_key,
    )
}

/// Mints a voucher in the long form, the signed CBOR map that inductors
/// from before the compact form read. Its reply is an MKEM ciphertext.
/// Arguments are as for [`mint_compact`].
pub fn mint_long(write_cap: &WriteCap, display_name: &str, rng: &mut dyn CryptoRng) -> Minted {
    let read_cap = write_cap.read_cap().to_bytes().to_vec();
    let secret = SEAL_NIKE.generate_key(rng);
    let public_key = secret.public_key().to_bytes();
    let please_add = Value::Map(vec![
        ("DisplayName".into(), Value::Text(display_name.into())),
        ("MessageReadCap".into(), Value::Bytes(read_cap)),
    ])
    .to_bytes();
    let signature = write_cap.root_signing_key().sign(&please_add);
    let signed = Value::Map(vec![
        ("PleaseAdd".into(), Value::Bytes(please_add)),
        (
            "Signature".into(),
            Value::Bytes(signature.to_bytes().to_vec()),
        ),
    ])
    .to_bytes();
    let payload = Value::Map(vec![
        ("SignedPleaseAdd".into(), Value::Bytes(signed)),
        ("VoucherPubKey".into(), Value::Bytes(public_key.clone())),
    ])
    .to_bytes();
    finish_mint(Form::Long, payload, secret.to_bytes(), public_key)
}

fn finish_mint(
    form: Form,
    payload: Vec<u8>,
    secret_key: SecretBytes,
    public_key: Vec<u8>,
) -> Minted {
    let voucher = blake2b_256(&[], &payload).expect("unkeyed");
    Minted {
        form,
        voucher,
        stream: VoucherStream::derive(&voucher),
        payload,
        secret_key,
        public_key,
    }
}

/// Answers a voucher: checks the payload and seals a reply to the joiner,
/// in the form the payload was minted in. The salt and the seal's ephemeral
/// key are drawn from `rng`, in that order.
///
/// `voucher` is the code the joiner handed over, `payload` what box 0 of its
/// [`VoucherStream`] holds, `who_reply` the group membership to send.
///
/// Fails with [`Error::VoucherMismatch`] when the payload is not the one
/// the voucher names, [`Error::InvalidSignature`] when its signature does
/// not verify under the read cap it names, and [`Error::InvalidInput`] or
/// [`Error::InvalidKey`] for anything malformed.
pub fn induct(
    voucher: &[u8; VOUCHER_SIZE],
    payload: &[u8],
    who_reply: &[u8],
    rng: &mut dyn CryptoRng,
) -> Result<Inducted> {
    let mut salt = [0; SALT_SIZE];
    rng.fill_bytes(&mut salt);
    induct_with_salt(voucher, payload, who_reply, &salt, rng)
}

/// [`induct`] with the salt given, drawing only the seal's ephemeral key
/// from `rng`. This is the split Go's and Python's `VoucherInduct` take
/// their `salt` and `seal_seed` arguments in.
pub fn induct_with_salt(
    voucher: &[u8; VOUCHER_SIZE],
    payload: &[u8],
    who_reply: &[u8],
    salt: &[u8; SALT_SIZE],
    rng: &mut dyn CryptoRng,
) -> Result<Inducted> {
    let hash = blake2b_256(&[], payload)?;
    if !bool::from(hash.ct_eq(voucher)) {
        return Err(Error::VoucherMismatch);
    }
    let form = Form::of_payload(payload)?;
    let (display_name, read_cap, public_key) = match form {
        Form::Compact => {
            let [read_cap, public_key, name, signature] =
                Value::from_bytes(payload)?.into_array()?;
            let (read_cap, public_key, name) = (
                read_cap.into_bytes()?,
                public_key.into_bytes()?,
                name.into_text()?,
            );
            let signed = Value::Array(vec![
                Value::Bytes(read_cap.clone()),
                Value::Bytes(public_key.clone()),
                Value::Text(name.clone()),
            ])
            .to_bytes();
            let read_cap = ReadCap::from_bytes(&read_cap).map_err(|_| MALFORMED)?;
            verify(&read_cap, &signed, &signature.into_bytes()?)?;
            (name, read_cap, public_key)
        }
        Form::Long => {
            let [signed, public_key] =
                Value::from_bytes(payload)?.into_fields(["SignedPleaseAdd", "VoucherPubKey"])?;
            let [please_add, signature] = Value::from_bytes(&signed.into_bytes()?)?
                .into_fields(["PleaseAdd", "Signature"])?;
            let please_add = please_add.into_bytes()?;
            let [name, read_cap] =
                Value::from_bytes(&please_add)?.into_fields(["DisplayName", "MessageReadCap"])?;
            let read_cap = ReadCap::from_bytes(&read_cap.into_bytes()?).map_err(|_| MALFORMED)?;
            verify(&read_cap, &please_add, &signature.into_bytes()?)?;
            (name.into_text()?, read_cap, public_key.into_bytes()?)
        }
    };
    let recipient = SEAL_NIKE
        .public_key_from_bytes(&public_key)
        .map_err(|_| MALFORMED)?;
    let sealed_reply = match form {
        Form::Compact => {
            let plaintext = Value::Array(vec![
                Value::Bytes(who_reply.to_vec()),
                Value::Bytes(salt.to_vec()),
            ])
            .to_bytes();
            SealedBox::new(SEAL_NIKE.clone()).seal(&*recipient, &plaintext, rng)?
        }
        Form::Long => {
            let plaintext = Value::Map(vec![
                ("WhoReply".into(), Value::Bytes(who_reply.to_vec())),
                ("VoucherSalt".into(), Value::Bytes(salt.to_vec())),
            ])
            .to_bytes();
            let (_, ciphertext) =
                Mkem::new(SEAL_NIKE.clone()).encapsulate(&[&*recipient], &plaintext, rng)?;
            ciphertext.to_bytes()
        }
    };
    Ok(Inducted {
        form,
        display_name,
        mutated_read_cap: read_cap.mutate_kdf_state(salt),
        sealed_reply,
        stream: VoucherStream::derive(voucher),
        salt: *salt,
    })
}

fn verify(read_cap: &ReadCap, message: &[u8], signature: &[u8]) -> Result<()> {
    let signature = Signature::from_slice(signature).map_err(|_| Error::InvalidSignature)?;
    read_cap
        .root_public_key()
        .verify(message, &signature)
        .map_err(|_| Error::InvalidSignature)
}

/// Opens the reply to a voucher the caller minted, in either form.
///
/// `secret_key` is [`Minted::secret_key`], `sealed_reply` the reply
/// reassembled from boxes 1 on (compact) or box 1 alone (long), and
/// `write_cap` the stream the voucher was minted from.
///
/// Fails with [`Error::DecryptionFailed`] when the reply was not sealed to
/// this key or is malformed, and [`Error::InvalidKey`] for a malformed key.
pub fn open_reply(
    secret_key: &[u8],
    sealed_reply: &[u8],
    write_cap: &WriteCap,
) -> Result<OpenedReply> {
    let private_key = SEAL_NIKE.private_key_from_bytes(secret_key)?;
    let opened = || -> Result<(Vec<u8>, Vec<u8>)> {
        if is_mkem_reply(sealed_reply) {
            let mkem = Mkem::new(SEAL_NIKE.clone());
            let plaintext =
                mkem.decapsulate(&*private_key, &Ciphertext::from_bytes(&mkem, sealed_reply)?)?;
            let [who, salt] =
                Value::from_bytes(&plaintext)?.into_fields(["WhoReply", "VoucherSalt"])?;
            Ok((who.into_bytes()?, salt.into_bytes()?))
        } else {
            let plaintext = SealedBox::new(SEAL_NIKE.clone()).open(
                &*private_key,
                &*private_key.public_key(),
                sealed_reply,
            )?;
            let [who, salt] = Value::from_bytes(&plaintext)?.into_array()?;
            Ok((who.into_bytes()?, salt.into_bytes()?))
        }
    };
    let (who_reply, salt) = opened().map_err(|_| Error::DecryptionFailed)?;
    let salt: [u8; SALT_SIZE] = salt.try_into().map_err(|_| Error::DecryptionFailed)?;
    Ok(OpenedReply {
        who_reply,
        salt,
        mutated_write_cap: write_cap.mutate_kdf_state(&salt),
    })
}

/// Whether a reply is the long form's MKEM ciphertext: a CBOR map of
/// exactly its three keys. A sealed box begins with a public key instead.
fn is_mkem_reply(sealed: &[u8]) -> bool {
    if sealed.first().is_none_or(|b| b >> 5 != 5) {
        return false;
    }
    match Value::from_bytes(sealed) {
        Ok(Value::Map(entries)) => {
            entries.len() == 3
                && ["EphemeralPublicKey", "DEKCiphertexts", "Envelope"]
                    .iter()
                    .all(|k| entries.iter().any(|(e, _)| e == k))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joiner() -> WriteCap {
        WriteCap::generate(&mut crate::util::rng())
    }

    #[test]
    fn both_forms_round_trip() {
        let rng = &mut crate::util::rng();
        let write_cap = joiner();
        for minted in [
            mint(&write_cap, "alice", rng),
            mint_long(&write_cap, "alice", rng),
        ] {
            assert_eq!(Form::of_payload(&minted.payload).unwrap(), minted.form);
            let inducted = induct(&minted.voucher, &minted.payload, b"members", rng).unwrap();
            assert_eq!(inducted.form, minted.form);
            assert_eq!(inducted.display_name, "alice");
            assert_eq!(
                inducted.stream.read_cap.to_bytes(),
                minted.stream.read_cap.to_bytes()
            );
            let opened =
                open_reply(&minted.secret_key, &inducted.sealed_reply, &write_cap).unwrap();
            assert_eq!(opened.who_reply, b"members");
            assert_eq!(opened.salt, inducted.salt);
            assert_eq!(
                opened.mutated_write_cap.read_cap().to_bytes(),
                inducted.mutated_read_cap.to_bytes()
            );
        }
    }

    #[test]
    fn rejects_tampering() {
        let rng = &mut crate::util::rng();
        let write_cap = joiner();
        let minted = mint(&write_cap, "alice", rng);

        let mut payload = minted.payload.clone();
        *payload.last_mut().unwrap() ^= 1;
        assert_eq!(
            induct(&minted.voucher, &payload, b"", rng).unwrap_err(),
            Error::VoucherMismatch
        );
        // A payload whose hash is the voucher but whose signature is wrong.
        let voucher = blake2b_256(&[], &payload).unwrap();
        assert_eq!(
            induct(&voucher, &payload, b"", rng).unwrap_err(),
            Error::InvalidSignature
        );

        let inducted = induct(&minted.voucher, &minted.payload, b"", rng).unwrap();
        let other = mint(&write_cap, "alice", rng);
        assert_eq!(
            open_reply(&other.secret_key, &inducted.sealed_reply, &write_cap).unwrap_err(),
            Error::DecryptionFailed
        );
    }
}
