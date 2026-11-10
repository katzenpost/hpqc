//! A capability paired with one box on its own stream.

use super::{BoxId, MessageBoxIndex, ReadCap, SIGNATURE_SIZE, WriteCap};
use crate::Result;
use crate::prelude::*;

/// A read cap together with one box on its stream. Positions come only from
/// [`ReadCap::start`], [`ReadCap::position_at`] and moving forward, so a cap
/// is never paired with an index from another stream.
#[derive(Clone, Debug)]
pub struct ReadPosition<'a> {
    cap: &'a ReadCap,
    index: MessageBoxIndex,
}

/// A write cap together with one box on its stream. See [`ReadPosition`].
#[derive(Clone, Debug)]
pub struct WritePosition<'a> {
    cap: &'a WriteCap,
    index: MessageBoxIndex,
}

impl ReadCap {
    /// The position of the cap's own index: the first box it reads.
    pub fn start(&self) -> ReadPosition<'_> {
        ReadPosition {
            cap: self,
            index: self.index.clone(),
        }
    }

    /// The position of `idx`, after checking with [`contains`] that it is on
    /// this cap's stream.
    ///
    /// [`contains`]: ReadCap::contains
    pub fn position_at(&self, idx: &MessageBoxIndex) -> Result<ReadPosition<'_>> {
        self.contains(idx)?;
        Ok(ReadPosition {
            cap: self,
            index: idx.clone(),
        })
    }
}

impl WriteCap {
    /// The position of the cap's own index: the first box it writes.
    pub fn start(&self) -> WritePosition<'_> {
        WritePosition {
            cap: self,
            index: self.index.clone(),
        }
    }

    /// The position of `idx`, after checking with [`contains`] that it is on
    /// this cap's stream.
    ///
    /// [`contains`]: WriteCap::contains
    pub fn position_at(&self, idx: &MessageBoxIndex) -> Result<WritePosition<'_>> {
        self.contains(idx)?;
        Ok(WritePosition {
            cap: self,
            index: idx.clone(),
        })
    }
}

impl<'a> ReadPosition<'a> {
    pub fn cap(&self) -> &'a ReadCap {
        self.cap
    }

    pub fn index(&self) -> &MessageBoxIndex {
        &self.index
    }

    /// The position of the following box.
    pub fn next(&self) -> Result<Self> {
        Ok(Self {
            cap: self.cap,
            index: self.index.next_index()?,
        })
    }

    /// The position of box `n`, which must not be behind this one.
    pub fn advance_to(&self, n: u64) -> Result<Self> {
        Ok(Self {
            cap: self.cap,
            index: self.index.advance_to(n)?,
        })
    }

    /// The ID of the box at this position under `ctx`.
    pub fn box_id(&self, ctx: &[u8]) -> Result<BoxId> {
        self.index.box_id(self.cap, ctx)
    }

    /// Verifies and decrypts the box at this position. See
    /// [`MessageBoxIndex::open`].
    pub fn open(
        &self,
        ctx: &[u8],
        box_id: &BoxId,
        ciphertext: &[u8],
        sig: &[u8],
    ) -> Result<Vec<u8>> {
        self.index.open(self.cap, ctx, box_id, ciphertext, sig)
    }
}

impl<'a> WritePosition<'a> {
    pub fn cap(&self) -> &'a WriteCap {
        self.cap
    }

    pub fn index(&self) -> &MessageBoxIndex {
        &self.index
    }

    /// The position of the following box.
    pub fn next(&self) -> Result<Self> {
        Ok(Self {
            cap: self.cap,
            index: self.index.next_index()?,
        })
    }

    /// The position of box `n`, which must not be behind this one.
    pub fn advance_to(&self, n: u64) -> Result<Self> {
        Ok(Self {
            cap: self.cap,
            index: self.index.advance_to(n)?,
        })
    }

    /// The ID of the box at this position under `ctx`.
    pub fn box_id(&self, ctx: &[u8]) -> Result<BoxId> {
        self.index
            .box_id_with_root(&self.cap.root_public_key(), ctx)
    }

    /// Encrypts and signs `plaintext` for the box at this position,
    /// returning the box ID, ciphertext and signature.
    pub fn encrypt(
        &self,
        ctx: &[u8],
        plaintext: &[u8],
    ) -> Result<(BoxId, Vec<u8>, [u8; SIGNATURE_SIZE])> {
        self.index.encrypt(self.cap, ctx, plaintext)
    }

    /// Signs the empty payload for the box at this position, returning the
    /// box ID and signature.
    pub fn tombstone(&self, ctx: &[u8]) -> Result<(BoxId, [u8; SIGNATURE_SIZE])> {
        self.index.tombstone(self.cap, ctx)
    }
}
