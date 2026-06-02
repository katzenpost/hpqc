# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Multi-recipient KEM construction.

Direct port of ``hpqc/kem/mkem`` on the Go side. Wraps any NIKE
scheme (X25519, CTIDH1024, hybrid) into an MKEM that encapsulates a
single payload to one or many recipients.

Construction:

  - For each recipient public key ``pk_i``, derive a shared secret
    ``s_i = NIKE.DeriveSecret(eph_priv, pk_i)`` and hash it through
    BLAKE2b-256 to obtain a 32-byte AEAD key.
  - Generate a fresh random 32-byte ``msg_key``.
  - Encrypt the payload under ``msg_key`` (ChaCha20-Poly1305, 12-byte
    nonce, no AAD) to produce the envelope.
  - Encrypt ``msg_key`` under each ``s_i`` to produce a 60-byte DEK
    ciphertext (12-byte nonce + 32-byte plaintext + 16-byte tag).
  - Send (eph_pub, [DEK ciphertext per recipient], envelope).

A recipient decapsulates by deriving ``s = NIKE.DeriveSecret(my_priv,
eph_pub)``, trying each DEK ciphertext until one decrypts to a
``msg_key``, then using that to decrypt the envelope.

A single-recipient variant (``envelope_reply`` / ``decrypt_envelope``)
skips the DEK indirection: the AEAD key is the hashed shared secret
directly.
"""
from __future__ import annotations

import dataclasses
import os
from typing import Callable, List, Optional, Tuple

import cbor2
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from hpqc.hash import sum256
from hpqc.nike.scheme import PrivateKey, PublicKey, Scheme as NIKEScheme

#: Size in bytes of one DEK ciphertext: 12-byte nonce + 32-byte
#: plaintext (the msg_key) + 16-byte ChaCha20-Poly1305 tag.
DEKSize: int = 60

_NONCE_SIZE: int = 12
_MSG_KEY_SIZE: int = 32


@dataclasses.dataclass
class Ciphertext:
    """An MKEM ciphertext.

    ``ephemeral_public_key`` is the sender's per-message public key.
    ``dek_ciphertexts`` is one 60-byte ChaCha20-Poly1305 ciphertext
    per recipient, each encrypting the same 32-byte ``msg_key`` under
    a recipient-specific key. ``envelope`` is the payload encrypted
    under that ``msg_key``.

    Wire format mirrors the Go side: a CBOR-encoded map with keys
    ``EphemeralPublicKey`` (the public key bytes), ``DEKCiphertexts``
    (a CBOR array of byte strings), and ``Envelope`` (a byte string).
    """

    ephemeral_public_key: PublicKey
    dek_ciphertexts: List[bytes]
    envelope: bytes

    def marshal(self) -> bytes:
        return cbor2.dumps(
            {
                "EphemeralPublicKey": self.ephemeral_public_key.to_bytes(),
                "DEKCiphertexts": list(self.dek_ciphertexts),
                "Envelope": self.envelope,
            },
            canonical=True,
        )


class MKEMScheme:
    """An MKEM built on top of any NIKE scheme."""

    def __init__(self, nike: NIKEScheme) -> None:
        self._nike = nike

    @property
    def nike(self) -> NIKEScheme:
        return self._nike

    # ----- delegated keypair generation -----

    def generate_keypair(self) -> Tuple[PublicKey, PrivateKey]:
        return self._nike.generate_keypair()

    # ----- internal AEAD helpers -----

    @staticmethod
    def _encrypt(
        key: bytes, plaintext: bytes, nonce: Optional[bytes] = None
    ) -> bytes:
        if nonce is None:
            nonce = os.urandom(_NONCE_SIZE)
        ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
        return nonce + ct

    @staticmethod
    def _decrypt(key: bytes, ciphertext: bytes) -> bytes:
        if len(ciphertext) < _NONCE_SIZE:
            raise ValueError("ciphertext too short")
        nonce = ciphertext[:_NONCE_SIZE]
        ct = ciphertext[_NONCE_SIZE:]
        return ChaCha20Poly1305(key).decrypt(nonce, ct, None)

    # ----- single-recipient envelope (no DEK indirection) -----

    def envelope_reply(
        self,
        privkey: PrivateKey,
        pubkey: PublicKey,
        plaintext: bytes,
    ) -> Ciphertext:
        """Encrypts ``plaintext`` to a single recipient.

        Used when the sender already shares a long-term DH context
        with the recipient (typical reply path). The AEAD key is
        BLAKE2b-256(NIKE.DeriveSecret(priv, pub)) directly; there is
        no DEK indirection.
        """
        secret = sum256(self._nike.derive_secret(privkey, pubkey))
        ciphertext = self._encrypt(secret, plaintext)
        return Ciphertext(
            ephemeral_public_key=pubkey,
            dek_ciphertexts=[],
            envelope=ciphertext,
        )

    def decrypt_envelope(
        self,
        privkey: PrivateKey,
        pubkey: PublicKey,
        envelope: bytes,
    ) -> bytes:
        """Inverse of ``envelope_reply``."""
        secret = sum256(self._nike.derive_secret(privkey, pubkey))
        return self._decrypt(secret, envelope)

    # ----- multi-recipient encapsulation -----

    def encapsulate(
        self,
        keys: List[PublicKey],
        payload: bytes,
        *,
        entropy: Optional[Callable[[int], bytes]] = None,
    ) -> Tuple[PrivateKey, Ciphertext]:
        """Encapsulates ``payload`` to one or more recipient pubkeys.

        Returns the ephemeral private key (so the sender can also
        decrypt later replies sent under it) and the Ciphertext.

        When ``entropy`` is given it must return exactly ``n`` bytes per
        call and supplies all randomness, in this fixed order: the
        ephemeral keypair, the 32-byte message key, the envelope nonce,
        then one nonce per recipient DEK. With a deterministic source the
        whole ciphertext is reproducible (used for the voucher seal and
        the cross-language vectors). Go's ``EncapsulateWithEntropy``
        consumes its ``io.Reader`` in the same order.
        """
        if not keys:
            raise ValueError("encapsulate requires at least one recipient key")
        if entropy is None:
            eph_pub, eph_priv = self._nike.generate_keypair()
            msg_key = os.urandom(_MSG_KEY_SIZE)
        else:
            eph_pub, eph_priv = self._nike.generate_keypair_from_entropy(entropy)
            msg_key = entropy(_MSG_KEY_SIZE)
        secrets = [
            sum256(self._nike.derive_secret(eph_priv, k)) for k in keys
        ]
        envelope = self._encrypt(
            msg_key, payload, entropy(_NONCE_SIZE) if entropy else None
        )
        dek_cts: List[bytes] = []
        for s in secrets:
            ct = self._encrypt(s, msg_key, entropy(_NONCE_SIZE) if entropy else None)
            if len(ct) != DEKSize:
                raise AssertionError("invalid DEK ciphertext size")
            dek_cts.append(ct)
        return eph_priv, Ciphertext(
            ephemeral_public_key=eph_pub,
            dek_ciphertexts=dek_cts,
            envelope=envelope,
        )

    def decapsulate(
        self,
        privkey: PrivateKey,
        ciphertext: Ciphertext,
    ) -> bytes:
        """Trial-decrypts the DEK ciphertexts in order, then opens the envelope."""
        eph_secret = sum256(
            self._nike.derive_secret(privkey, ciphertext.ephemeral_public_key)
        )
        for dek_ct in ciphertext.dek_ciphertexts:
            try:
                msg_key = self._decrypt(eph_secret, dek_ct)
            except InvalidTag:
                continue
            return self._decrypt(msg_key, ciphertext.envelope)
        raise ValueError("failed to trial decrypt: no DEK ciphertext matched this private key")

    # ----- ciphertext serialisation -----

    def ciphertext_from_bytes(self, data: bytes) -> Ciphertext:
        d = cbor2.loads(data)
        if not isinstance(d, dict):
            raise ValueError("MKEM ciphertext: expected a CBOR map")
        try:
            pub_bytes = d["EphemeralPublicKey"]
            dek_cts = d["DEKCiphertexts"]
            envelope = d["Envelope"]
        except KeyError as e:
            raise ValueError(f"MKEM ciphertext: missing field {e.args[0]}") from e
        pub = self._nike.public_key_from_bytes(bytes(pub_bytes))
        return Ciphertext(
            ephemeral_public_key=pub,
            dek_ciphertexts=[bytes(c) for c in dek_cts],
            envelope=bytes(envelope),
        )
