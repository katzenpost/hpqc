"""
This is near-verbatim port of blinded25519.go written with a little help from
the author of the original (3-bit hacker).

>>> msg = b"Hello World"
>>> a = SigningKey(b"1" * 32)
>>> A = a.verify_key
>>> assert A.verify(a.sign(msg)) == msg
>>> factor1 = b"2" * 32
>>> b = a.blind(factor1)
>>> B = A.blind(factor1)
>>> assert B.verify(b.sign(msg)) == msg
>>> factor2 = b"3" * 32
>>> c = b.blind(factor2)
>>> C = B.blind(factor2)
>>> assert C.verify(c.sign(msg)) == msg
>>> c2 = a.blind(factor2).blind(factor1)
>>> C2 = A.blind(factor2).blind(factor1)
>>> assert bytes(c2) == bytes(c)
>>> assert bytes(C2) == bytes(C)
>>> assert C2.verify(c2.sign(msg)) == msg
"""

import hashlib
import nacl.signing
from nacl.bindings import (
    crypto_scalarmult_ed25519,
    crypto_scalarmult_ed25519_base_noclamp,
)

Sum512 = lambda s: hashlib.sha512(s).digest()
Sum512_256 = lambda s: hashlib.new("sha512-256", s).digest()


class scalar:
    """
    This is the parts of https://pkg.go.dev/filippo.io/edwards25519#Scalar
    which were needed for verbatim porting hpqc's blinded25519.go to Python.

    Note that unlike the golang, this is just a utility class of static
    methods.
    """

    l = 2**252 + 27742317777372353535851937790883648493

    @staticmethod
    def Multiply(x: bytes, y: bytes) -> bytes:
        return (
            (
                int.from_bytes(x, byteorder="little")
                * int.from_bytes(y, byteorder="little")
            )
            % scalar.l
        ).to_bytes(length=32, byteorder="little")

    @staticmethod
    def MultiplyAdd(x: bytes, y: bytes, z: bytes) -> bytes:
        return (
            (
                int.from_bytes(x, byteorder="little")
                * int.from_bytes(y, byteorder="little")
                + int.from_bytes(z, byteorder="little")
            )
            % scalar.l
        ).to_bytes(length=32, byteorder="little")

    @staticmethod
    def SetUniformBytes(b: bytes) -> bytes:
        "mod l"
        return (int.from_bytes(b, byteorder="little") % scalar.l).to_bytes(
            length=32, byteorder="little"
        )

    @staticmethod
    def clamp(b: bytes) -> bytes:
        b = list(b)
        b[0] &= 248
        b[31] &= 63
        b[31] |= 64
        b = int.from_bytes(bytes(b), byteorder="little")
        b %= scalar.l
        return b.to_bytes(byteorder="little", length=32)


class SigningKey(nacl.signing.SigningKey):
    def __init__(self, *a, **kw):
        super(SigningKey, self).__init__(*a, **kw)
        self.verify_key = VerifyKey(self.verify_key.encode())

    def blind(self, factor):
        digest = Sum512(self.encode())[:32]
        clamped = scalar.clamp(digest)
        return BlindedSigningKey(clamped).blind(factor)


class BlindedSigningKey(SigningKey):
    def __init__(self, *a, **kw):
        nacl.signing.SigningKey.__init__(self, *a, **kw)
        self.verify_key = VerifyKey(
            crypto_scalarmult_ed25519_base_noclamp(self.encode())
        )

    def sign(self, message):
        "this returns signature concatenated with message, to match nacl's API"
        digest1 = Sum512(self.encode())
        md = Sum512(digest1[32:] + message + digest1[33:])
        mdReduced = scalar.SetUniformBytes(md)
        encodedR = crypto_scalarmult_ed25519_base_noclamp(mdReduced)
        hramDigest = Sum512(encodedR + self.verify_key.encode() + message)
        hramDigestReduced = scalar.SetUniformBytes(hramDigest)
        sNew = scalar.MultiplyAdd(hramDigestReduced, self.encode(), mdReduced)
        signature = encodedR + sNew
        return signature + message

    def blind(self, factor):
        return BlindedSigningKey(
            scalar.Multiply(self.encode(), scalar.clamp(Sum512_256(factor)))
        )


class VerifyKey(nacl.signing.VerifyKey):
    def blind(self, factor):
        return VerifyKey(crypto_scalarmult_ed25519(Sum512_256(factor), self.encode()))


if __name__ == "__main__":
    import doctest
    import os
    from base64 import b64encode, b64decode

    doctest.testmod(verbose=True)

    tests = [
        line.split(b",")
        for line in open(os.path.dirname(__file__) + "/kat.csv")
        .read()
        .strip()
        .encode()
        .split(b"\n")
    ]

    for seed, expected_pk, msg, expected_sig, *factors in tests:
        key = SigningKey(seed)
        cur_pk = key.verify_key
        assert expected_pk == b64encode(bytes(cur_pk))
        assert expected_sig == b64encode(key.sign(msg)[:64])
        while factors:
            factor, expected_pk, expected_sig, *factors = factors
            key = key.blind(factor)
            cur_pk = cur_pk.blind(factor)
            assert bytes(cur_pk) == bytes(key.verify_key)
            assert expected_pk == b64encode(bytes(cur_pk))
            sig = key.sign(msg)[:64]
            assert cur_pk.verify(msg, sig) == msg
            assert expected_sig == b64encode(sig)
