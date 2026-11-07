# Constructions

How hpqc builds hybrids and protocols out of its primitives. Back to the
[README](../README.md); the scheme names are in [schemes.md](schemes.md).

## NIKE and KEM

A NIKE (non-interactive key exchange) is what is usually meant by
Diffie-Hellman: two parties each derive the same shared secret from their own
private key and the other's public key, with no interaction beyond publishing
those keys. A KEM (key encapsulation mechanism) works differently:
encapsulation takes a public key and returns a ciphertext and a freshly
generated shared secret, and the recipient recovers the same secret by
decapsulating the ciphertext with its private key.

Each family, and the signature schemes, is defined by three interfaces,
`Scheme`, `PublicKey` and `PrivateKey`:
[nike](https://pkg.go.dev/github.com/katzenpost/hpqc/nike#Scheme),
[kem](https://pkg.go.dev/github.com/katzenpost/hpqc/kem#Scheme) and
[sign](https://pkg.go.dev/github.com/katzenpost/hpqc/sign#Scheme). Code
written against them can switch primitives, or move to a hybrid, without
other changes.

## NIKE to KEM adapter

`kem/adapter` turns any NIKE into a KEM with a hashed ElGamal construction:

```
ENCAPSULATE(pk_recipient):
    pk_eph, sk_eph = GEN_KEYPAIR(RNG)
    ss = DH(sk_eph, pk_recipient)        // rejected if all zero
    return ct = pk_eph, key = PRF(ss, pk_recipient || pk_eph)

DECAPSULATE(sk_recipient, ct = pk_eph):
    ss = DH(sk_recipient, pk_eph)
    return PRF(ss, pk_recipient || pk_eph)
```

The deployed PRF is a BLAKE2b XOF keyed by `ss`, or by BLAKE2b-256 of `ss`
when `ss` is not 32 bytes.

## KEM combiner

The [KEM Combiners paper](https://eprint.iacr.org/2018/024.pdf) observes that
a hybrid built with a combiner that is not security preserving loses IND-CCA2
security if one of its KEMs lacks it. With a security-preserving combiner, the
hybrid is IND-CCA2 secure as long as one of its KEMs is.

`kem/combiner` combines any number of KEMs with the split-PRF construction of
that paper (Lemma 8), using BLAKE2b-256 in keyed mode as the PRF:

```
key_i  = BLAKE2b-256(ss_i)
hash_i = BLAKE2b-256(key = key_i,
                     msg = "splitprf-v1" || u32be(n) ||
                           u32be(len(ct_1)) || ct_1 || ... || u32be(len(ct_n)) || ct_n)
return hash_1 XOR ... XOR hash_n
```

This is why hpqc registers its own `MLKEM768-X25519` alongside `XWING`, which
pre-combines the same two primitives.

## MKEM

[`protocols/mkem`](https://pkg.go.dev/github.com/katzenpost/hpqc/protocols/mkem)
encrypts one message to many recipients over any NIKE. Each recipient gets
its own wrapping of the message key, so the ciphertext grows by one wrapping
per recipient.

## Sealed box

[`protocols/sealedbox`](https://pkg.go.dev/github.com/katzenpost/hpqc/protocols/sealedbox)
is anonymous public-key encryption to one recipient over any NIKE, in the
sense of libsodium's `crypto_box_seal`. The sender is not authenticated. The
key derivation differs from libsodium's, so the two do not interoperate even
over X25519. With a hybrid NIKE such as `X25519-CTIDH1024` it is
post-quantum. A sealed box adds the NIKE public key size plus 16 bytes to its
plaintext; for one recipient that is smaller than MKEM.
