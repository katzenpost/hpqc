# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Writes voucher/testdata/voucher_vectors_v2.json: the compact voucher form minted, inducted
and opened from the same inputs as voucher_vectors.json, so Go and Python agree byte for byte.

    python -m hpqc.voucher.gen_vectors_v2 voucher/testdata/voucher_vectors.json > voucher/testdata/voucher_vectors_v2.json
"""
import json
import sys

from .api import voucher_induct, voucher_mint, voucher_open_reply


def vectors(inputs: dict) -> dict:
    uh = bytes.fromhex
    mint = voucher_mint(uh(inputs["message_write_cap"]), inputs["display_name"], keypair_seed=uh(inputs["keypair_seed"]), version=2)
    induct = voucher_induct(mint.voucher, mint.voucher_payload, uh(inputs["who_reply"]), salt=uh(inputs["salt"]), seal_seed=uh(inputs["seal_seed"]))
    opened = voucher_open_reply(mint.voucher_secret_key, induct.sealed_reply, uh(inputs["message_write_cap"]))
    return {
        "about": "The compact Contact Voucher form: box 0 is the CBOR array [read_cap, voucher_pub_key, display_name, signature], the signature Ed25519 by the read cap's root key over the CBOR array of the first three, the Voucher the BLAKE2b-256 of box 0; the reply is the sealed box (hpqc protocols/sealedbox over CTIDH1024-X25519, ephemeral key from SHAKE256(seal_seed)) of the CBOR array [who_reply, salt]. Inputs are those of voucher_vectors.json.",
        "inputs": inputs,
        "mint": {
            "voucher": mint.voucher.hex(),
            "voucher_payload": mint.voucher_payload.hex(),
            "voucher_write_cap": mint.voucher_write_cap.hex(),
            "voucher_read_cap": mint.voucher_read_cap.hex(),
            "voucher_secret_key": mint.voucher_secret_key.hex(),
            "voucher_public_key": mint.voucher_public_key.hex(),
        },
        "induct": {
            "display_name": induct.display_name,
            "mutated_message_read_cap": induct.mutated_message_read_cap.hex(),
            "sealed_reply": induct.sealed_reply.hex(),
            "voucher_write_cap": induct.voucher_write_cap.hex(),
            "voucher_read_cap": induct.voucher_read_cap.hex(),
            "salt": induct.salt.hex(),
        },
        "open": {
            "who_reply": opened.who_reply.hex(),
            "salt": opened.salt.hex(),
            "mutated_message_write_cap": opened.mutated_message_write_cap.hex(),
        },
    }


if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        v1 = json.load(f)
    json.dump(vectors(v1["inputs"]), sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
