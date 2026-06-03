# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Asserts the Python voucher implementation against the shared cross-language
vector file at ``voucher/testdata/voucher_vectors.json``. The Go suite asserts
against the same file, so the two implementations are pinned to each other.
"""
import json
from pathlib import Path

from hpqc.voucher import voucher_induct, voucher_mint, voucher_open_reply

_VEC = json.loads(
    (
        Path(__file__).resolve().parents[3]
        / "voucher"
        / "testdata"
        / "voucher_vectors.json"
    ).read_text()
)
_uh = bytes.fromhex


def test_mint_vector():
    inp, want = _VEC["inputs"], _VEC["mint"]
    mint = voucher_mint(
        _uh(inp["message_write_cap"]),
        inp["display_name"],
        keypair_seed=_uh(inp["keypair_seed"]),
    )
    assert mint.voucher.hex() == want["voucher"]
    assert mint.voucher_payload.hex() == want["voucher_payload"]
    assert mint.voucher_write_cap.hex() == want["voucher_write_cap"]
    assert mint.voucher_read_cap.hex() == want["voucher_read_cap"]
    assert mint.voucher_secret_key.hex() == want["voucher_secret_key"]
    assert mint.voucher_public_key.hex() == want["voucher_public_key"]


def test_induct_vector():
    inp, mn, want = _VEC["inputs"], _VEC["mint"], _VEC["induct"]
    induct = voucher_induct(
        _uh(mn["voucher"]),
        _uh(mn["voucher_payload"]),
        _uh(inp["who_reply"]),
        salt=_uh(inp["salt"]),
        seal_seed=_uh(inp["seal_seed"]),
    )
    assert induct.display_name == want["display_name"]
    assert induct.mutated_message_read_cap.hex() == want["mutated_message_read_cap"]
    assert induct.sealed_reply.hex() == want["sealed_reply"]
    assert induct.voucher_write_cap.hex() == want["voucher_write_cap"]
    assert induct.voucher_read_cap.hex() == want["voucher_read_cap"]
    assert induct.salt.hex() == want["salt"]


def test_open_reply_vector():
    inp, mn, ind, want = _VEC["inputs"], _VEC["mint"], _VEC["induct"], _VEC["open"]
    opened = voucher_open_reply(
        _uh(mn["voucher_secret_key"]),
        _uh(ind["sealed_reply"]),
        _uh(inp["message_write_cap"]),
    )
    assert opened.who_reply.hex() == want["who_reply"]
    assert opened.salt.hex() == want["salt"]
    assert opened.mutated_message_write_cap.hex() == want["mutated_message_write_cap"]
