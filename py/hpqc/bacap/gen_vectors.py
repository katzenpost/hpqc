# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Generate the BACAP vector files from testvectors/bacap/inputs.json.

The Go generator (testvectors/cmd/generate) and CryptWalker's Lean
implementation generate the same files from the same inputs; the three must
agree on every value. See testvectors/README.md for the inputs format.

    python -m hpqc.bacap.gen_vectors --inputs testvectors/bacap/inputs.json --out DIR
"""
from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .stateless import MessageBoxIndex, ReadCap, WriteCap, _hkdf_blake2b
from hpqc.sign.ed25519 import SigningKey as BlindableSigningKey

FORMAT_VERSION = 1
GENERATOR = "github.com/katzenpost/hpqc/testvectors/cmd/generate"

FILE_ORDER = [
    "message_box_index", "box_id", "encrypt", "mutate_kdf_state",
    "layout", "tombstone", "position", "negative",
]


def deterministic_bytes(label: str, name: str, n: int) -> bytes:
    """The Go generator's deterministicBytes: HKDF-BLAKE2b-512 over a label."""
    return _hkdf_blake2b(b"hpqc-vector-seed-" + label.encode(), b"", name.encode(), n)


def spec_bytes(spec: Optional[dict]) -> bytes:
    if spec is None:
        return b""
    if "hex" in spec:
        return bytes.fromhex(spec["hex"])
    if "utf8" in spec:
        return spec["utf8"].encode()
    if "repeat" in spec:
        return bytes([spec["repeat"]["byte"]]) * spec["repeat"]["count"]
    if "derive" in spec:
        d = spec["derive"]
        return deterministic_bytes(d["label"], d["name"], d["length"])
    raise ValueError(f"empty bytes spec {spec!r}")


def build_cap(spec: dict) -> WriteCap:
    sk = BlindableSigningKey(spec_bytes(spec["seed"]))
    if spec.get("index") is not None:
        first = MessageBoxIndex.from_bytes(spec_bytes(spec["index"]))
    else:
        start = spec["start_idx64"]
        if isinstance(start, dict):
            b = bytearray(spec_bytes(start["irwin_hall"]))
            b[7] &= 0x3F
            b[15] &= 0x3F
            start = (int.from_bytes(b[:8], "little") + int.from_bytes(b[8:16], "little")) & (2**64 - 1)
        zero = b"\x00" * 32
        first = MessageBoxIndex(start, zero, zero, spec_bytes(spec["hkdf_state"])).next_index()
    return WriteCap(sk, first)


def advanced(idx: MessageBoxIndex, by: int) -> MessageBoxIndex:
    return idx.advance_index_to(idx.idx_64 + by) if by else idx


def reachable(rc: ReadCap, idx: MessageBoxIndex) -> bool:
    start = rc.message_box_index
    if idx.idx_64 < start.idx_64:
        return False
    return start.advance_index_to(idx.idx_64).to_bytes() == idx.to_bytes()


def flipped(b: bytes, i: int) -> bytes:
    out = bytearray(b)
    out[i] ^= 0x01
    return bytes(out)


def generate(inputs: dict) -> Dict[str, dict]:
    """Every BACAP vector file, keyed by its name in inputs.json."""
    caps: Dict[str, WriteCap] = {c["name"]: build_cap(c) for c in inputs["caps"]}

    def file(name: str, vectors: List[dict]) -> dict:
        f = inputs["files"][name]
        return {"format_version": FORMAT_VERSION, "generator": GENERATOR,
                "primitive": f["primitive"], "description": f["description"], "vectors": vectors}

    out: Dict[str, dict] = {}

    vs = []
    for v in inputs["message_box_index"]:
        idx = caps[v["cap"]].message_box_index
        vs.append({"name": v["name"], "initial_index_hex": idx.to_bytes().hex(),
                   "advance_to": idx.idx_64 + v["advance_by"],
                   "expected_index_hex": advanced(idx, v["advance_by"]).to_bytes().hex()})
    out["message_box_index"] = file("message_box_index", vs)

    vs = []
    for v in inputs["box_id"]:
        wc = caps[v["cap"]]
        idx = advanced(wc.message_box_index, v["advance_by"])
        ctx = spec_bytes(v["ctx"])
        box = (idx.box_id_for_context(wc.read_cap(), ctx) if v["use_context"]
               else idx.derive_message_box_id(wc.read_cap().root_public_key))
        vs.append({"name": v["name"], "writecap_hex": wc.to_bytes().hex(), "advance_by": v["advance_by"],
                   "ctx_hex": ctx.hex(), "use_context": v["use_context"], "expected_box_id_hex": box.hex()})
    out["box_id"] = file("box_id", vs)

    vs = []
    for v in inputs["encrypt"]:
        wc = caps[v["cap"]]
        idx = advanced(wc.message_box_index, v["advance_by"])
        ctx, pt = spec_bytes(v["ctx"]), spec_bytes(v["plaintext"])
        box, ct, sig = idx.encrypt_for_context(wc, ctx, pt)
        if idx.decrypt_for_context(box, ctx, ct, sig) != pt:
            raise AssertionError(f"encrypt vector {v['name']}: round trip mismatch")
        vs.append({"name": v["name"], "writecap_hex": wc.to_bytes().hex(), "advance_by": v["advance_by"],
                   "ctx_hex": ctx.hex(), "plaintext_hex": pt.hex(), "expected_box_id_hex": box.hex(),
                   "expected_ciphertext_hex": ct.hex(), "expected_signature_hex": sig.hex()})
    out["encrypt"] = file("encrypt", vs)

    vs = []
    for v in inputs["mutate_kdf_state"]:
        wc = caps[v["cap"]]
        salt, rctx = spec_bytes(v["salt"]), spec_bytes(v["read_ctx"])
        m = advanced(wc.message_box_index, v["advance_by"]).mutate_kdf_state(salt)
        vs.append({"name": v["name"], "writecap_hex": wc.to_bytes().hex(), "advance_by": v["advance_by"],
                   "salt_hex": salt.hex(), "read_ctx_hex": rctx.hex(),
                   "expected_mutated_index_hex": m.to_bytes().hex(),
                   "expected_mutated_box_id_hex": m.box_id_for_context(wc.read_cap(), rctx).hex()})
    out["mutate_kdf_state"] = file("mutate_kdf_state", vs)

    vs = []
    for v in inputs["layout"]:
        wc = caps[v["cap"]]
        rc = wc.read_cap()
        idx = wc.message_box_index
        vs.append({"name": v["name"], "writecap_hex": wc.to_bytes().hex(),
                   "expected_root_public_key_hex": bytes(rc.root_public_key).hex(),
                   "expected_readcap_hex": rc.to_bytes().hex(),
                   "expected_index_hex": idx.to_bytes().hex(), "expected_idx64": idx.idx_64})
    out["layout"] = file("layout", vs)

    vs = []
    for v in inputs["tombstone"]:
        wc = caps[v["cap"]]
        idx = advanced(wc.message_box_index, v["advance_by"])
        ctx = spec_bytes(v["ctx"])
        box, sig = idx.sign_box(wc, ctx, b"")
        if idx.decrypt_for_context(box, ctx, b"", sig) != b"":
            raise AssertionError(f"tombstone vector {v['name']}: does not open")
        vs.append({"name": v["name"], "writecap_hex": wc.to_bytes().hex(), "advance_by": v["advance_by"],
                   "ctx_hex": ctx.hex(), "expected_box_id_hex": box.hex(), "expected_signature_hex": sig.hex()})
    out["tombstone"] = file("tombstone", vs)

    vs = []
    for v in inputs["position"]:
        wc = caps[v["cap"]]
        rc = wc.read_cap()
        start = wc.message_box_index
        kind = v["kind"]
        if kind == "advance":
            idx = advanced(start, v["advance_by"])
        elif kind == "foreign":
            idx = dataclasses.replace(caps[v["other_cap"]].message_box_index,
                                      idx_64=start.idx_64 + v["idx64_offset"])
        elif kind == "mutated":
            idx = advanced(start.mutate_kdf_state(spec_bytes(v["salt"])), v["advance_by"])
        elif kind == "tampered":
            if v["field"] != "hkdf_state":
                raise ValueError(f"tampered: unknown field {v['field']}")
            t = advanced(start, v["advance_by"])
            hs = bytearray(t.hkdf_state)
            hs[v["byte"]] ^= v["xor"]
            idx = dataclasses.replace(t, hkdf_state=bytes(hs))
        elif kind == "behind":
            rc = rc.with_message_box_index(advanced(start, v["rebase_advance_by"]))
            idx = start
        else:
            raise ValueError(f"unknown position kind {kind}")
        vs.append({"name": v["name"], "readcap_hex": rc.to_bytes().hex(), "index_hex": idx.to_bytes().hex(),
                   "reachable": reachable(rc, idx), "description": v["description"]})
    out["position"] = file("position", vs)

    vs = []
    for v in inputs["negative"]:
        n: dict = {"name": v["name"], "operation": v["operation"], "category": v["category"],
                   "description": v["description"]}
        fields: dict = {}
        op = v["operation"]
        if op == "advance_index_to":
            idx = caps[v["cap"]].message_box_index
            fields["index_hex"] = idx.to_bytes().hex()
            fields["advance_to"] = idx.idx_64 - v["rewind_by"]
        elif op == "next_index":
            fields["index_hex"] = advanced(caps[v["cap"]].message_box_index, v["index_advance_by"]).to_bytes().hex()
        elif op in ("decrypt", "verify_box", "open"):
            wc = caps[v["cap"]]
            src = v["source"]
            sidx = advanced(wc.message_box_index, src["advance_by"])
            if src["kind"] == "encrypt":
                box, ct, sig = sidx.encrypt_for_context(wc, spec_bytes(src["ctx"]), spec_bytes(src["plaintext"]))
            elif src["kind"] == "tombstone":
                box, sig = sidx.sign_box(wc, spec_bytes(src["ctx"]), b"")
                ct = b""
            else:
                raise ValueError(f"unknown source kind {src['kind']}")
            flip = v.get("flip")
            if flip is not None:
                if flip["field"] == "ciphertext":
                    ct = flipped(ct, flip["byte"])
                elif flip["field"] == "signature":
                    sig = flipped(sig, flip["byte"])
                else:
                    raise ValueError(f"unknown flip field {flip['field']}")
            fields.update(writecap_hex=wc.to_bytes().hex(), advance_by=v["advance_by"],
                          ctx_hex=spec_bytes(v.get("ctx")).hex(), box_id_hex=box.hex(),
                          ciphertext_hex=ct.hex(), signature_hex=sig.hex())
        elif op in ("parse_message_box_index", "parse_read_cap", "parse_write_cap"):
            fields["blob_hex"] = edit_blob(v["blob"], caps).hex()
        else:
            raise ValueError(f"unknown operation {op}")
        # The Go struct's field order; empty strings and an unset advance_to are
        # left out, and advance_by is always present.
        for key in ("blob_hex", "index_hex", "advance_to", "writecap_hex", "advance_by",
                    "ctx_hex", "box_id_hex", "ciphertext_hex", "signature_hex"):
            if key == "advance_by":
                n[key] = fields.get(key, 0)
            elif key in fields and fields[key] != "":
                n[key] = fields[key]
        vs.append(n)
    out["negative"] = file("negative", vs)
    return out


def edit_blob(blob: dict, caps: Dict[str, WriteCap]) -> bytes:
    wc = caps[blob["cap"]]
    frm = blob["from"]
    if frm == "index":
        b = wc.message_box_index.to_bytes()
    elif frm == "readcap":
        b = wc.read_cap().to_bytes()
    elif frm == "writecap":
        b = wc.to_bytes()
    else:
        raise ValueError(f"unknown blob source {frm}")
    e = blob["edit"]
    kind = e["kind"]
    if kind == "empty":
        return b""
    if kind == "truncate":
        return b[: len(b) - e["count"]]
    if kind == "append_zero":
        return b + b"\x00" * e["count"]
    if kind == "replace":
        if e.get("public_key_of"):
            w = caps[e["public_key_of"]].to_bytes()[32:64]
        else:
            w = spec_bytes(e["bytes"])
        out = bytearray(b)
        out[e["offset"]: e["offset"] + len(w)] = w
        return bytes(out)
    raise ValueError(f"unknown blob edit {kind}")


def main(argv: Optional[List[str]] = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--inputs", default="testvectors/bacap/inputs.json")
    ap.add_argument("--out", required=True, help="directory to write the vector files into")
    args = ap.parse_args(argv)
    files = generate(json.loads(Path(args.inputs).read_text()))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name in FILE_ORDER:
        (out / f"{name}.json").write_text(json.dumps(files[name], indent=2) + "\n")
        print("wrote", out / f"{name}.json")


if __name__ == "__main__":
    main()
