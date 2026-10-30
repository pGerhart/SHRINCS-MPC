"""Known-answer vectors from the SHRINCS BIP reference implementation.

usage: python3 -I scripts/gen_vectors.py <shrincs-bip>/impl shrincs/tests/vectors

Writes wots_c.txt (sk_seed pk_seed height index balanced depth digest pk sig),
shrincs.txt for a balanced key and uxmss.txt for an unbalanced key of depth 70
(seed depth pk, then per signature state msg ctx sig, state "sl" when stateless).
"""
import hashlib
import os
import sys

sys.path.insert(0, sys.argv[1])
from shrincs import (  # noqa: E402
    FXMSS_SHAPE_BALANCED, shrincs_keygen, shrincs_sign, shrincs_verify,
    wots_c_pubkey_from_sig, wots_c_pubkey_gen, wots_c_sign,
)

out = sys.argv[2]
os.makedirs(out, exist_ok=True)


def h(tag: str, i: int) -> bytes:
    return hashlib.sha256(f"{tag}/{i}".encode()).digest()


with open(os.path.join(out, "wots_c.txt"), "w") as f:
    cases = [(254, 1, False, 31), (224, 1, False, 31), (224, 0, False, 31), (250, 17, True, 5), (0, 2**64 - 1, False, 255)]
    for i, (height, index, balanced, depth) in enumerate(cases):
        sk_seed, pk_seed, digest = h("sk", i)[:16], h("pk", i)[:16], h("msg", i)
        pk = wots_c_pubkey_gen(sk_seed, pk_seed, height, index, balanced, depth)
        sig = wots_c_sign(digest, sk_seed, pk_seed, height, index, balanced, depth)
        assert wots_c_pubkey_from_sig(sig, digest, pk_seed, height, index) == pk
        print(sk_seed.hex(), pk_seed.hex(), height, index, int(balanced), depth, digest.hex(), pk.hex(), sig.hex(), file=f)

with open(os.path.join(out, "shrincs.txt"), "w") as f:
    seed, depth = h("seed", 0)[:48] + h("seed", 1)[:16], 2
    sk, pk = shrincs_keygen(seed[:48], bytes([FXMSS_SHAPE_BALANCED, depth]))
    print(seed[:48].hex(), depth, pk.hex(), file=f)
    for state, msg, ctx in [(0, b"first", b""), (3, b"last leaf", b"ctx"), (None, b"stateless", b"ctx")]:
        sig = shrincs_sign(msg, ctx, sk, state, None)
        assert shrincs_verify(msg, sig, ctx, pk)
        print("sl" if state is None else state, msg.hex(), ctx.hex() or "-", sig.hex(), file=f)

with open(os.path.join(out, "uxmss.txt"), "w") as f:
    from shrincs import FXMSS_SHAPE_UNBALANCED
    seed, depth = h("useed", 0) + h("useed", 1)[:16], 70
    sk, pk = shrincs_keygen(seed, bytes([FXMSS_SHAPE_UNBALANCED, depth]))
    print(seed.hex(), depth, pk.hex(), file=f)
    for state, msg, ctx in [(0, b"shallow", b""), (69, b"deep leaf", bytes(range(255)))]:
        sig = shrincs_sign(msg, ctx, sk, state, None)
        assert shrincs_verify(msg, sig, ctx, pk)
        print(state, msg.hex(), ctx.hex() or "-", sig.hex(), file=f)
