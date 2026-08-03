#!/usr/bin/env python3
"""btc_derive.py — minimal, test-vector-gated BIP39 -> BIP32 -> scriptPubKey derivation.

Pure stdlib (hashlib / hmac): a hand-rolled secp256k1, BIP32 (CKDpriv), BIP39
(entropy -> mnemonic -> seed), and scriptPubKey construction for P2WPKH / P2PKH /
P2TR. No third-party crypto — every primitive is checked against published test
vectors by `selftest()`, which callers MUST run before trusting any output.

scriptPubKey bytes are network-independent, so these are correct for testnet as-is
(testnet only changes the *address* encoding, and coin type in the path is 1').

This is a research / PoC building block: it derives public scripts to test set
membership. It never signs, spends, or moves anything.
"""

import hashlib
import hmac
import os

# --------------------------------------------------------------------------
# secp256k1 (short Weierstrass y^2 = x^3 + 7)
# --------------------------------------------------------------------------
_P = 2**256 - 2**32 - 977
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_G = (_GX, _GY)


def _pt_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None  # point at infinity
    if p == q:
        m = (3 * x1 * x1) * pow(2 * y1, -1, _P) % _P
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (m * m - x1 - x2) % _P
    y3 = (m * (x1 - x3) - y1) % _P
    return (x3, y3)


def _pt_mul(k, p=_G):
    r = None
    k %= _N
    while k:
        if k & 1:
            r = _pt_add(r, p)
        p = _pt_add(p, p)
        k >>= 1
    return r


def _ser_pub(priv):
    """Compressed SEC1 public key (33 bytes) for a private scalar."""
    x, y = _pt_mul(priv)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def _lift_x(x):
    """BIP340 lift_x: the point with even y for a given x (raises if off-curve)."""
    y2 = (pow(x, 3, _P) + 7) % _P
    y = pow(y2, (_P + 1) // 4, _P)
    if (y * y) % _P != y2:
        raise ValueError("x is not on the curve")
    return (x, y if y % 2 == 0 else _P - y)


# --------------------------------------------------------------------------
# hashes
# --------------------------------------------------------------------------
def _sha256(b):
    return hashlib.sha256(b).digest()


def hash160(b):
    return hashlib.new("ripemd160", _sha256(b)).digest()


def _tagged_hash(tag, msg):
    t = _sha256(tag.encode())
    return _sha256(t + t + msg)


# --------------------------------------------------------------------------
# BIP39: entropy -> mnemonic -> seed
# --------------------------------------------------------------------------
_WORDLIST = None
_DEFAULT_WORDLIST = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "bip39_english.txt"
)


def load_wordlist(path=_DEFAULT_WORDLIST):
    global _WORDLIST
    with open(path, "r", encoding="utf-8") as fh:
        words = [w.strip() for w in fh if w.strip()]
    if len(words) != 2048:
        raise ValueError(f"wordlist must have 2048 words, got {len(words)}")
    _WORDLIST = words
    return words


def entropy_to_mnemonic(entropy):
    """BIP39 entropy (16/20/24/28/32 bytes) -> mnemonic sentence."""
    if _WORDLIST is None:
        load_wordlist()
    if len(entropy) % 4 != 0 or not (16 <= len(entropy) <= 32):
        raise ValueError("entropy must be 16..32 bytes, multiple of 4")
    ent_bits = len(entropy) * 8
    cs_bits = ent_bits // 32
    checksum = _sha256(entropy)[0] >> (8 - cs_bits)
    bits = (int.from_bytes(entropy, "big") << cs_bits) | checksum
    total = ent_bits + cs_bits
    words = []
    for i in range(total // 11):
        idx = (bits >> (total - 11 * (i + 1))) & 0x7FF
        words.append(_WORDLIST[idx])
    return " ".join(words)


def mnemonic_to_seed(mnemonic, passphrase=""):
    """BIP39 seed: PBKDF2-HMAC-SHA512, 2048 rounds (the expensive part)."""
    return hashlib.pbkdf2_hmac(
        "sha512",
        mnemonic.encode("utf-8"),
        ("mnemonic" + passphrase).encode("utf-8"),
        2048,
        64,
    )


# --------------------------------------------------------------------------
# BIP32: seed -> master -> child (private derivation)
# --------------------------------------------------------------------------
_HARDENED = 0x80000000


def _hmac512(key, data):
    return hmac.new(key, data, hashlib.sha512).digest()


def master_from_seed(seed):
    I = _hmac512(b"Bitcoin seed", seed)
    return int.from_bytes(I[:32], "big"), I[32:]  # (key, chain code)


def ckd_priv(k, c, i):
    if i & _HARDENED:
        data = b"\x00" + k.to_bytes(32, "big") + i.to_bytes(4, "big")
    else:
        data = _ser_pub(k) + i.to_bytes(4, "big")
    I = _hmac512(c, data)
    ki = (int.from_bytes(I[:32], "big") + k) % _N
    return ki, I[32:]


def parse_path(path):
    """ "m/84'/1'/0'/0/0" -> [0x80000054, 0x80000001, 0x80000000, 0, 0]."""
    out = []
    for part in path.strip().split("/"):
        if part in ("m", ""):
            continue
        hardened = part[-1] in ("'", "h", "H")
        idx = int(part[:-1] if hardened else part)
        out.append(idx + _HARDENED if hardened else idx)
    return out


def derive_priv(seed, indices):
    k, c = master_from_seed(seed)
    for i in indices:
        k, c = ckd_priv(k, c, i)
    return k


# --------------------------------------------------------------------------
# scriptPubKey construction (the bytes stored in the UTXO set)
# --------------------------------------------------------------------------
def spk_p2wpkh(priv):
    """OP_0 <20-byte hash160(pubkey)>  (BIP84)."""
    return b"\x00\x14" + hash160(_ser_pub(priv))


def spk_p2pkh(priv):
    """OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG  (BIP44)."""
    return b"\x76\xa9\x14" + hash160(_ser_pub(priv)) + b"\x88\xac"


def spk_p2tr(priv):
    """OP_1 <32-byte tweaked x-only key>  (BIP86 key-path, no script tree)."""
    x = _pt_mul(priv)[0]
    internal = _lift_x(x)
    t = int.from_bytes(_tagged_hash("TapTweak", x.to_bytes(32, "big")), "big") % _N
    q = _pt_add(internal, _pt_mul(t))
    return b"\x51\x20" + q[0].to_bytes(32, "big")


SCRIPT_FUNCS = {
    "p2wpkh": (spk_p2wpkh, "84'"),  # (builder, BIP purpose)
    "p2pkh": (spk_p2pkh, "44'"),
    "p2tr": (spk_p2tr, "86'"),
}


# --------------------------------------------------------------------------
# self-test — published vectors gate every run
# --------------------------------------------------------------------------
_ABANDON = " ".join(["abandon"] * 11 + ["about"])  # entropy = 16 * 0x00


def selftest():
    load_wordlist()

    # 1. BIP39 mnemonic + checksum construction (no PBKDF2 involved).
    got = entropy_to_mnemonic(b"\x00" * 16)
    assert got == _ABANDON, f"BIP39 mnemonic: {got!r}"

    # 2. secp256k1: G = pubkey(1).
    assert _ser_pub(1).hex() == (
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    )

    # 3. BIP32 test vector 1 (seed = 000102..0f) master key + chain code.
    k, c = master_from_seed(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    assert k.to_bytes(32, "big").hex() == (
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    )
    assert c.hex() == (
        "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
    )

    # 4. End-to-end BIP84 vector: mnemonic -> seed -> m/84'/1'/0'/0/0 pubkey.
    #    Exercises PBKDF2, BIP32 hardened+normal steps, and secp256k1 together.
    seed = mnemonic_to_seed(_ABANDON)
    k0 = derive_priv(seed, parse_path("m/84'/1'/0'/0/0"))
    assert _ser_pub(k0).hex() == (
        "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c"
    ), "BIP84 pubkey mismatch"

    # 5. BIP86 (taproot) key-path vector: m/86'/1'/0'/0/0 tweaked output key.
    kt = derive_priv(seed, parse_path("m/86'/1'/0'/0/0"))
    assert spk_p2tr(kt).hex() == (
        "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
    ), "BIP86 output key mismatch"

    return True


if __name__ == "__main__":
    selftest()
    print("btc_derive selftest: OK (BIP39 + secp256k1 + BIP32 + BIP84 + BIP86)")
