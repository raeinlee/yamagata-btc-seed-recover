#!/usr/bin/env python3
"""
utxo_filter_demo.py — Compact set-membership structures over the Bitcoin UTXO set.

Builds and benchmarks three ways to answer "is this scriptPubKey in the set?":

  1. Bloom filter          — random access, 1.44 * log2(1/fpr) bits/elem
  2. BIP158 Golomb-Coded Set — sequential decode, ~log2(1/fpr) + 1.5 bits/elem
  3. Sorted hash-prefix table — random access, log2(n/fpr) bits/elem

The point of the demo: (2) is the near-optimal *wire format* (which is why
Bitcoin uses it for light clients), (1) and (3) are the right *index formats*.
Bitcoin's own history walks this exact tradeoff: BIP37 -> BIP157/158.

No dependencies beyond numpy (+ matplotlib for the chart).

Usage:
    python utxo_filter_demo.py --synthetic 1000000
    python utxo_filter_demo.py --scripts utxos.csv --column scriptpubkey
    python utxo_filter_demo.py --synthetic 500000 --chart out.png
"""

import argparse
import hashlib
import math
import os
import sys
import time

import numpy as np

# --------------------------------------------------------------------------
# BIP158 constants
# --------------------------------------------------------------------------
BIP158_P = 19
BIP158_M = 784931  # ~= 1.497137 * 2**19


# ==========================================================================
# 1. SipHash-2-4, vectorized over numpy arrays
# ==========================================================================
# BIP158 specifies siphash-2-4 as the hash. Python has no batch siphash, so we
# implement it with numpy uint64 arithmetic (which wraps mod 2**64 natively).
# Items are grouped by byte length so each group is a clean (n, L) uint8 matrix.

_SIP_C0 = np.uint64(0x736F6D6570736575)
_SIP_C1 = np.uint64(0x646F72616E646F6D)
_SIP_C2 = np.uint64(0x6C7967656E657261)
_SIP_C3 = np.uint64(0x7465646279746573)


def _rotl(x, b):
    b = np.uint64(b)
    return (x << b) | (x >> np.uint64(64 - b))


def _sipround(v0, v1, v2, v3):
    v0 += v1
    v1 = _rotl(v1, 13)
    v1 ^= v0
    v0 = _rotl(v0, 32)
    v2 += v3
    v3 = _rotl(v3, 16)
    v3 ^= v2
    v0 += v3
    v3 = _rotl(v3, 21)
    v3 ^= v0
    v2 += v1
    v1 = _rotl(v1, 17)
    v1 ^= v2
    v2 = _rotl(v2, 32)
    return v0, v1, v2, v3


def siphash24_fixedlen(data, k0, k1):
    """SipHash-2-4 over an (n, L) uint8 array. Returns (n,) uint64."""
    data = np.ascontiguousarray(data, dtype=np.uint8)
    if data.ndim == 1:
        data = data.reshape(1, -1)
    n, length = data.shape

    k0 = np.uint64(k0)
    k1 = np.uint64(k1)
    v0 = np.full(n, k0 ^ _SIP_C0, dtype=np.uint64)
    v1 = np.full(n, k1 ^ _SIP_C1, dtype=np.uint64)
    v2 = np.full(n, k0 ^ _SIP_C2, dtype=np.uint64)
    v3 = np.full(n, k1 ^ _SIP_C3, dtype=np.uint64)

    nwords = length // 8
    tail = length % 8

    with np.errstate(over="ignore"):
        for w in range(nwords):
            chunk = data[:, w * 8 : (w + 1) * 8].astype(np.uint64)
            m = np.zeros(n, dtype=np.uint64)
            for byte in range(8):  # little-endian
                m |= chunk[:, byte] << np.uint64(8 * byte)
            v3 ^= m
            v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
            v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
            v0 ^= m

        # final word: remaining bytes in the low position, length in the top byte
        m = np.full(n, np.uint64((length & 0xFF) << 56), dtype=np.uint64)
        if tail:
            chunk = data[:, nwords * 8 :].astype(np.uint64)
            for byte in range(tail):
                m |= chunk[:, byte] << np.uint64(8 * byte)
        v3 ^= m
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
        v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)
        v0 ^= m

        v2 ^= np.uint64(0xFF)
        for _ in range(4):
            v0, v1, v2, v3 = _sipround(v0, v1, v2, v3)

    return v0 ^ v1 ^ v2 ^ v3


def siphash24_ragged(items, k0, k1):
    """SipHash-2-4 over a list of variable-length bytes. Returns (n,) uint64.

    Groups by length so each group hits the vectorized fixed-length path.
    scriptPubKeys only come in a handful of lengths, so this is ~2-5 groups.
    """
    n = len(items)
    out = np.zeros(n, dtype=np.uint64)
    by_len = {}
    for i, it in enumerate(items):
        by_len.setdefault(len(it), []).append(i)
    for length, idxs in by_len.items():
        mat = np.frombuffer(b"".join(items[i] for i in idxs), dtype=np.uint8)
        mat = mat.reshape(len(idxs), length) if length else mat.reshape(len(idxs), 0)
        out[np.asarray(idxs)] = siphash24_fixedlen(mat, k0, k1)
    return out


def _selftest_siphash():
    """Reference vectors from the SipHash paper (key = 00 01 .. 0f)."""
    k = bytes(range(16))
    k0 = int.from_bytes(k[:8], "little")
    k1 = int.from_bytes(k[8:], "little")
    expect = {
        # published vectors (byte sequences read as little-endian u64)
        0: 0x726FDB47DD0E0E31,
        1: 0x74F839C593DC67FD,
        7: 0xAB0200F58B01D137,
        15: 0xA129CA6149BE45E5,
        # real scriptPubKey lengths, cross-checked against a scalar reference
        22: 0x93536795E3A33E88,  # P2WPKH
        25: 0xBCE192DE8A85B8EA,  # P2PKH
        34: 0x12E0B01ABB051238,  # P2TR / P2WSH
    }
    for n, want in expect.items():
        got = int(siphash24_ragged([bytes(range(n))], k0, k1)[0])
        assert got == want, f"siphash len={n}: got {got:#018x} want {want:#018x}"
    return True


# ==========================================================================
# 2. Golomb-Coded Set (BIP158)
# ==========================================================================


def gcs_hash_to_range(items, n, M, key):
    """BIP158 hashed_set_construct: (siphash(k, item) * F) >> 64, F = n*M."""
    k0 = int.from_bytes(key[:8], "little")
    k1 = int.from_bytes(key[8:16], "little")
    h = siphash24_ragged(items, k0, k1)
    F = n * M
    # 128-bit multiply-shift without overflow, via Python-free numpy object math:
    # split h into hi/lo 32-bit halves and do schoolbook multiplication.
    return _mulshift64(h, np.uint64(F))


def _mulshift64(a, b):
    """(a * b) >> 64 for uint64 a (array) and uint64 b (scalar), exactly."""
    a_hi = (a >> np.uint64(32)).astype(np.uint64)
    a_lo = (a & np.uint64(0xFFFFFFFF)).astype(np.uint64)
    b_hi = np.uint64(int(b) >> 32)
    b_lo = np.uint64(int(b) & 0xFFFFFFFF)
    with np.errstate(over="ignore"):
        ll = a_lo * b_lo
        lh = a_lo * b_hi
        hl = a_hi * b_lo
        hh = a_hi * b_hi
        mid = (
            (ll >> np.uint64(32))
            + (lh & np.uint64(0xFFFFFFFF))
            + (hl & np.uint64(0xFFFFFFFF))
        )
        return (
            hh + (lh >> np.uint64(32)) + (hl >> np.uint64(32)) + (mid >> np.uint64(32))
        )


def gcs_encoded_bits(sorted_vals, P=BIP158_P):
    """Exact bit length of the Golomb-Rice encoding, without building it."""
    deltas = np.diff(sorted_vals, prepend=np.uint64(0))
    quotients = deltas >> np.uint64(P)
    return int(quotients.sum()) + len(sorted_vals) * (1 + P)


def gcs_build(items, P=BIP158_P, M=BIP158_M, key=b"\x00" * 16):
    """Build a BIP158-style GCS. Returns (filter_bytes, n_distinct)."""
    n = len(items)
    vals = gcs_hash_to_range(items, n, M, key)
    vals = np.unique(vals)  # sorted + deduped, as the BIP requires
    n_dist = len(vals)

    deltas = np.diff(vals, prepend=np.uint64(0))
    q = (deltas >> np.uint64(P)).astype(np.int64)
    r = (deltas & np.uint64((1 << P) - 1)).astype(np.uint64)

    lengths = q + 1 + P
    ends = np.cumsum(lengths)
    starts = ends - lengths
    total_bits = int(ends[-1])

    bits = np.zeros(total_bits, dtype=np.uint8)

    # unary: q ones, then an implicit 0 (already zero)
    total_ones = int(q.sum())
    if total_ones:
        # ragged range: for each i, positions starts[i] .. starts[i]+q[i]-1
        rep_start = np.repeat(starts, q)
        within = np.arange(total_ones) - np.repeat(np.cumsum(q) - q, q)
        bits[rep_start + within] = 1

    # remainder: P bits, MSB first
    shifts = np.arange(P - 1, -1, -1, dtype=np.uint64)
    rbits = ((r[:, None] >> shifts[None, :]) & np.uint64(1)).astype(np.uint8)
    rpos = (starts + q + 1)[:, None] + np.arange(P)[None, :]
    bits[rpos.ravel()] = rbits.ravel()

    return np.packbits(bits).tobytes(), n_dist


def gcs_decode(filter_bytes, n, P=BIP158_P):
    """Sequentially decode a GCS back to its sorted value array.

    This is the honest access pattern: GCS has no random access. Real light
    clients decode a whole (small, per-block) filter in one streaming pass.
    """
    out = np.empty(n, dtype=np.uint64)
    data = filter_bytes
    pos = 0
    acc = 0
    mask = (1 << P) - 1
    for i in range(n):
        q = 0
        while True:
            bit = (data[pos >> 3] >> (7 - (pos & 7))) & 1
            pos += 1
            if not bit:
                break
            q += 1
        r = 0
        for _ in range(P):
            r = (r << 1) | ((data[pos >> 3] >> (7 - (pos & 7))) & 1)
            pos += 1
        acc += (q << P) + r
        out[i] = acc
    return out


# ==========================================================================
# 3. Bloom filter
# ==========================================================================


class BloomFilter:
    def __init__(self, n, bits_per_elem, key=b"\x01" * 16):
        self.n = n
        self.m = max(8, int(n * bits_per_elem))
        self.k = max(1, round(bits_per_elem * math.log(2)))
        self.key = key
        self._bits = None  # packed uint8, one bit per slot
        self.k0 = int.from_bytes(key[:8], "little")
        self.k1 = int.from_bytes(key[8:16], "little")

    def _positions(self, items):
        """Kirsch-Mitzenmacher double hashing: h_i = h1 + i*h2 (mod m)."""
        h1 = siphash24_ragged(items, self.k0, self.k1)
        h2 = siphash24_ragged(items, self.k0 ^ 0x9E3779B97F4A7C15, self.k1)
        h2 = h2 | np.uint64(1)  # keep h2 odd so the probe sequence spans m
        m = np.uint64(self.m)
        with np.errstate(over="ignore"):
            return np.stack(
                [(h1 + np.uint64(i) * h2) % m for i in range(self.k)], axis=1
            )

    def build(self, items):
        scratch = np.zeros(self.m, dtype=np.uint8)  # byte-per-bit while building
        scratch[self._positions(items).ravel()] = 1
        self._bits = np.packbits(scratch)
        del scratch
        return self

    def build_stream(self, items_iter, chunk=1_000_000, progress=None):
        """Build from an iterator, one chunk at a time — for sets too big for RAM.

        Only the packed bit array (~m/8 bytes) plus a single chunk's hash
        positions are ever resident, so this scales to the full UTXO set without
        materializing it. `progress(seen)` is called after each flushed chunk.
        Bits are set MSB-first per byte, matching build()/contains().
        """
        self._bits = np.zeros((self.m + 7) // 8, dtype=np.uint8)
        seen = 0

        def flush(buf):
            pos = self._positions(buf).ravel()
            bit = np.uint8(1) << (7 - (pos & 7).astype(np.uint8))
            np.bitwise_or.at(self._bits, pos >> 3, bit)  # unbuffered: dup-safe

        buf = []
        for it in items_iter:
            buf.append(it)
            if len(buf) >= chunk:
                flush(buf)
                seen += len(buf)
                buf.clear()
                if progress:
                    progress(seen)
        if buf:
            flush(buf)
            seen += len(buf)
            if progress:
                progress(seen)
        return self

    def save(self, path):
        """Persist the built filter (bit array + params) to a .npz cache file."""
        if self._bits is None:
            raise ValueError("nothing to save — build the filter first")
        np.savez(
            path,
            bits=self._bits,
            params=np.array([self.m, self.k, self.n], dtype=np.int64),
            key=np.frombuffer(self.key, dtype=np.uint8),
        )
        return self

    @classmethod
    def load(cls, path):
        """Reload a filter saved by save(), skipping any re-read of the source CSV."""
        d = np.load(path)
        m, k, n = (int(x) for x in d["params"])
        key = d["key"].tobytes()
        bf = cls.__new__(cls)
        bf.n, bf.m, bf.k, bf.key = n, m, k, key
        bf.k0 = int.from_bytes(key[:8], "little")
        bf.k1 = int.from_bytes(key[8:16], "little")
        bf._bits = d["bits"]
        return bf

    def contains(self, items):
        pos = self._positions(items)
        byte = self._bits[pos >> 3]
        bit = (byte >> (7 - (pos & 7).astype(np.uint8))) & 1
        return bit.all(axis=1)

    @property
    def nbytes(self):
        return int(self._bits.nbytes)

    def theoretical_fpr(self):
        return (1 - math.exp(-self.k * self.n / self.m)) ** self.k


# ==========================================================================
# 4. Sorted hash-prefix table
# ==========================================================================


class PrefixTable:
    """Truncate each item's hash to b bits, sort, binary search.

    This is the 'obvious' compact DB. It is also exactly what a GCS is,
    before delta-compression — which is the punchline of the demo.
    """

    def __init__(self, prefix_bits, key=b"\x02" * 16):
        self.b = prefix_bits
        self.k0 = int.from_bytes(key[:8], "little")
        self.k1 = int.from_bytes(key[8:16], "little")
        self.table = None

    def _h(self, items):
        return siphash24_ragged(items, self.k0, self.k1) >> np.uint64(64 - self.b)

    def build(self, items):
        self.table = np.unique(self._h(items))
        return self

    def contains(self, items):
        h = self._h(items)
        idx = np.searchsorted(self.table, h)
        idx = np.clip(idx, 0, len(self.table) - 1)
        return self.table[idx] == h

    @property
    def nbytes(self):
        """Bit-packed size (numpy stores uint64 slots; a real build packs)."""
        return math.ceil(len(self.table) * self.b / 8)


# ==========================================================================
# 5. UTXO sources
# ==========================================================================

# Rough testnet scriptPubKey mix (taproot-heavy post-inscriptions).
# Override with real data via --scripts.
SCRIPT_MIX = [
    ("P2TR", 0.42, lambda r, n: _wrap(r, n, 32, b"\x51\x20", b"")),
    ("P2WPKH", 0.28, lambda r, n: _wrap(r, n, 20, b"\x00\x14", b"")),
    ("P2PKH", 0.15, lambda r, n: _wrap(r, n, 20, b"\x76\xa9\x14", b"\x88\xac")),
    ("P2SH", 0.10, lambda r, n: _wrap(r, n, 20, b"\xa9\x14", b"\x87")),
    ("P2WSH", 0.05, lambda r, n: _wrap(r, n, 32, b"\x00\x20", b"")),
]


def _wrap(rng, n, hashlen, prefix, suffix):
    raw = rng.integers(0, 256, size=(n, hashlen), dtype=np.uint8)
    return [prefix + bytes(row) + suffix for row in raw]


def synthetic_scripts(n, seed=0):
    rng = np.random.default_rng(seed)
    out = []
    for name, share, gen in SCRIPT_MIX:
        cnt = int(n * share)
        if cnt:
            out.extend(gen(rng, cnt))
    while len(out) < n:
        out.append(SCRIPT_MIX[0][2](rng, 1)[0])
    rng.shuffle(out)
    return out


# bitcoin-utxo-dump stores the *payload* (hash160 / witness program), not the
# full scriptPubKey. BIP158 filters commit to the full script, so rebuild it.
_SPK_TEMPLATE = {
    "p2pkh": (b"\x76\xa9\x14", b"\x88\xac"),
    "p2sh": (b"\xa9\x14", b"\x87"),
    "p2wpkh": (b"\x00\x14", b""),
    "p2wsh": (b"\x00\x20", b""),
    "p2tr": (b"\x51\x20", b""),
}


def rebuild_spk(script_hex, script_type):
    payload = bytes.fromhex(script_hex)
    tmpl = _SPK_TEMPLATE.get((script_type or "").strip().lower())
    if tmpl is None:
        return payload  # p2ms / non-standard / already-full script
    return tmpl[0] + payload + tmpl[1]


def iter_scripts(path, column="script", type_column="type", counters=None):
    """Stream scriptPubKey bytes from a CSV/TSV (or one hex/line), constant memory.

    Yields one full scriptPubKey (bytes) at a time — never holds the file in RAM,
    so it scales to the full multi-GB UTXO dump. Pass a dict as `counters` to
    collect {'kept', 'skipped'} tallies (unparseable rows are skipped silently).
    """
    kept = skipped = 0
    with open(path, "r") as fh:
        header = fh.readline().strip()
        sep = "," if "," in header else ("\t" if "\t" in header else None)
        col, tcol = 0, None
        if sep:
            cols = [c.strip().lower() for c in header.split(sep)]
            if column and column.lower() in cols:
                col = cols.index(column.lower())
                if type_column in cols:
                    tcol = cols.index(type_column)
            else:
                fh.seek(0)  # no header — treat line 1 as data
        else:
            fh.seek(0)
        for line in fh:
            line = line.strip()
            if not line:
                continue
            parts = line.split(sep) if sep else [line]
            try:
                stype = parts[tcol] if tcol is not None and tcol < len(parts) else None
                spk = rebuild_spk(parts[col], stype)
            except (ValueError, IndexError):
                skipped += 1
                continue
            kept += 1
            yield spk
    if counters is not None:
        counters["kept"], counters["skipped"] = kept, skipped


def load_scripts(path, column="script", limit=None, type_column="type"):
    """Read scriptPubKeys into a list (small/limited loads). Streams via iter_scripts.

    Designed for `bitcoin-utxo-dump -f script,type -o utxodump.csv`. For the full
    UTXO set prefer iter_scripts / BloomFilter.build_stream — this materializes
    every kept script in RAM.
    """
    counters = {}
    items = []
    for spk in iter_scripts(path, column, type_column, counters):
        items.append(spk)
        if limit and len(items) >= limit:
            break
    if counters.get("skipped"):
        print(f"  [warn] skipped {counters['skipped']:,} unparseable rows")
    return items


# ==========================================================================
# 6. Benchmark
# ==========================================================================


def human(nbytes):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if nbytes < 1024 or unit == "TiB":
            return f"{nbytes:,.1f} {unit}"
        nbytes /= 1024


def measure_fpr(structure, n_probe, seed=999):
    """Probe with scripts guaranteed not to be in the set (distinct seed space)."""
    rng = np.random.default_rng(seed)
    raw = rng.integers(0, 256, size=(n_probe, 32), dtype=np.uint8)
    probes = [b"\x51\x20" + bytes(row) for row in raw]  # P2TR-shaped, random
    hits = int(np.count_nonzero(structure.contains(probes)))
    return hits / n_probe, probes


def run(items, testnet_n, do_gcs_decode=True, chart=None):
    n = len(items)
    distinct = len(set(items))
    print(f"\n{'='*74}")
    print(
        f"  UTXO SET MEMBERSHIP STRUCTURES  —  n = {n:,} scripts "
        f"({distinct:,} distinct)"
    )
    print(f"{'='*74}\n")

    rows = []

    # ---- 1. GCS (BIP158 parameters) --------------------------------------
    t0 = time.time()
    gcs_bytes, gcs_n = gcs_build(items)
    t_gcs = time.time() - t0
    gcs_bpe = len(gcs_bytes) * 8 / gcs_n
    gcs_fpr = 1 / BIP158_M
    rows.append(
        (
            "GCS (BIP158, P=19 M=784931)",
            len(gcs_bytes),
            gcs_bpe,
            gcs_fpr,
            "sequential",
            t_gcs,
        )
    )

    if do_gcs_decode:
        t0 = time.time()
        decoded = gcs_decode(gcs_bytes, gcs_n)
        t_dec = time.time() - t0
        vals = np.unique(gcs_hash_to_range(items, n, BIP158_M, b"\x00" * 16))
        ok = np.array_equal(decoded, vals)
        print(
            f"  [check] GCS round-trip decode: {'OK' if ok else 'FAILED'} "
            f"({gcs_n:,} elems in {t_dec:.2f}s, "
            f"{gcs_n/max(t_dec,1e-9)/1e3:,.0f}k elem/s)"
        )

    # ---- 2. Bloom, matched to the same FPR --------------------------------
    #  Bloom needs 1.44 * log2(1/fpr) bits/elem to hit the same rate.
    bloom_bpe = math.log2(1 / gcs_fpr) / math.log(2)  # = 1.4427 * log2(1/fpr)
    t0 = time.time()
    bloom = BloomFilter(distinct, bloom_bpe).build(items)
    t_bloom = time.time() - t0
    rows.append(
        (
            f"Bloom filter (k={bloom.k}, matched FPR)",
            bloom.nbytes,
            bloom.nbytes * 8 / distinct,
            bloom.theoretical_fpr(),
            "random O(k)",
            t_bloom,
        )
    )

    # ---- 3. Sorted hash-prefix table --------------------------------------
    #  For FPR f over n entries you need b = log2(n / f) bits per prefix.
    pref_bits = math.ceil(math.log2(distinct / gcs_fpr))
    t0 = time.time()
    ptab = PrefixTable(pref_bits).build(items)
    t_ptab = time.time() - t0
    rows.append(
        (
            f"Sorted prefix table (b={pref_bits})",
            ptab.nbytes,
            ptab.nbytes * 8 / distinct,
            distinct / 2**pref_bits,
            "random O(log n)",
            t_ptab,
        )
    )

    # ---- 4. Raw baseline ---------------------------------------------------
    raw_bytes = sum(len(i) for i in set(items))
    rows.append(
        (
            "Raw scriptPubKeys (no filter)",
            raw_bytes,
            raw_bytes * 8 / distinct,
            0.0,
            "n/a",
            0.0,
        )
    )

    # ---- report -----------------------------------------------------------
    print(
        f"\n  {'structure':<34} {'size':>11} {'bits/el':>8} "
        f"{'FPR':>11} {'access':>15}"
    )
    print(f"  {'-'*34} {'-'*11} {'-'*8} {'-'*11} {'-'*15}")
    for name, sz, bpe, fpr, access, _t in rows:
        fpr_s = "exact" if fpr == 0 else f"1 in {1/fpr:,.0f}"
        print(f"  {name:<34} {human(sz):>11} {bpe:>8.2f} {fpr_s:>11} {access:>15}")

    print(
        f"\n  Information-theoretic floor for FPR=1/{BIP158_M:,}: "
        f"{math.log2(BIP158_M):.2f} bits/element"
    )
    print(
        f"  GCS overhead over the floor: "
        f"{gcs_bpe - math.log2(BIP158_M):+.2f} bits "
        f"({(gcs_bpe/math.log2(BIP158_M)-1)*100:+.1f}%)"
    )
    print(
        f"  Bloom overhead over the floor: "
        f"{bloom.nbytes*8/distinct - math.log2(BIP158_M):+.2f} bits "
        f"({(bloom.nbytes*8/distinct/math.log2(BIP158_M)-1)*100:+.1f}%)"
    )

    # ---- empirical FPR: no false negatives, and FPR tracks theory ---------
    print(f"\n  Correctness: every member must be found (no false negatives).")
    sample = items[: min(50_000, n)]
    print(
        f"    Bloom        {int(bloom.contains(sample).sum()):,}/{len(sample):,} members found"
    )
    print(
        f"    Prefix table {int(ptab.contains(sample).sum()):,}/{len(sample):,} members found"
    )

    n_probe = 400_000
    print(f"\n  Bloom filter FPR sweep — {n_probe:,} non-member probes each:")
    print(
        f"    {'bits/el':>8} {'k':>3} {'size':>10} {'predicted':>11} {'measured':>11}"
    )
    print(f"    {'-'*8} {'-'*3} {'-'*10} {'-'*11} {'-'*11}")
    for bpe in (4, 6, 8, 10, 12, 16):
        bf = BloomFilter(distinct, bpe).build(items)
        meas, _ = measure_fpr(bf, n_probe)
        print(
            f"    {bpe:>8} {bf.k:>3} {human(bf.nbytes):>10} "
            f"{bf.theoretical_fpr():>11.4f} {meas:>11.4f}"
        )
        del bf

    # ---- extrapolate to testnet -------------------------------------------
    # NOTE: GCS and Bloom bits/element are independent of n, so they scale
    # linearly. The prefix table is NOT — it needs log2(n/fpr) bits, so its
    # per-element cost grows with the set. Recompute rather than scale.
    mn = int(testnet_n)
    mn_pref_bits = math.ceil(math.log2(mn / gcs_fpr))
    avg_script = raw_bytes / distinct
    extrap = [
        ("GCS (BIP158, P=19 M=784931)", gcs_bpe),
        (f"Bloom filter (k={bloom.k}, matched FPR)", bloom.nbytes * 8 / distinct),
        (f"Sorted prefix table (b={mn_pref_bits} at this n)", mn_pref_bits),
        ("Raw scriptPubKeys (no filter)", avg_script * 8),
    ]
    print(
        f"\n  Extrapolated to the full testnet UTXO set "
        f"(~{testnet_n/1e6:.0f}M outputs, same 1-in-{1/gcs_fpr:,.0f} FPR):"
    )
    for name, bpe in extrap:
        print(f"    {name:<38} {human(bpe * mn / 8):>11}  ({bpe:.2f} bits/el)")
    print(f"    {'(testnet UTXO set itself, Bitcoin Core)':<38} {'~11 GiB':>11}")

    # ---- build throughput -------------------------------------------------
    print(f"\n  Build time (this machine, pure numpy — a Rust/C++ build is 50-100x):")
    for name, _sz, _bpe, _fpr, _acc, t in rows:
        if t:
            print(f"    {name:<34} {t:>7.2f}s  ({n/t/1e3:>8,.0f}k scripts/s)")

    if chart:
        make_chart(chart, distinct)
    print()
    return rows


def make_chart(path, n):
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fprs = np.logspace(-1, -8, 60)
    floor = np.log2(1 / fprs)
    bloom = floor / math.log(2)
    gcs = floor + 1.5  # Golomb-Rice overhead, approx
    prefix = np.log2(n / fprs)

    fig, ax = plt.subplots(figsize=(9, 5.5))
    ax.plot(fprs, prefix, lw=2, label=f"Sorted prefix table (n={n:,})")
    ax.plot(fprs, bloom, lw=2, label="Bloom filter (optimal k)")
    ax.plot(fprs, gcs, lw=2, label="Golomb-coded set (BIP158)")
    ax.plot(
        fprs,
        floor,
        lw=2,
        ls="--",
        color="0.4",
        label="Information-theoretic floor  log₂(1/ε)",
    )
    ax.axvline(1 / BIP158_M, color="crimson", ls=":", lw=1.5)
    ax.annotate(
        "BIP158\n1 in 784,931",
        (1 / BIP158_M, 4),
        color="crimson",
        fontsize=9,
        ha="left",
        va="bottom",
    )
    ax.set_xscale("log")
    ax.invert_xaxis()
    ax.set_xlabel("false positive rate  ε")
    ax.set_ylabel("bits per element")
    ax.set_title("Cost of set membership over the Bitcoin UTXO set")
    ax.grid(alpha=0.3)
    ax.legend(loc="upper left", fontsize=9)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    print(f"\n  chart -> {path}")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--synthetic",
        type=int,
        metavar="N",
        help="generate N synthetic testnet-shaped scriptPubKeys",
    )
    src.add_argument(
        "--scripts", metavar="FILE", help="CSV/TSV/plain file of scriptPubKey hex"
    )
    ap.add_argument(
        "--column",
        default="script",
        help="column name holding the script hex (default: script)",
    )
    ap.add_argument("--limit", type=int, help="cap scripts read from --scripts")
    ap.add_argument(
        "--testnet-utxos",
        type=float,
        default=173e6,
        help="UTXO count to extrapolate to (default 173e6)",
    )
    ap.add_argument("--chart", metavar="PNG", help="write a size/FPR chart")
    ap.add_argument(
        "--no-decode",
        action="store_true",
        help="skip the GCS round-trip check (slow in pure Python)",
    )
    args = ap.parse_args()

    _selftest_siphash()
    print("  [check] SipHash-2-4 reference vectors: OK")

    if args.synthetic:
        items = synthetic_scripts(args.synthetic)
    else:
        items = load_scripts(args.scripts, args.column, args.limit)
        if not items:
            sys.exit(f"no scripts parsed from {args.scripts}")

    run(items, args.testnet_utxos, do_gcs_decode=not args.no_decode, chart=args.chart)


if __name__ == "__main__":
    main()
