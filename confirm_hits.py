#!/usr/bin/env python3
"""
confirm_hits.py — Confirm main.py's bloom candidates against the exact UTXO set.

main.py logs every bloom-filter hit to hits.txt as a `spk=<hex> ...` line. Most
are real, but a bloom filter has false positives (~--fpr per query), so each
candidate must be checked against the actual set before it means anything.

This streams the CSV once, holding only the (small) candidate set in memory —
never the multi-GB UTXO set — and reports each candidate as a REAL HIT or a
bloom false positive.

Usage:
    ./confirm_hits.py hits.txt snapshot/scripts.csv
    ./confirm_hits.py hits.txt utxodump.csv --column script
"""

import argparse
import sys
import time

from utxo_filter import iter_scripts


def load_candidates(path):
    """Map scriptPubKey bytes -> the hits.txt lines that logged it."""
    cands = {}
    with open(path, "r") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tok = line.split(None, 1)[0]
            if not tok.startswith("spk="):
                print(f"  [warn] {path}:{lineno}: no spk= field, skipped", file=sys.stderr)
                continue
            try:
                spk = bytes.fromhex(tok[len("spk="):])
            except ValueError:
                print(f"  [warn] {path}:{lineno}: bad spk hex, skipped", file=sys.stderr)
                continue
            cands.setdefault(spk, []).append(line)
    return cands


def confirm(cands, scripts_path, column):
    """Stream the CSV once; return the subset of candidate scripts present in it."""
    found = set()
    counters = {}
    t0 = time.time()
    for n, spk in enumerate(iter_scripts(scripts_path, column, counters=counters), 1):
        if spk in cands:
            found.add(spk)
            if len(found) == len(cands):
                break  # every candidate confirmed; no need to read the rest
        if n % 10_000_000 == 0:
            print(f"    {n:,} scripts scanned ({time.time() - t0:.0f}s)", file=sys.stderr)
    if counters.get("skipped"):
        print(f"  [warn] skipped {counters['skipped']:,} unparseable rows", file=sys.stderr)
    return found


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("hits", help="candidate log written by main.py (hits.txt)")
    ap.add_argument("scripts", help="the UTXO CSV the bloom filter was built from")
    ap.add_argument("--column", default="script", help="script-hex column name")
    args = ap.parse_args()

    cands = load_candidates(args.hits)
    if not cands:
        print(f"  no candidates in {args.hits}")
        return 0
    print(f"  confirming {len(cands):,} distinct candidate scripts against {args.scripts} ...")

    found = confirm(cands, args.scripts, args.column)

    for spk, lines in cands.items():
        tag = "REAL HIT" if spk in found else "bloom false positive"
        for line in lines:
            print(f"\n  [{tag}]\n      {line}")

    print(f"\n  {'='*58}")
    print(f"  real hits={len(found)}  false positives={len(cands) - len(found)}")
    print(f"  {'='*58}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
