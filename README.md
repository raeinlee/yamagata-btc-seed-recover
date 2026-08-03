# Yamagata — weak-RNG Bitcoin key-recovery PoC

A teaching / research proof-of-concept that shows what happens when a hardware
wallet's "randomness" isn't random. A deliberately weak PRNG (**yamagata**),
seeded from predictable STM32 device registers, is run through the *real* BIP39
→ BIP32 → scriptPubKey derivation used by actual wallets. Because the seed space
is tiny, the harness can **enumerate it, regenerate the keys, and check whether
any of them control a live output in the Bitcoin UTXO set**.

If a regenerated key matches a funded output, the device's RNG is broken and its
funds are recoverable by anyone — that's the whole point of the demonstration.

> **Scope: detection only.** Nothing here builds, signs, or broadcasts a
> transaction, and there is no capability to move funds. It reports *that* a key
> would be recoverable; it does not spend anything. The derivation is otherwise a
> standards-correct wallet implementation (validated against published BIP
> vectors on every startup).

---

## What a result actually means

A **hit** (a derived scriptPubKey found in the UTXO set) is a strong positive: a
full-script match implies the same public key (barring a 2⁻¹⁶⁰ hash collision),
so that regenerated key demonstrably controls a real output.

A **miss / "no candidates"** is *ambiguous* and must not be over-read:

- The UTXO set is only **currently-unspent** outputs, **not** a usage history. A
  key that was used and later emptied looks identical to one never used. This
  tool answers *"does this key control funds right now,"* **not** *"has anyone
  ever used this key."*
- Only the derivation paths / script types you enumerate are checked.
- The snapshot is stale the moment it's taken (the set changes every block).
- Membership is tested against whatever CSV you loaded — pick the network
  deliberately. `DEFAULT_COIN` is `1` (testnet path); the sample data workflow
  below builds a **testnet** set. Deriving mainnet-path scripts and checking them
  against a testnet set is a coverage mismatch, not an "all clear."

So a miss is only meaningful once (a) the pipeline is proven with `--check` and
(b) the enumerated register space actually covers the device. See
`main.py`'s module docstring for the full rationale.

---

## Repository layout

| File | Role |
|------|------|
| `prng.py` | **yamagata** — the non-cryptographic PRNG being modeled. Its entire output is a function of four small, register-bounded inputs, which is exactly the weakness under study. |
| `stm32_uids.py` | Generates realistic STM32 96-bit device UIDs (the `uid` that seeds the PRNG), so the search draws from plausible silicon IDs. |
| `btc_derive.py` | Pure-stdlib, test-vector-gated derivation: hand-rolled secp256k1, BIP39 (entropy→mnemonic→seed), BIP32 (CKDpriv), and P2WPKH/P2PKH/P2TR scriptPubKeys. `selftest()` checks BIP39/BIP32/BIP84/BIP86 vectors before any run. |
| `main.py` | **The harness.** Enumerates the constrained register space → yamagata entropy → keys → membership test against the UTXO set via a streaming, cached bloom filter → logs candidate hits. |
| `confirm_hits.py` | Streams the full CSV once to confirm logged bloom candidates, separating real UTXO hits from bloom false positives. |
| `utxo_filter.py` | Standalone set-membership library + benchmark (Bloom / BIP158 GCS / sorted hash-prefix). Also supplies the `BloomFilter`, `iter_scripts`, and `rebuild_spk` the harness reuses. |
| `bip39_english.txt` | BIP39 English wordlist (2048 words). |
| `tools/txoutset/` | Rust crate (clarkmoody/txoutset) that converts a Bitcoin Core `dumptxoutset` `.dat` snapshot into CSV. |
| `snapshot/` | Gitignored data: the parsed `scripts.csv`, its `*.bloom.npz` cache, etc. |

---

## The pipeline

```
 Bitcoin Core dumptxoutset            tools/txoutset (Rust)          this repo (Python)
┌──────────────────────────┐      ┌───────────────────────┐   ┌────────────────────────────┐
│  utxo.dat  (AssumeUTXO    │ ───► │  txoutset-csv         │──►│  snapshot/scripts.csv      │
│  serialized UTXO set)     │      │  → full scriptPubKeys │   │  (header: script)          │
└──────────────────────────┘      └───────────────────────┘   └────────────┬───────────────┘
                                                                            │  get_bloom(): build once,
                                                                            ▼  cache to scripts.csv.bloom.npz
   yamagata PRNG ── entropy ──► BIP39/BIP32 ──► scriptPubKeys ──► bloom membership ──► hits.txt
   (uid,systick,tr,ssr)          (btc_derive)                       (btc_wallet_seed_gen)     │
                                                                                              ▼
                                                              confirm_hits.py streams the CSV once
                                                              → REAL HIT vs bloom false positive
```

The CSV is read **in full, exactly once**, to build the bloom filter; the filter
is then cached, so later searches load ~590 MB instead of re-reading the 9.4 GB
CSV. There is intentionally **no CSV cap** in the search — a truncated haystack
would produce false "no hits."

---

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install numpy matplotlib
```

- **numpy is required** — startup self-tests run immediately and fail without it.
- **matplotlib** is only needed for `utxo_filter.py --chart`.
- **Rust** (cargo ≥ 1.85, for `edition2024`) is only needed to (re)build the
  `.dat` → CSV converter in `tools/txoutset`.

---

## 1. Prepare a UTXO CSV (from a `dumptxoutset` `.dat`)

The Python never parses the binary dump — that's the Rust tool's job. The
harness only consumes a CSV (or a plain file of one scriptPubKey-hex per line).

**Get the `.dat`.** Either dump it from a synced node…

```bash
bitcoin-cli dumptxoutset /tmp/utxo.dat      # AssumeUTXO serialized UTXO set
```

…or range-download a slice from a snapshot mirror. The `.dat` is a header
followed by a sequential stream of UTXO records, so a truncated prefix still
parses cleanly (the parser just stops at EOF):

```bash
mkdir -p snapshot
curl -H "Range: bytes=0-2147483647" \
  -o snapshot/utxo-935000.partial.dat \
  https://files-vps02.jaonoctus.dev/utxo-935000.dat    # ~2 GiB ≈ 37M records
```

Full snapshots are **8.7–9.7 GiB**; a large prefix is already tens of millions of
real, distinct scriptPubKeys.

**Build the parser and convert to CSV** (`txoutset-csv` column 5 is the full
scriptPubKey hex, so no `type` column is needed):

```bash
cd tools/txoutset && cargo build --release -p txoutset-csv && cd ../..
BIN=tools/txoutset/target/release/txoutset-csv
{ echo "script"; $BIN snapshot/utxo-935000.partial.dat 2>/dev/null | awk -F',' '{print $5}'; } \
  > snapshot/scripts.csv
```

> Alternative source: `bitcoin-utxo-dump -f script,type -o utxodump.csv` reads a
> live chainstate LevelDB and emits *payloads* + a `type` column; `iter_scripts`
> auto-detects that layout and `rebuild_spk` reconstructs the full script.

---

## 2. Build the filter and search

```bash
.venv/bin/python main.py \
  --scripts snapshot/scripts.csv \
  --uids 100 \
  --systick 0..65535 \
  --tr 12:00:00..13:00:00 \
  --ssr 0..255 \
  --scripts-types p2wpkh,p2tr \
  --gap 20
```

First run streams the CSV (two passes: count, then build) and writes
`snapshot/scripts.csv.bloom.npz`. Every later run **loads that cache** and never
touches the big CSV. Bloom hits are appended to `hits.txt` as parseable
`spk=<hex> …` lines (flushed as they're found, so a long run survives
interruption).

Register dimensions are modeled as their **real STM32 encodings**: `--tr` is a
wall-clock window BCD-packed into `RTC_TR` (`12:00:00` → `0x120000`), `--systick`
is the 24-bit `SysTick->VAL` down-counter, `--ssr` is `0..PREDIV_S`. Each accepts
a dim spec (`a`, `a,b,c`, `a..b`, `a..b..step`, `@file`).

---

## 3. Confirm candidates

Bloom hits are *candidates* — mostly real, plus the occasional false positive
(~`--fpr` per query). Confirm them against the actual set without holding it in
RAM:

```bash
./confirm_hits.py hits.txt snapshot/scripts.csv
```

It streams the CSV once, holding only the (small) candidate set, and prints each
`REAL HIT` versus each bloom false positive.

---

## Closed-loop validation (`--check`)

Before trusting *any* null result, prove the harness can rederive a **known**
device key end-to-end. Fund a key generated on the real device, then:

```bash
# uid,tick,tr,ssr = <scriptpubkey-hex>   (tr may be a raw register int or HH:MM:SS)
./main.py --check "0x1234,0,12:00:00,128=0014a1b2...c3"
```

A `MATCH … closed-loop OK` proves PRNG + derivation + your packing assumptions
(`--entropy-bytes`, `--endian`, `--coin`) reproduce the device. Run `--check`
with the **same `--coin` the firmware uses**, or every search will be a
meaningless null. (The startup `selftest()` is weaker — it proves the crypto is
correct, not that your device model is.)

---

## `utxo_filter.py` — standalone membership benchmark

Independent of the key search, this builds and compares three ways to answer
"is this scriptPubKey in the set?":

1. **Bloom filter** — random access, `1.44 · log2(1/fpr)` bits/elem
2. **BIP158 Golomb-Coded Set** — sequential decode, `~log2(1/fpr) + 1.5` bits/elem
3. **Sorted hash-prefix table** — random access, `log2(n/fpr)` bits/elem

The lesson: (2) is the near-optimal *wire* format (why Bitcoin uses it for light
clients), while (1) and (3) are the right *index* formats — the BIP37 → BIP157/158
tradeoff.

```bash
.venv/bin/python utxo_filter.py --synthetic 1000000            # no data needed
.venv/bin/python utxo_filter.py --scripts snapshot/scripts.csv --column script --limit 5000000
.venv/bin/python utxo_filter.py --synthetic 500000 --chart out.png
```

`--synthetic N` generates fake testnet-shaped scripts locally (no node needed).
GCS decode is a pure-Python loop, so `--limit` (or `--no-decode`) keeps a big run
snappy; `--testnet-utxos` sets the extrapolation target.

---

## Selected options

**`main.py`**

| Option | Default | Meaning |
|--------|---------|---------|
| `--scripts CSV` | — | UTXO scriptPubKey CSV (required for a search) |
| `--uids N` | 1 | how many random STM32 UIDs to draw into the search |
| `--systick` | `1..2` | `SysTick->VAL` dim spec, or `full` for `0..reload` |
| `--tr` | `18:00:00..18:01:00` | `RTC_TR` window `HH:MM:SS[..HH:MM:SS[..step_s]]`, or raw ints |
| `--ssr` | `0..255` | `RTC_SSR` sub-second dim spec (`0..PREDIV_S`), or `full` |
| `--scripts-types` | `p2wpkh` | comma list of `p2wpkh,p2pkh,p2tr` |
| `--accounts` / `--gap` | `0` / `1` | account indices / addresses `0..gap-1` per account |
| `--coin` | `0` | BIP44 coin type (testnet = `1`) |
| `--entropy-bytes` / `--endian` | `16` / `big` | firmware packing of yamagata words → BIP39 entropy |
| `--limit N` | — | hard cap on **search loops (seeds)** — the CSV is always read in full |
| `--bloom-cache` / `--rebuild-bloom` | `<scripts>.bloom.npz` | filter cache path / force rebuild |
| `--hits FILE` | `hits.txt` | where bloom candidates are appended |
| `--fpr` | `1e-6` | target bloom false-positive rate (used only when building) |
| `--check SPEC` | — | closed-loop rederivation test (see above) |

---

## Known noise

On this machine's pyenv-built Python 3.12.2, OpenSSL lacks blake2, so `hashlib`
logs a one-time `blake2b`/`blake2s` "unsupported hash type" traceback on first
import. `main.py` swallows exactly that single message with an
import shim; `utxo_filter.py` implements its own vectorized SipHash-2-4 in numpy
and never touches `hashlib`. `btc_derive.py` uses `hashlib` for SHA-256 /
RIPEMD-160 / PBKDF2 / HMAC-SHA512 but never blake2. Safe to ignore.

Building the bloom over a single-column CSV (header `script`, no delimiter)
always reports `skipped 1 unparseable rows` — that's the header line being read
as data. Harmless; the script count is still correct.
