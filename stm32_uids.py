#!/usr/bin/env python3
"""
Generate a realistic STM32 96-bit Unique Device ID (UID)
"""

import random
import struct


def generate_stm32_uid(year: int = None) -> dict:
    """
    Returns a dict with:
      - uid_words  : list of three 32-bit integers  [UID[31:0], UID[63:32], UID[95:64]]
      - hex_string : continuous 24-character hex representation
      - decoded    : human-readable breakdown
    """
    if year is None:
        year = random.randint(2020, 2026)  # post-2020

    # --- 1. Lot number (7 ASCII characters total) ---
    # Real ST lot numbers are short alphanumeric strings.
    # We make them look modern by embedding the year and a random lot code.
    year_suffix = str(year)[-2:]  # "22", "23", ...
    lot_code = "".join(random.choices("0123456789ABCDEFGHJKLMNPQRSTUVWXYZ", k=5))
    lot = (year_suffix + lot_code)[:7].ljust(7)  # exactly 7 chars

    # Pack the 7-byte lot into the two 32-bit fields the way the silicon does:
    # UID[95:64] = LOT_NUM[55:24]   → first 4 bytes of lot
    # UID[63:40] = LOT_NUM[23:0]    → next 3 bytes of lot
    # UID[39:32] = WAF_NUM
    lot_bytes = lot.encode("ascii")
    uid95_64 = int.from_bytes(lot_bytes[0:4], "little")
    lot_low = int.from_bytes(lot_bytes[4:7] + b"\x00", "little")  # 3 bytes + pad

    # --- 2. Wafer number (8-bit) ---
    waf_num = random.randint(1, 60)  # typical range seen in the wild

    # --- 3. X/Y wafer coordinates in BCD ---
    # Each coordinate is a 16-bit BCD value. Real chips often have the
    # high bit of one coordinate set, and values are usually modest.
    def random_bcd_coord():
        # Generate a plausible 0–99 BCD value, sometimes with high bit set
        val = random.randint(0, 99)
        bcd = ((val // 10) << 4) | (val % 10)
        if random.random() < 0.35:  # ~35 % of real samples
            bcd |= 0x8000
        return bcd

    x = random_bcd_coord()
    y = random_bcd_coord()
    uid31_0 = (y << 16) | x

    # Assemble the middle word:  UID[63:32] = (LOT_NUM[23:0] << 8) | WAF_NUM
    uid63_32 = (lot_low << 8) | waf_num

    uid_words = [uid31_0, uid63_32, uid95_64]

    # Continuous 24-hex-digit string (big-endian style people usually print)
    hex_string = "".join(f"{w:08X}" for w in reversed(uid_words))

    decoded = {
        "lot": lot.strip(),
        "wafer": waf_num,
        "x_bcd": f"0x{x:04X}",
        "y_bcd": f"0x{y:04X}",
        "year_hint": year,
    }

    return {
        "uid_words": uid_words,
        "hex_string": hex_string,
        "decoded": decoded,
    }


# ----------------------------------------------------------------------
# Demo
# ----------------------------------------------------------------------
if __name__ == "__main__":
    for i in range(4):
        uid = generate_stm32_uid()
        print(f"UID words : {[f'0x{w:08X}' for w in uid['uid_words']]}")
        print(f"Hex string: {uid['hex_string']}")
        print(
            f"Decoded   : lot='{uid['decoded']['lot']}', "
            f"wafer={uid['decoded']['wafer']}, "
            f"X={uid['decoded']['x_bcd']}, Y={uid['decoded']['y_bcd']}"
        )
        print("-" * 60)
