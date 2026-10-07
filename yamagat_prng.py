MASK32 = 0xFFFFFFFF
MASK8 = 0xFF

yamagata_pad = 0x0A8CE26F
yamagata_n = 71
yamagata_d = 233
yamagata_dat = 0


# yamagata PRNG is a non-cryptographic PRNG I made
def my_yamagata():
    global yamagata_pad, yamagata_n, yamagata_d, yamagata_dat

    yamagata_pad = (yamagata_pad + yamagata_dat + yamagata_d * yamagata_n) & MASK32

    yamagata_pad = ((yamagata_pad << 3) + (yamagata_pad >> 29)) & MASK32

    yamagata_n = (yamagata_pad | 2) & MASK32

    yamagata_d ^= ((yamagata_pad << 31) + (yamagata_pad >> 1)) & MASK32
    yamagata_d &= MASK32

    yamagata_dat ^= (yamagata_pad & MASK8) ^ (yamagata_d >> 8) ^ 1
    yamagata_dat &= MASK8

    return (
        yamagata_pad
        ^ ((yamagata_d << 5) & MASK32)
        ^ (yamagata_pad >> 18)
        ^ (yamagata_dat << 1)
    ) & MASK32
