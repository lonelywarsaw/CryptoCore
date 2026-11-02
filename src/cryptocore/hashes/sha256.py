"""SHA-256."""

import struct


MASK = 0xFFFFFFFF

INITIAL_STATE = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)

ROUND_CONSTANTS = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
)


def rotate_right(value: int, count: int) -> int:
    return (
        (value >> count) | (value << (32 - count))
    ) & MASK


class SHA256:
    block_size = 64
    digest_size = 32

    def __init__(self, data: bytes = b""):
        self._state = list(INITIAL_STATE)
        self._buffer = b""
        self._length = 0

        if data:
            self.update(data)

    def copy(self):
        result = SHA256()
        result._state = self._state.copy()
        result._buffer = self._buffer
        result._length = self._length
        return result

    def _process_block(self, block: bytes) -> None:
        words = list(struct.unpack(">16I", block))

        for index in range(16, 64):
            first = words[index - 15]
            second = words[index - 2]

            sigma0 = (
                rotate_right(first, 7)
                ^ rotate_right(first, 18)
                ^ (first >> 3)
            )
            sigma1 = (
                rotate_right(second, 17)
                ^ rotate_right(second, 19)
                ^ (second >> 10)
            )

            words.append(
                (
                    words[index - 16]
                    + sigma0
                    + words[index - 7]
                    + sigma1
                ) & MASK
            )

        a, b, c, d, e, f, g, h = self._state

        for index in range(64):
            sum1 = (
                rotate_right(e, 6)
                ^ rotate_right(e, 11)
                ^ rotate_right(e, 25)
            )
            choice = (e & f) ^ ((~e) & g)

            temporary1 = (
                h
                + sum1
                + choice
                + ROUND_CONSTANTS[index]
                + words[index]
            ) & MASK

            sum0 = (
                rotate_right(a, 2)
                ^ rotate_right(a, 13)
                ^ rotate_right(a, 22)
            )
            majority = (a & b) ^ (a & c) ^ (b & c)
            temporary2 = (sum0 + majority) & MASK

            a, b, c, d, e, f, g, h = (
                (temporary1 + temporary2) & MASK,
                a,
                b,
                c,
                (d + temporary1) & MASK,
                e,
                f,
                g,
            )

        self._state = [
            (previous + current) & MASK
            for previous, current in zip(
                self._state,
                (a, b, c, d, e, f, g, h),
            )
        ]

    def update(self, data: bytes):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("Ожидались байтовые данные.")

        data = bytes(data)

        if self._length + len(data) >= (1 << 61):
            raise ValueError(
                "Длина сообщения SHA-256 должна быть меньше 2^64 бит."
            )

        self._length += len(data)
        position = 0

        if self._buffer:
            needed = self.block_size - len(self._buffer)
            self._buffer += data[:needed]
            position = min(needed, len(data))

            if len(self._buffer) == self.block_size:
                self._process_block(self._buffer)
                self._buffer = b""

        while position + self.block_size <= len(data):
            self._process_block(
                data[position:position + self.block_size]
            )
            position += self.block_size

        self._buffer += data[position:]
        return self

    def digest(self) -> bytes:
        result = self.copy()

        padding = b"\x80"
        padding += b"\x00" * ((55 - self._length) % 64)
        padding += struct.pack(">Q", self._length * 8)

        final_blocks = result._buffer + padding

        for position in range(0, len(final_blocks), self.block_size):
            result._process_block(
                final_blocks[position:position + self.block_size]
            )

        return struct.pack(">8I", *result._state)

    def hexdigest(self) -> str:
        return self.digest().hex()