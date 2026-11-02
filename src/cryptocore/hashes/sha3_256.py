"""SHA3-256 на основе Keccak-f[1600]."""


MASK = (1 << 64) - 1

ROUND_CONSTANTS = (
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
)

ROTATIONS = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)


def rotate_left(value: int, count: int) -> int:
    return (
        (value << count) | (value >> (64 - count))
    ) & MASK


def keccak_f(state):
    for constant in ROUND_CONSTANTS:
        columns = [
            state[x]
            ^ state[x + 5]
            ^ state[x + 10]
            ^ state[x + 15]
            ^ state[x + 20]
            for x in range(5)
        ]

        differences = [
            columns[(x - 1) % 5]
            ^ rotate_left(columns[(x + 1) % 5], 1)
            for x in range(5)
        ]

        for y in range(5):
            for x in range(5):
                state[x + 5 * y] ^= differences[x]

        moved = [0] * 25

        for y in range(5):
            for x in range(5):
                new_x = y
                new_y = (2 * x + 3 * y) % 5

                moved[new_x + 5 * new_y] = rotate_left(
                    state[x + 5 * y],
                    ROTATIONS[x][y],
                )

        for y in range(5):
            for x in range(5):
                state[x + 5 * y] = (
                    moved[x + 5 * y]
                    ^ (
                        (~moved[(x + 1) % 5 + 5 * y])
                        & moved[(x + 2) % 5 + 5 * y]
                    )
                ) & MASK

        state[0] ^= constant


class SHA3_256:
    block_size = 136
    digest_size = 32

    def __init__(self, data: bytes = b""):
        self._state = [0] * 25
        self._buffer = b""

        if data:
            self.update(data)

    def copy(self):
        result = SHA3_256()
        result._state = self._state.copy()
        result._buffer = self._buffer
        return result

    def _process_block(self, block: bytes) -> None:
        for index in range(self.block_size // 8):
            position = index * 8

            self._state[index] ^= int.from_bytes(
                block[position:position + 8],
                byteorder="little",
            )

        keccak_f(self._state)

    def update(self, data: bytes):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("Ожидались байтовые данные.")

        data = bytes(data)
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

        final_block = bytearray(self.block_size)
        final_block[:len(result._buffer)] = result._buffer

        final_block[len(result._buffer)] ^= 0x06
        final_block[-1] ^= 0x80

        result._process_block(bytes(final_block))

        output = b"".join(
            word.to_bytes(8, byteorder="little")
            for word in result._state
        )

        return output[:self.digest_size]

    def hexdigest(self) -> str:
        return self.digest().hex()