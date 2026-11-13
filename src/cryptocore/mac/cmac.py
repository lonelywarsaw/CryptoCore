"""AES-128-CMAC."""

from hmac import compare_digest

from Crypto.Cipher import AES


BLOCK_SIZE = 16


def xor_blocks(first: bytes, second: bytes) -> bytes:
    return bytes(
        left ^ right
        for left, right in zip(first, second)
    )


def double_block(block: bytes) -> bytes:
    value = int.from_bytes(block, "big")
    high_bit = value >> 127

    value = (value << 1) & ((1 << 128) - 1)

    if high_bit:
        value ^= 0x87

    return value.to_bytes(BLOCK_SIZE, "big")


class CMAC:
    block_size = BLOCK_SIZE
    digest_size = BLOCK_SIZE

    def __init__(self, key: bytes):
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("Ключ должен быть байтовой строкой.")

        self._key = bytes(key)

        if len(self._key) != BLOCK_SIZE:
            raise ValueError(
                "Ключ AES-CMAC должен содержать ровно 16 байт."
            )

        self._cipher = AES.new(self._key, AES.MODE_ECB)

        first = self._cipher.encrypt(b"\x00" * BLOCK_SIZE)
        self._subkey1 = double_block(first)
        self._subkey2 = double_block(self._subkey1)

        self._state = b"\x00" * BLOCK_SIZE
        self._buffer = b""

    def _process_block(self, block: bytes) -> None:
        self._state = self._cipher.encrypt(
            xor_blocks(self._state, block)
        )

    def update(self, data: bytes):
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("Ожидались байтовые данные.")

        data = self._buffer + bytes(data)
        position = 0

        # Последний блок сохраняется до вычисления digest.
        while position + BLOCK_SIZE < len(data):
            self._process_block(
                data[position:position + BLOCK_SIZE]
            )
            position += BLOCK_SIZE

        self._buffer = data[position:]
        return self

    def copy(self):
        result = CMAC(self._key)
        result._state = self._state
        result._buffer = self._buffer
        return result

    def digest(self) -> bytes:
        if len(self._buffer) == BLOCK_SIZE:
            last_block = xor_blocks(
                self._buffer,
                self._subkey1,
            )
        else:
            padded = (
                self._buffer
                + b"\x80"
                + b"\x00" * (BLOCK_SIZE - len(self._buffer) - 1)
            )
            last_block = xor_blocks(padded, self._subkey2)

        return self._cipher.encrypt(
            xor_blocks(self._state, last_block)
        )

    def hexdigest(self) -> str:
        return self.digest().hex()

    def verify(self, expected: bytes) -> bool:
        return compare_digest(self.digest(), expected)

    def compute(self, message: bytes) -> str:
        result = self.copy()
        result.update(message)
        return result.hexdigest()