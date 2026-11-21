"""AES-128-GCM по NIST SP 800-38D."""

from hmac import compare_digest
import io

from Crypto.Cipher import AES

from cryptocore import csprng
from cryptocore.aead import AuthenticationError


REDUCTION = 0xE1000000000000000000000000000000
MAX_TEXT_BYTES = (1 << 36) - 32
MAX_LENGTH_BYTES = (1 << 61) - 1


def xor_bytes(first: bytes, second: bytes) -> bytes:
    return bytes(
        left ^ right
        for left, right in zip(first, second)
    )


def multiply_gf(first: int, second: int) -> int:
    """Побитовое умножение для проверки табличной реализации."""
    result = 0
    value = second

    for position in range(127, -1, -1):
        if (first >> position) & 1:
            result ^= value

        if value & 1:
            value = (value >> 1) ^ REDUCTION
        else:
            value >>= 1

    return result


def multiplication_table(hash_key: int):
    """Предвычисление произведений для 16 позиций байта."""
    basis = []
    value = hash_key

    for _ in range(128):
        basis.append(value)

        if value & 1:
            value = (value >> 1) ^ REDUCTION
        else:
            value >>= 1

    tables = []

    for position in range(16):
        row = [0] * 256

        for byte in range(1, 256):
            lowest = byte & -byte
            bit = lowest.bit_length() - 1

            row[byte] = (
                row[byte ^ lowest]
                ^ basis[position * 8 + 7 - bit]
            )

        tables.append(tuple(row))

    return tuple(tables)


class GHASH:
    def __init__(self, hash_key: bytes):
        if len(hash_key) != 16:
            raise ValueError("GHASH требует ключ из 16 байт.")

        self._tables = multiplication_table(
            int.from_bytes(hash_key, "big")
        )
        self._value = 0
        self._buffer = b""

    def multiply(self, value: int) -> int:
        result = 0

        for position, byte in enumerate(
            value.to_bytes(16, "big")
        ):
            result ^= self._tables[position][byte]

        return result

    def _block(self, block: bytes) -> None:
        self._value = self.multiply(
            self._value ^ int.from_bytes(block, "big")
        )

    def update(self, data: bytes) -> None:
        data = self._buffer + bytes(data)
        end = len(data) - len(data) % 16

        for position in range(0, end, 16):
            self._block(data[position:position + 16])

        self._buffer = data[end:]

    def pad(self) -> None:
        if self._buffer:
            self._block(self._buffer.ljust(16, b"\x00"))
            self._buffer = b""

    def digest(self) -> bytes:
        if self._buffer:
            raise ValueError("GHASH содержит неполный блок.")

        return self._value.to_bytes(16, "big")


def make_j0(hash_key: bytes, nonce: bytes) -> bytes:
    if not nonce:
        raise ValueError("Nonce не должен быть пустым.")

    if len(nonce) > MAX_LENGTH_BYTES:
        raise ValueError("Nonce слишком длинный.")

    if len(nonce) == 12:
        return nonce + b"\x00\x00\x00\x01"

    result = GHASH(hash_key)
    result.update(nonce)
    result.pad()
    result.update(
        b"\x00" * 8
        + (len(nonce) * 8).to_bytes(8, "big")
    )
    return result.digest()


class Counter:
    """CTR с увеличением младших 32 бит."""

    def __init__(self, key: bytes, initial: bytes):
        if len(initial) != 16:
            raise ValueError("Начальный блок должен содержать 16 байт.")

        self._aes = AES.new(key, AES.MODE_ECB)
        self._prefix = initial[:12]
        self._counter = int.from_bytes(initial[12:], "big")
        self._pending = b""
        self._blocks = 0

    def transform(self, data: bytes) -> bytes:
        output = bytearray()
        position = 0

        while position < len(data):
            if not self._pending:
                if self._blocks >= (1 << 32) - 2:
                    raise ValueError("Превышен лимит блоков CTR.")

                self._counter = (
                    self._counter + 1
                ) & 0xFFFFFFFF

                self._pending = self._aes.encrypt(
                    self._prefix
                    + self._counter.to_bytes(4, "big")
                )
                self._blocks += 1

            size = min(
                len(self._pending),
                len(data) - position,
            )

            output.extend(
                xor_bytes(
                    data[position:position + size],
                    self._pending[:size],
                )
            )

            self._pending = self._pending[size:]
            position += size

        return bytes(output)


class GCMContext:
    """Потоковый контекст одного сообщения."""

    tag_size = 16

    def __init__(self, key: bytes, nonce: bytes, aad_stream):
        if len(key) != 16:
            raise ValueError("AES-128 требует ключ из 16 байт.")

        self._aes = AES.new(key, AES.MODE_ECB)
        hash_key = self._aes.encrypt(b"\x00" * 16)

        self._j0 = make_j0(hash_key, nonce)
        self.counter = Counter(key, self._j0)
        self._ghash = GHASH(hash_key)

        self._aad_length = 0
        self._text_length = 0
        self._finished = False

        while True:
            chunk = aad_stream.read(8192)

            if not chunk:
                break

            self._aad_length += len(chunk)

            if self._aad_length > MAX_LENGTH_BYTES:
                raise ValueError("AAD слишком длинный.")

            self._ghash.update(chunk)

        self._ghash.pad()

    def update(self, ciphertext: bytes) -> None:
        if self._finished:
            raise ValueError("Контекст GCM уже завершён.")

        self._text_length += len(ciphertext)

        if self._text_length > MAX_TEXT_BYTES:
            raise ValueError("Превышен лимит длины GCM.")

        self._ghash.update(ciphertext)

    def tag(self) -> bytes:
        if self._finished:
            raise ValueError("Контекст GCM уже завершён.")

        self._finished = True
        self._ghash.pad()
        self._ghash.update(
            (self._aad_length * 8).to_bytes(8, "big")
            + (self._text_length * 8).to_bytes(8, "big")
        )

        return xor_bytes(
            self._aes.encrypt(self._j0),
            self._ghash.digest(),
        )


class GCM:
    """Интерфейс для небольших сообщений в памяти."""

    def __init__(self, key: bytes, nonce=None):
        self.key = bytes(key)

        if len(self.key) != 16:
            raise ValueError("AES-128 требует ключ из 16 байт.")

        self.nonce = (
            csprng.generate_random_bytes(12)
            if nonce is None
            else bytes(nonce)
        )

        if not self.nonce:
            raise ValueError("Nonce не должен быть пустым.")

    def encrypt_detached(
        self,
        plaintext: bytes,
        aad: bytes = b"",
    ):
        context = GCMContext(
            self.key,
            self.nonce,
            io.BytesIO(aad),
        )

        ciphertext = context.counter.transform(plaintext)
        context.update(ciphertext)

        return ciphertext, context.tag()

    def decrypt_detached(
        self,
        ciphertext: bytes,
        tag: bytes,
        aad: bytes = b"",
    ) -> bytes:
        context = GCMContext(
            self.key,
            self.nonce,
            io.BytesIO(aad),
        )
        context.update(ciphertext)

        if not compare_digest(context.tag(), tag):
            raise AuthenticationError(
                "Authentication failed: неверный ключ, "
                "AAD или изменённые данные."
            )

        return context.counter.transform(ciphertext)

    def encrypt(
        self,
        plaintext: bytes,
        aad: bytes = b"",
    ) -> bytes:
        if len(self.nonce) != 12:
            raise ValueError(
                "Для формата nonce || ciphertext || tag "
                "требуется nonce из 12 байт."
            )

        ciphertext, tag = self.encrypt_detached(plaintext, aad)
        return self.nonce + ciphertext + tag

    def decrypt(
        self,
        data: bytes,
        aad: bytes = b"",
    ) -> bytes:
        if len(data) < 28:
            raise AuthenticationError("Слишком короткий GCM-файл.")

        result = GCM(self.key, data[:12])

        return result.decrypt_detached(
            data[12:-16],
            data[-16:],
            aad,
        )