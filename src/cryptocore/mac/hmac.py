"""HMAC-SHA256."""

from hmac import compare_digest

from cryptocore.hashes.sha256 import SHA256


class HMAC:
    block_size = 64
    digest_size = 32

    def __init__(self, key: bytes, hash_function: str = "sha256"):
        if hash_function != "sha256":
            raise ValueError("HMAC поддерживает только sha256.")

        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("Ключ должен быть байтовой строкой.")

        key = bytes(key)

        if len(key) > self.block_size:
            key = SHA256(key).digest()

        key = key.ljust(self.block_size, b"\x00")

        inner_pad = bytes(byte ^ 0x36 for byte in key)
        outer_pad = bytes(byte ^ 0x5C for byte in key)

        self._inner = SHA256(inner_pad)
        self._outer = SHA256(outer_pad)

    def update(self, data: bytes):
        self._inner.update(data)
        return self

    def copy(self):
        result = object.__new__(HMAC)
        result._inner = self._inner.copy()
        result._outer = self._outer.copy()
        return result

    def digest(self) -> bytes:
        outer = self._outer.copy()
        outer.update(self._inner.digest())
        return outer.digest()

    def hexdigest(self) -> str:
        return self.digest().hex()

    def verify(self, expected: bytes) -> bool:
        return compare_digest(self.digest(), expected)

    def compute(self, message: bytes) -> str:
        result = self.copy()
        result.update(message)
        return result.hexdigest()