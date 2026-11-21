"""Encrypt-then-MAC на AES-CTR и HMAC-SHA256."""

from cryptocore.aead.gcm import Counter
from cryptocore.aead.gcm import MAX_TEXT_BYTES
from cryptocore.mac.hmac import HMAC


DOMAIN = b"CryptoCore-ETM-v1\x00"


def derive_keys(master_key: bytes):
    if len(master_key) != 32:
        raise ValueError(
            "ETM требует master key длиной 32 байта."
        )

    label = b"CryptoCore-ETM-v1"
    output = b""

    # HMAC-based KDF в режиме счётчика.
    # Context пустой, длина результата 384 бита.
    for counter in (1, 2):
        message = (
            counter.to_bytes(4, "big")
            + label
            + b"\x00"
            + (384).to_bytes(4, "big")
        )

        result = HMAC(master_key)
        result.update(message)
        output += result.digest()

    material = output[:48]
    return material[:16], material[16:]


class ETMContext:
    tag_size = 32

    def __init__(self, master_key: bytes, nonce: bytes, aad_stream):
        if len(nonce) != 12:
            raise ValueError("ETM требует nonce из 12 байт.")

        encryption_key, mac_key = derive_keys(master_key)

        self.counter = Counter(
            encryption_key,
            nonce + b"\x00" * 4,
        )

        self._mac = HMAC(mac_key)
        self._mac.update(DOMAIN + nonce)
        self._aad_stream = aad_stream
        self._text_length = 0
        self._finished = False

    def update(self, ciphertext: bytes) -> None:
        if self._finished:
            raise ValueError("Контекст ETM уже завершён.")

        self._text_length += len(ciphertext)

        if self._text_length > MAX_TEXT_BYTES:
            raise ValueError("Превышен лимит длины ETM.")

        self._mac.update(ciphertext)

    def tag(self) -> bytes:
        if self._finished:
            raise ValueError("Контекст ETM уже завершён.")

        self._finished = True
        aad_length = 0

        while True:
            chunk = self._aad_stream.read(8192)

            if not chunk:
                break

            aad_length += len(chunk)

            if aad_length >= (1 << 61):
                raise ValueError("AAD слишком длинный.")

            self._mac.update(chunk)

        self._mac.update(
            (self._text_length * 8).to_bytes(8, "big")
            + (aad_length * 8).to_bytes(8, "big")
        )

        return self._mac.digest()