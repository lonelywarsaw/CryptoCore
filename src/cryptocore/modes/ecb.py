"""ECB с ручной обработкой блоков и дополнением PKCS#7.

Примитив AES предоставляется библиотекой pycryptodome.
"""

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def _validate_key(key: bytes) -> None:
    if len(key) != BLOCK_SIZE:
        raise ValueError("Ключ AES-128 должен содержать ровно 16 байт.")


def encrypt(data: bytes, key: bytes) -> bytes:
    """Дополнить данные по PKCS#7 и зашифровать каждый блок AES."""

    _validate_key(key)

    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    padded_data = data + bytes([padding_length]) * padding_length

    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()

    for offset in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[offset:offset + BLOCK_SIZE]
        result.extend(cipher.encrypt(block))

    return bytes(result)


def decrypt(data: bytes, key: bytes) -> bytes:
    """Расшифровать блоки AES, проверить и удалить дополнение PKCS#7."""

    _validate_key(key)

    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError(
            "Шифртекст должен содержать хотя бы один блок "
            "и иметь длину, кратную 16 байтам."
        )

    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset:offset + BLOCK_SIZE]
        result.extend(cipher.decrypt(block))

    padding_length = result[-1]

    if not 1 <= padding_length <= BLOCK_SIZE:
        raise ValueError("Некорректное дополнение PKCS#7.")

    if result[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Некорректное дополнение PKCS#7.")

    return bytes(result[:-padding_length])