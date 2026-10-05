"""Режим ECB."""

from Crypto.Cipher import AES


BLOCK_SIZE = 16


def validate_key(key: bytes) -> None:
    if len(key) != BLOCK_SIZE:
        raise ValueError(
            "Ключ AES-128 должен содержать ровно 16 байт."
        )


def add_padding(data: bytes) -> bytes:
    padding_size = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_size]) * padding_size


def remove_padding(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError(
            "Данные должны иметь длину, кратную 16 байтам."
        )

    padding_size = data[-1]

    if not 1 <= padding_size <= BLOCK_SIZE:
        raise ValueError(
            "Некорректное дополнение PKCS#7."
        )

    expected_padding = bytes([padding_size]) * padding_size

    if data[-padding_size:] != expected_padding:
        raise ValueError(
            "Некорректное дополнение PKCS#7."
        )

    return data[:-padding_size]


def encrypt(data: bytes, key: bytes) -> bytes:
    validate_key(key)

    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = add_padding(data)
    result = bytearray()

    for offset in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[offset:offset + BLOCK_SIZE]
        result.extend(cipher.encrypt(block))

    return bytes(result)


def decrypt(data: bytes, key: bytes) -> bytes:
    validate_key(key)

    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError(
            "Шифртекст ECB должен иметь длину, кратную 16 байтам."
        )

    cipher = AES.new(key, AES.MODE_ECB)
    result = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset:offset + BLOCK_SIZE]
        result.extend(cipher.decrypt(block))

    return remove_padding(bytes(result))