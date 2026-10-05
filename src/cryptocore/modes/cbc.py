"""Режим CBC."""

from Crypto.Cipher import AES

from cryptocore.modes.ecb import add_padding
from cryptocore.modes.ecb import remove_padding
from cryptocore.modes.ecb import validate_key

BLOCK_SIZE = 16


def validate_iv(iv: bytes) -> None:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV должен содержать ровно 16 байт.")


def xor_blocks(first: bytes, second: bytes) -> bytes:
    return bytes(
        left ^ right
        for left, right in zip(first, second)
    )


def encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_key(key)
    validate_iv(iv)

    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = add_padding(data)

    previous_block = iv
    result = bytearray()

    for offset in range(0, len(padded_data), BLOCK_SIZE):
        plaintext_block = padded_data[
            offset:offset + BLOCK_SIZE
        ]

        mixed_block = xor_blocks(
            plaintext_block,
            previous_block,
        )

        ciphertext_block = cipher.encrypt(mixed_block)
        result.extend(ciphertext_block)
        previous_block = ciphertext_block

    return bytes(result)


def decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_key(key)
    validate_iv(iv)

    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError(
            "Шифртекст CBC должен иметь длину, кратную 16 байтам."
        )

    cipher = AES.new(key, AES.MODE_ECB)

    previous_block = iv
    result = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        ciphertext_block = data[
            offset:offset + BLOCK_SIZE
        ]

        decrypted_block = cipher.decrypt(ciphertext_block)

        plaintext_block = xor_blocks(
            decrypted_block,
            previous_block,
        )

        result.extend(plaintext_block)
        previous_block = ciphertext_block

    return remove_padding(bytes(result))