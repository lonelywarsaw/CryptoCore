"""Режимы CFB, OFB и CTR."""

from Crypto.Cipher import AES

from cryptocore.modes.ecb import validate_key


BLOCK_SIZE = 16


def validate_iv(iv: bytes) -> None:
    if len(iv) != BLOCK_SIZE:
        raise ValueError(
            "IV должен содержать ровно 16 байт."
        )


def xor_bytes(first: bytes, second: bytes) -> bytes:
    return bytes(
        left ^ right
        for left, right in zip(first, second)
    )


def cfb_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_key(key)
    validate_iv(iv)

    cipher = AES.new(key, AES.MODE_ECB)
    feedback = iv
    result = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        current_block = data[
            offset:offset + BLOCK_SIZE
        ]

        keystream = cipher.encrypt(feedback)
        ciphertext_block = xor_bytes(
            current_block,
            keystream,
        )

        result.extend(ciphertext_block)

        if len(ciphertext_block) == BLOCK_SIZE:
            feedback = ciphertext_block

    return bytes(result)


def cfb_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_key(key)
    validate_iv(iv)

    cipher = AES.new(key, AES.MODE_ECB)
    feedback = iv
    result = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        current_block = data[
            offset:offset + BLOCK_SIZE
        ]

        keystream = cipher.encrypt(feedback)
        plaintext_block = xor_bytes(
            current_block,
            keystream,
        )

        result.extend(plaintext_block)

        if len(current_block) == BLOCK_SIZE:
            feedback = current_block

    return bytes(result)


def ofb_crypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_key(key)
    validate_iv(iv)

    cipher = AES.new(key, AES.MODE_ECB)
    feedback = iv
    result = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        feedback = cipher.encrypt(feedback)

        current_block = data[
            offset:offset + BLOCK_SIZE
        ]

        result.extend(
            xor_bytes(current_block, feedback)
        )

    return bytes(result)


def ctr_crypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    validate_key(key)
    validate_iv(iv)

    cipher = AES.new(key, AES.MODE_ECB)

    counter = int.from_bytes(
        iv,
        byteorder="big",
    )

    result = bytearray()

    for offset in range(0, len(data), BLOCK_SIZE):
        counter_block = counter.to_bytes(
            BLOCK_SIZE,
            byteorder="big",
        )

        keystream = cipher.encrypt(counter_block)

        current_block = data[
            offset:offset + BLOCK_SIZE
        ]

        result.extend(
            xor_bytes(current_block, keystream)
        )

        counter = (counter + 1) % (1 << 128)

    return bytes(result)