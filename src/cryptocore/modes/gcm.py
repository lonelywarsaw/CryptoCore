"""Режим GCM."""

import os

from Crypto.Cipher import AES

from cryptocore.modes.ecb import validate_key


NONCE_SIZE = 12
TAG_SIZE = 16
MAGIC = b"CCG1"


def encrypt(data: bytes, key: bytes) -> bytes:
    validate_key(key)

    nonce = os.urandom(NONCE_SIZE)

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce,
        mac_len=TAG_SIZE,
    )

    ciphertext, tag = cipher.encrypt_and_digest(data)

    return MAGIC + nonce + ciphertext + tag


def decrypt(data: bytes, key: bytes) -> bytes:
    validate_key(key)

    minimum_size = len(MAGIC) + NONCE_SIZE + TAG_SIZE

    if len(data) < minimum_size:
        raise ValueError("Файл GCM слишком короткий.")

    if data[:len(MAGIC)] != MAGIC:
        raise ValueError("Некорректная сигнатура файла GCM.")

    nonce_start = len(MAGIC)
    nonce_end = nonce_start + NONCE_SIZE

    nonce = data[nonce_start:nonce_end]
    ciphertext = data[nonce_end:-TAG_SIZE]
    tag = data[-TAG_SIZE:]

    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce,
        mac_len=TAG_SIZE,
    )

    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as error:
        raise ValueError(
            "Файл изменён или указан неправильный ключ."
        ) from error