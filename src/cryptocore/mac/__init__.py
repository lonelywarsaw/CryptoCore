"""Вычисление MAC для потоков и файлов."""

from cryptocore.mac.cmac import CMAC
from cryptocore.mac.hmac import HMAC


CHUNK_SIZE = 8192


def create_mac(kind: str, key: bytes):
    if kind == "hmac":
        return HMAC(key)

    if kind == "cmac":
        return CMAC(key)

    raise ValueError(f"Неизвестный вид MAC: {kind}")


def mac_stream(stream, kind: str, key: bytes) -> bytes:
    result = create_mac(kind, key)

    while True:
        chunk = stream.read(CHUNK_SIZE)

        if not chunk:
            break

        result.update(chunk)

    return result.digest()


def mac_file(path, kind: str, key: bytes) -> bytes:
    with open(path, "rb") as source:
        return mac_stream(source, kind, key)