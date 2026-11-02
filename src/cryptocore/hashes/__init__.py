"""Хеширование файлов."""

from cryptocore.hashes.sha256 import SHA256
from cryptocore.hashes.sha3_256 import SHA3_256


CHUNK_SIZE = 8192

ALGORITHMS = {
    "sha256": SHA256,
    "sha3-256": SHA3_256,
}


def create_hasher(algorithm: str):
    try:
        constructor = ALGORITHMS[algorithm]
    except KeyError as error:
        raise ValueError(
            f"Неподдерживаемый алгоритм хеширования: {algorithm}"
        ) from error

    return constructor()


def hash_stream(stream, algorithm: str) -> str:
    hasher = create_hasher(algorithm)

    while True:
        chunk = stream.read(CHUNK_SIZE)

        if not chunk:
            break

        hasher.update(chunk)

    return hasher.hexdigest()


def hash_file(path, algorithm: str) -> str:
    with open(path, "rb") as source:
        return hash_stream(source, algorithm)