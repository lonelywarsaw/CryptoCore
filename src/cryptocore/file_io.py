"""Работа с файлами"""


def read_file(path: str) -> bytes:
    with open(path, "rb") as source:
        return source.read()


def write_file(path: str, data: bytes) -> None:
    with open(path, "wb") as destination:
        destination.write(data)