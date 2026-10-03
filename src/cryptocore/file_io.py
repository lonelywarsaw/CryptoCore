"""Бинарное чтение и запись файлов."""


def read_file(path: str) -> bytes:
    """Прочитать всё содержимое входного файла."""

    with open(path, "rb") as source:
        return source.read()


def write_file(path: str, data: bytes) -> None:
    """Записать все байты в выходной файл."""

    with open(path, "wb") as destination:
        destination.write(data)