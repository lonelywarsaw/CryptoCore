"""Генерация случайных байтов"""

import os


class RandomSourceError(RuntimeError):
    """Ошибка источника случайности"""


def generate_random_bytes(num_bytes: int) -> bytes:
    if isinstance(num_bytes, bool) or not isinstance(num_bytes, int):
        raise TypeError("Количество байтов должно быть целым числом.")

    if num_bytes < 0:
        raise ValueError("Количество байтов не может быть отрицательным.")

    try:
        data = os.urandom(num_bytes)
    except (OSError, NotImplementedError) as error:
        raise RandomSourceError(
            "Не удалось получить случайные байты от операционной системы."
        ) from error

    if len(data) != num_bytes:
        raise RandomSourceError(
            "Источник случайности вернул неверное количество байтов."
        )

    return data