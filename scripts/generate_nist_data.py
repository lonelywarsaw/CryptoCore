"""Подготовка данных для NIST STS"""

import argparse
import hashlib
import sys
from pathlib import Path

from cryptocore.csprng import generate_random_bytes
from cryptocore.csprng import RandomSourceError


DEFAULT_SIZE = 12_500_000
CHUNK_SIZE = 65_536


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Подготовка бинарного файла для NIST STS.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("nist_test_data.bin"),
    )
    parser.add_argument(
        "--size",
        type=int,
        default=DEFAULT_SIZE,
        help="Размер файла в байтах.",
    )

    args = parser.parse_args()

    if args.size <= 0:
        parser.error("--size должен быть положительным.")

    if args.output.exists():
        parser.error(
            "Выходной файл уже существует. "
            "Укажите другой путь или удалите старый файл."
        )

    digest = hashlib.sha256()
    created = False

    try:
        with args.output.open("xb") as destination:
            created = True
            remaining = args.size

            while remaining:
                chunk = generate_random_bytes(
                    min(CHUNK_SIZE, remaining)
                )
                destination.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)

    except (OSError, RandomSourceError) as error:
        if created:
            try:
                args.output.unlink()
            except OSError:
                pass

        print(f"Ошибка подготовки данных: {error}", file=sys.stderr)
        return 1

    print(f"File: {args.output.resolve()}")
    print(f"Bytes: {args.size}")
    print(f"SHA256: {digest.hexdigest()}")

    return 0


if __name__ == "__main__":
    sys.exit(main())