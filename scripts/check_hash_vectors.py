"""Проверка байтовых тестовых векторов NIST."""

import argparse
import sys
from pathlib import Path

from cryptocore.hashes import ALGORITHMS
from cryptocore.hashes import create_hasher


def read_vectors(path):
    fields = {}

    with path.open("r", encoding="utf-8-sig") as source:
        for line_number, line in enumerate(source, 1):
            line = line.strip()

            if not line or line.startswith(("#", "[")):
                continue

            if "=" not in line:
                continue

            name, value = (
                part.strip()
                for part in line.split("=", 1)
            )

            if name == "Len":
                fields = {"Len": int(value)}
            elif name in ("Msg", "MD"):
                fields[name] = value

            if name == "MD" and "Len" in fields:
                if "Msg" not in fields:
                    raise ValueError(
                        f"{path}:{line_number}: отсутствует Msg."
                    )

                bit_length = fields["Len"]

                if bit_length % 8:
                    raise ValueError(
                        f"{path}:{line_number}: нужен byte-oriented набор."
                    )

                if bit_length == 0:
                    message = b""
                else:
                    message = bytes.fromhex(fields["Msg"])

                if len(message) * 8 != bit_length:
                    raise ValueError(
                        f"{path}:{line_number}: неверная длина Msg."
                    )

                yield message, fields["MD"].lower()
                fields = {}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--algorithm",
        required=True,
        choices=sorted(ALGORITHMS),
    )
    parser.add_argument(
        "--directory",
        type=Path,
        required=True,
    )

    args = parser.parse_args()

    if args.algorithm == "sha256":
        names = (
            "SHA256ShortMsg.rsp",
            "SHA256LongMsg.rsp",
        )
    else:
        names = (
            "SHA3_256ShortMsg.rsp",
            "SHA3_256LongMsg.rsp",
        )

    total = 0

    try:
        for name in names:
            paths = list(args.directory.rglob(name))

            if len(paths) != 1:
                raise ValueError(
                    f"Ожидался ровно один файл {name}, найдено {len(paths)}."
                )

            count = 0

            for message, expected in read_vectors(paths[0]):
                hasher = create_hasher(args.algorithm)
                hasher.update(message)
                actual = hasher.hexdigest()

                if actual != expected:
                    raise ValueError(
                        f"{name}, вектор {count + 1}: "
                        f"ожидалось {expected}, получено {actual}."
                    )

                count += 1

            if count == 0:
                raise ValueError(f"В {name} не найдены тестовые векторы.")

            total += count
            print(f"PASS {name}: {count}")

    except (OSError, ValueError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1

    print(f"PASS total: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())