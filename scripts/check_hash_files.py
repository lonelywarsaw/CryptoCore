"""Проверка хешей файлов и измерение времени."""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptocore.hashes import hash_file


def create_file(path: Path, size: int) -> None:
    chunk = bytes(range(256)) * 4096
    remaining = size

    with path.open("wb") as destination:
        while remaining:
            part = chunk[:min(len(chunk), remaining)]
            destination.write(part)
            remaining -= len(part)


def reference_hash(path: Path, algorithm: str, tool: str) -> str:
    if tool == "openssl":
        command = [
            "openssl", "dgst", f"-{algorithm}", str(path),
        ]
    elif tool == "sha256sum":
        if algorithm != "sha256":
            raise ValueError("sha256sum поддерживает только sha256.")

        command = ["sha256sum", str(path)]
    elif tool == "sha3sum":
        if algorithm != "sha3-256":
            raise ValueError("Для sha3sum укажите sha3-256.")

        command = ["sha3sum", "-a", "256", str(path)]
    else:
        raise ValueError("Неизвестная системная команда.")

    if shutil.which(command[0]) is None:
        raise ValueError(f"Команда {command[0]} не найдена.")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise ValueError(
            f"Ошибка {command[0]}: {result.stderr.strip()}"
        )

    matches = re.findall(
        r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])",
        result.stdout,
    )

    if len(matches) != 1:
        raise ValueError(
            f"Не удалось разобрать вывод: {result.stdout}"
        )

    return matches[0].lower()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--algorithm",
        choices=["sha256", "sha3-256", "all"],
        default="all",
    )
    parser.add_argument(
        "--reference",
        choices=["openssl", "sha256sum", "sha3sum"],
        default="openssl",
    )
    parser.add_argument(
        "--sizes-mib",
        type=int,
        nargs="+",
        default=[1, 10],
    )

    args = parser.parse_args()

    if any(size <= 0 for size in args.sizes_mib):
        parser.error("Размеры должны быть положительными.")

    algorithms = (
        ["sha256", "sha3-256"]
        if args.algorithm == "all"
        else [args.algorithm]
    )

    if args.reference == "sha256sum" and algorithms != ["sha256"]:
        parser.error("Для sha256sum укажите --algorithm sha256.")

    if args.reference == "sha3sum" and algorithms != ["sha3-256"]:
        parser.error("Для sha3sum укажите --algorithm sha3-256.")

    print(
        "algorithm,bytes,implementation_seconds,"
        "reference,reference_seconds,match",
        flush=True,
    )

    try:
        with tempfile.TemporaryDirectory(
            prefix="cryptocore-hash-"
        ) as directory:
            path = Path(directory) / "input.bin"

            for size_mib in args.sizes_mib:
                size = size_mib * 1024 * 1024

                print(
                    f"Preparing {size} bytes",
                    file=sys.stderr,
                    flush=True,
                )
                create_file(path, size)

                for algorithm in algorithms:
                    print(
                        f"Hashing {algorithm}: {size_mib} MiB",
                        file=sys.stderr,
                        flush=True,
                    )

                    started = time.perf_counter()
                    actual = hash_file(path, algorithm)
                    implementation_time = time.perf_counter() - started

                    started = time.perf_counter()
                    expected = reference_hash(
                        path,
                        algorithm,
                        args.reference,
                    )
                    reference_time = time.perf_counter() - started

                    matches = actual == expected

                    print(
                        f"{algorithm},{size},"
                        f"{implementation_time:.6f},"
                        f"{args.reference},"
                        f"{reference_time:.6f},"
                        f"{str(matches).lower()}",
                        flush=True,
                    )

                    if not matches:
                        raise ValueError(
                            f"Хеши {algorithm} не совпали."
                        )

    except (OSError, ValueError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())