"""Хеширование и проверка MAC."""

import argparse
from hmac import compare_digest
import os
import re
import sys

from cryptocore.hashes import ALGORITHMS
from cryptocore.hashes import hash_file
from cryptocore.hashes import hash_stream
from cryptocore.mac import mac_file
from cryptocore.mac import mac_stream


HEX_KEY = re.compile(r"(?:[0-9a-fA-F]{2})*\Z")


def parse_mac_key(value: str) -> bytes:
    if HEX_KEY.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "--key должен содержать чётное число hex-символов."
        )

    return bytes.fromhex(value)


def check_output_path(input_path: str, output_path: str) -> None:
    if input_path == "-":
        return

    source = os.path.normcase(os.path.realpath(input_path))
    destination = os.path.normcase(os.path.realpath(output_path))

    if source == destination:
        raise ValueError(
            "Входной и выходной файлы должны различаться."
        )

    if os.path.exists(input_path) and os.path.exists(output_path):
        if os.path.samefile(input_path, output_path):
            raise ValueError(
                "Входной и выходной файлы должны различаться."
            )


def read_expected_mac(path: str, digest_size: int) -> bytes:
    # Достаточно первой непустой строки. Большой файл целиком не читается.
    with open(path, "r", encoding="utf-8-sig") as source:
        while True:
            line = source.readline(65537)

            if not line:
                raise ValueError("Файл с ожидаемым MAC пуст.")

            if len(line) > 65536:
                raise ValueError("Строка с ожидаемым MAC слишком длинная.")

            if line.strip():
                break

        for remaining_line in source:
            if remaining_line.strip():
                raise ValueError(
                    "Файл проверки должен содержать один MAC."
                )

    value = line.split()[0]

    if re.fullmatch(
        rf"[0-9a-fA-F]{{{digest_size * 2}}}",
        value,
    ) is None:
        raise ValueError(
            "Некорректное ожидаемое значение MAC."
        )

    return bytes.fromhex(value)


def write_result(line: str, output_path) -> None:
    if output_path is None:
        sys.stdout.write(line)
        return

    with open(
        output_path,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as destination:
        destination.write(line)


def main(arguments=None) -> int:
    parser = argparse.ArgumentParser(
        prog="cryptocore dgst",
        description="Хеширование файлов и вычисление MAC.",
        allow_abbrev=False,
    )

    parser.add_argument(
        "--algorithm",
        required=True,
        choices=sorted(ALGORITHMS) + ["aes"],
    )

    operation = parser.add_mutually_exclusive_group()
    operation.add_argument("--hmac", action="store_true")
    operation.add_argument("--cmac", action="store_true")

    parser.add_argument("--key", type=parse_mac_key)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output")
    parser.add_argument("--verify", metavar="MAC_FILE")

    args = parser.parse_args(arguments)

    is_mac = args.hmac or args.cmac

    if is_mac and args.key is None:
        parser.error("--key обязателен для HMAC и CMAC.")

    if not is_mac and args.key is not None:
        parser.error("--key применяется только с --hmac или --cmac.")

    if args.verify is not None and not is_mac:
        parser.error("--verify применяется только с --hmac или --cmac.")

    if args.verify is not None and args.output is not None:
        parser.error("--verify и --output нельзя использовать вместе.")

    if args.hmac and args.algorithm != "sha256":
        parser.error("Для --hmac используется --algorithm sha256.")

    if args.cmac:
        if args.algorithm != "aes":
            parser.error("Для --cmac используется --algorithm aes.")

        if len(args.key) != 16:
            parser.error("Для AES-CMAC требуется ключ из 16 байт.")

    if not is_mac and args.algorithm not in ALGORITHMS:
        parser.error("Для обычного хеширования выберите sha256 или sha3-256.")

    try:
        if args.output is not None:
            check_output_path(args.input, args.output)

        expected = None

        if args.verify is not None:
            expected = read_expected_mac(
                args.verify,
                32 if args.hmac else 16,
            )

        if is_mac:
            kind = "hmac" if args.hmac else "cmac"

            if args.input == "-":
                result = mac_stream(
                    sys.stdin.buffer,
                    kind,
                    args.key,
                )
            else:
                result = mac_file(
                    args.input,
                    kind,
                    args.key,
                )

            if expected is not None:
                label = kind.upper()

                if compare_digest(result, expected):
                    print(f"[OK] {label} verification successful")
                    return 0

                print(
                    f"[ERROR] {label} verification failed",
                    file=sys.stderr,
                )
                return 1

            line = f"{result.hex()} {args.input}\n"

        else:
            if args.input == "-":
                digest = hash_stream(
                    sys.stdin.buffer,
                    args.algorithm,
                )
            else:
                digest = hash_file(
                    args.input,
                    args.algorithm,
                )

            line = f"{digest}  {args.input}\n"

        write_result(line, args.output)

    except (OSError, ValueError, UnicodeError) as error:
        print(f"Ошибка dgst: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())