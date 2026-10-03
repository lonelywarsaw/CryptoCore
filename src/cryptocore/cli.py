"""Интерфейс командной строки CryptoCore."""

import argparse
import os
import re
import sys

from cryptocore.file_io import read_file, write_file
from cryptocore.modes.ecb import decrypt, encrypt

HEX_KEY_PATTERN = re.compile(r"[0-9a-fA-F]{32}\Z")


def parse_key(value: str) -> bytes:
    """Проверить шестнадцатеричный ключ AES-128."""

    if HEX_KEY_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            "--key должен содержать ровно 32 шестнадцатеричных символа."
        )

    return bytes.fromhex(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Шифрование файлов с помощью AES-128-ECB и PKCS#7.",
    )

    parser.add_argument("--algorithm", required=True, choices=["aes"])
    parser.add_argument("--mode", required=True, choices=["ecb"])

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true")
    operation.add_argument("--decrypt", action="store_true")

    parser.add_argument("--key", required=True, type=parse_key)
    parser.add_argument("--input", required=True, metavar="INPUT_FILE")
    parser.add_argument("--output", metavar="OUTPUT_FILE")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    output_path = args.output
    if output_path is None:
        suffix = ".enc" if args.encrypt else ".dec"
        output_path = args.input + suffix

    try:
        # Запрещаем перезапись входа даже при другом написании того же пути.
        if os.path.samefile(args.input, output_path):
            parser.error("Входной и выходной файлы должны различаться.")
    except FileNotFoundError:
        # Проверка существования входа выполняется при чтении ниже.
        pass
    except OSError as exc:
        print(f"Ошибка проверки путей: {exc}", file=sys.stderr)
        return 1

    try:
        source_data = read_file(args.input)

        if args.encrypt:
            result = encrypt(source_data, args.key)
        else:
            result = decrypt(source_data, args.key)

        write_file(output_path, result)
    except (OSError, ValueError) as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())