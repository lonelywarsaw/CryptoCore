"""Командная строка CryptoCore"""

import argparse
import os
import re
import sys
from typing import Optional
from typing import Tuple

from cryptocore.csprng import generate_random_bytes
from cryptocore.csprng import RandomSourceError
from cryptocore.file_io import read_file
from cryptocore.file_io import write_file
from cryptocore.modes.cbc import decrypt as cbc_decrypt
from cryptocore.modes.cbc import encrypt as cbc_encrypt
from cryptocore.modes.ecb import decrypt as ecb_decrypt
from cryptocore.modes.ecb import encrypt as ecb_encrypt
from cryptocore.modes.gcm import decrypt as gcm_decrypt
from cryptocore.modes.gcm import encrypt as gcm_encrypt
from cryptocore.modes.streaming import cfb_decrypt
from cryptocore.modes.streaming import cfb_encrypt
from cryptocore.modes.streaming import ctr_crypt
from cryptocore.modes.streaming import ofb_crypt


BLOCK_SIZE = 16
MODES = ["ecb", "cbc", "cfb", "ofb", "ctr", "gcm"]
HEX_PATTERN = re.compile(r"[0-9a-fA-F]{32}\Z")


def parse_hex_value(value: str, name: str) -> bytes:
    if HEX_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError(
            f"{name} должен содержать 32 шестнадцатеричных символа."
        )

    return bytes.fromhex(value)


def parse_key(value: str) -> bytes:
    return parse_hex_value(value, "--key")


def parse_iv(value: str) -> bytes:
    return parse_hex_value(value, "--iv")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="Шифрование файлов с помощью AES-128.",
    )

    parser.add_argument(
        "--algorithm",
        required=True,
        choices=["aes"],
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=MODES,
    )

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true")
    operation.add_argument("--decrypt", action="store_true")

    parser.add_argument(
        "--key",
        type=parse_key,
        help="Ключ из 32 hex-символов. Обязателен при расшифровании.",
    )
    parser.add_argument("--iv", type=parse_iv)
    parser.add_argument("--input", required=True, metavar="INPUT_FILE")
    parser.add_argument("--output", metavar="OUTPUT_FILE")

    return parser


def is_weak_key(key: bytes) -> bool:
    if len(set(key)) == 1:
        return True

    ascending = all(
        key[index] == (key[index - 1] + 1) % 256
        for index in range(1, len(key))
    )
    descending = all(
        key[index] == (key[index - 1] - 1) % 256
        for index in range(1, len(key))
    )

    return ascending or descending


def output_path_for(input_path: str, encrypting: bool) -> str:
    if encrypting:
        return input_path + ".enc"

    return input_path + ".dec"


def check_paths(input_path: str, output_path: str) -> None:
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


def get_iv_and_ciphertext(
    data: bytes,
    supplied_iv: Optional[bytes],
) -> Tuple[bytes, bytes]:
    if supplied_iv is not None:
        return supplied_iv, data

    if len(data) < BLOCK_SIZE:
        raise ValueError(
            "Файл слишком короткий и не содержит полный IV."
        )

    return data[:BLOCK_SIZE], data[BLOCK_SIZE:]


def encrypt_data(mode: str, data: bytes, key: bytes) -> bytes:
    if mode == "ecb":
        return ecb_encrypt(data, key)

    if mode == "gcm":
        return gcm_encrypt(data, key)

    iv = generate_random_bytes(BLOCK_SIZE)

    if mode == "cbc":
        ciphertext = cbc_encrypt(data, key, iv)
    elif mode == "cfb":
        ciphertext = cfb_encrypt(data, key, iv)
    elif mode == "ofb":
        ciphertext = ofb_crypt(data, key, iv)
    elif mode == "ctr":
        ciphertext = ctr_crypt(data, key, iv)
    else:
        raise ValueError(f"Неподдерживаемый режим: {mode}")

    return iv + ciphertext


def decrypt_data(
    mode: str,
    data: bytes,
    key: bytes,
    supplied_iv: Optional[bytes],
) -> bytes:
    if mode == "ecb":
        return ecb_decrypt(data, key)

    if mode == "gcm":
        return gcm_decrypt(data, key)

    iv, ciphertext = get_iv_and_ciphertext(data, supplied_iv)

    if mode == "cbc":
        return cbc_decrypt(ciphertext, key, iv)

    if mode == "cfb":
        return cfb_decrypt(ciphertext, key, iv)

    if mode == "ofb":
        return ofb_crypt(ciphertext, key, iv)

    if mode == "ctr":
        return ctr_crypt(ciphertext, key, iv)

    raise ValueError(f"Неподдерживаемый режим: {mode}")


def encryption_main() -> int:
    parser = create_parser()
    args = parser.parse_args()

    if args.decrypt and args.key is None:
        parser.error(
            "Для расшифрования необходимо указать --key."
        )

    if args.encrypt and args.iv is not None:
        parser.error(
            "Параметр --iv нельзя указывать при шифровании."
        )

    if args.mode in ("ecb", "gcm") and args.iv is not None:
        parser.error(
            f"Параметр --iv нельзя использовать с режимом {args.mode}."
        )

    output_path = args.output

    if output_path is None:
        output_path = output_path_for(args.input, args.encrypt)

    try:
        check_paths(args.input, output_path)
        source_data = read_file(args.input)

        key = args.key

        if key is None:
            key = generate_random_bytes(BLOCK_SIZE)
            print(f"Generated random key: {key.hex()}", flush=True)
        elif is_weak_key(key):
            print(
                "Предупреждение: --key содержит простой шаблон. "
                "Лучше использовать случайный ключ.",
                file=sys.stderr,
            )

        if args.encrypt:
            result = encrypt_data(args.mode, source_data, key)
        else:
            result = decrypt_data(
                args.mode,
                source_data,
                key,
                args.iv,
            )

        write_file(output_path, result)

    except RandomSourceError as error:
        print(f"Ошибка генерации случайных данных: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"Ошибка файловой операции: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"Ошибка: {error}", file=sys.stderr)
        return 1

    return 0


def main() -> int:
    arguments = sys.argv[1:]

    if arguments and arguments[0] == "dgst":
        from cryptocore.digest_cli import main as digest_main

        return digest_main(arguments[1:])

    mode = None

    for position, argument in enumerate(arguments):
        if argument == "--mode" and position + 1 < len(arguments):
            mode = arguments[position + 1]
        elif argument.startswith("--mode="):
            mode = argument.split("=", 1)[1]

    if mode in ("gcm", "etm"):
        from cryptocore.aead_cli import main as aead_main

        return aead_main(arguments)

    return encryption_main()


if __name__ == "__main__":
    sys.exit(main())