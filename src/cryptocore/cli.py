"""Командная строка CryptoCore."""

import argparse
import os
import re
import sys
from typing import Optional
from typing import Tuple

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
KEY_PATTERN = re.compile(r"[0-9a-fA-F]{32}\Z")


def parse_hex_value(value: str, name: str) -> bytes:
    if KEY_PATTERN.fullmatch(value) is None:
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

    operation.add_argument(
        "--encrypt",
        action="store_true",
    )

    operation.add_argument(
        "--decrypt",
        action="store_true",
    )

    parser.add_argument(
        "--key",
        required=True,
        type=parse_key,
    )

    parser.add_argument(
        "--iv",
        type=parse_iv,
    )

    parser.add_argument(
        "--input",
        required=True,
        metavar="INPUT_FILE",
    )

    parser.add_argument(
        "--output",
        metavar="OUTPUT_FILE",
    )

    return parser


def output_path_for(input_path: str, encrypting: bool) -> str:
    if encrypting:
        return input_path + ".enc"

    return input_path + ".dec"


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


def encrypt_data(
    mode: str,
    data: bytes,
    key: bytes,
) -> bytes:
    if mode == "ecb":
        return ecb_encrypt(data, key)

    if mode == "gcm":
        return gcm_encrypt(data, key)

    iv = os.urandom(BLOCK_SIZE)

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
        if supplied_iv is not None:
            raise ValueError(
                "Параметр --iv нельзя использовать с ECB."
            )

        return ecb_decrypt(data, key)

    if mode == "gcm":
        if supplied_iv is not None:
            raise ValueError(
                "Параметр --iv нельзя использовать с GCM."
            )

        return gcm_decrypt(data, key)

    iv, ciphertext = get_iv_and_ciphertext(
        data,
        supplied_iv,
    )

    if mode == "cbc":
        return cbc_decrypt(ciphertext, key, iv)

    if mode == "cfb":
        return cfb_decrypt(ciphertext, key, iv)

    if mode == "ofb":
        return ofb_crypt(ciphertext, key, iv)

    if mode == "ctr":
        return ctr_crypt(ciphertext, key, iv)

    raise ValueError(f"Неподдерживаемый режим: {mode}")


def main() -> int:
    parser = create_parser()
    args = parser.parse_args()

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
        output_path = output_path_for(
            args.input,
            args.encrypt,
        )

    try:
        source_data = read_file(args.input)

        if args.encrypt:
            result = encrypt_data(
                args.mode,
                source_data,
                args.key,
            )
        else:
            result = decrypt_data(
                args.mode,
                source_data,
                args.key,
                args.iv,
            )

        write_file(output_path, result)

    except OSError as error:
        print(
            f"Ошибка файловой операции: {error}",
            file=sys.stderr,
        )
        return 1

    except ValueError as error:
        print(
            f"Ошибка: {error}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())