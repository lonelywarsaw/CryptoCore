"""CLI для GCM и Encrypt-then-MAC."""

import argparse
import re
import sys

from cryptocore import csprng
from cryptocore.aead.files import decrypt_file
from cryptocore.aead.files import encrypt_file


def parse_hex(value):
    if re.fullmatch(r"(?:[0-9a-fA-F]{2})*", value) is None:
        raise argparse.ArgumentTypeError(
            "Ожидалась hex-строка с чётным числом символов."
        )

    return bytes.fromhex(value)


def main(arguments=None):
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="AES-128-GCM и Encrypt-then-MAC.",
        allow_abbrev=False,
    )

    parser.add_argument(
        "--algorithm",
        required=True,
        choices=["aes"],
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["gcm", "etm"],
    )

    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--encrypt", action="store_true")
    operation.add_argument("--decrypt", action="store_true")

    parser.add_argument("--key", type=parse_hex)
    parser.add_argument("--input", required=True)
    parser.add_argument("--output")

    nonce_group = parser.add_mutually_exclusive_group()
    nonce_group.add_argument("--nonce", type=parse_hex)
    nonce_group.add_argument("--iv", type=parse_hex)

    aad_group = parser.add_mutually_exclusive_group()
    aad_group.add_argument("--aad", type=parse_hex, default=b"")
    aad_group.add_argument("--aad-file")

    args = parser.parse_args(arguments)

    key_size = 16 if args.mode == "gcm" else 32
    nonce = args.nonce if args.nonce is not None else args.iv

    if args.encrypt and nonce is not None:
        parser.error(
            "При шифровании nonce генерируется автоматически."
        )

    if nonce is not None and len(nonce) != 12:
        parser.error("Nonce должен содержать 12 байт.")

    if args.decrypt and args.key is None:
        parser.error("При расшифровании требуется --key.")

    if args.key is not None and len(args.key) != key_size:
        parser.error(
            f"Для {args.mode} требуется ключ из {key_size} байт."
        )

    if args.output is None:
        # Сохраняется прежнее правило выбора выходного пути.
        from cryptocore.file_io import output_path_for

        output_path = output_path_for(args.input, args.encrypt)
    else:
        output_path = args.output

    try:
        key = args.key

        if key is None:
            key = csprng.generate_random_bytes(key_size)
            print(
                f"Generated random key: {key.hex()}",
                flush=True,
            )
        else:
            from cryptocore.cli import is_weak_key

            if is_weak_key(key):
                print(
                    "Предупреждение: --key содержит простой шаблон. "
                    "Используйте случайный ключ.",
                    file=sys.stderr,
                )

        if args.encrypt:
            encrypt_file(
                args.input,
                output_path,
                key,
                mode=args.mode,
                aad=args.aad,
                aad_path=args.aad_file,
            )
        else:
            decrypt_file(
                args.input,
                output_path,
                key,
                mode=args.mode,
                aad=args.aad,
                aad_path=args.aad_file,
                nonce=nonce,
            )

    except (OSError, ValueError, csprng.RandomSourceError) as error:
        print(f"[ERROR] {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())