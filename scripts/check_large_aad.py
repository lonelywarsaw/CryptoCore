"""Проверка большого AAD при ограниченной памяти."""

import argparse
from pathlib import Path
import sys
import tempfile

from Crypto.Cipher import AES

from cryptocore.aead import AuthenticationError
from cryptocore.aead.files import decrypt_file
from cryptocore.aead.files import encrypt_file


MIB = 1024 * 1024
KEY = bytes(range(16))


def create_aad(path, size):
    chunk = bytes(range(256)) * 4096

    with path.open("wb") as destination:
        while size:
            part = chunk[:min(size, len(chunk))]
            destination.write(part)
            size -= len(part)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--memory-mib", type=int, default=128)
    parser.add_argument("--aad-mib", type=int, default=129)
    args = parser.parse_args()

    if not sys.platform.startswith("linux"):
        parser.error("Запустите сценарий в Linux или Ubuntu WSL.")

    if args.memory_mib <= 0 or args.aad_mib <= args.memory_mib:
        parser.error("Размер AAD должен превышать лимит памяти.")

    import resource

    try:
        limit = args.memory_mib * MIB
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)

            aad = directory / "aad.bin"
            source = directory / "input.bin"
            encrypted = directory / "encrypted.bin"
            output = directory / "output.bin"

            source.write_bytes(b"Small plaintext")
            create_aad(aad, args.aad_mib * MIB)

            print(
                f"Memory limit: {args.memory_mib} MiB",
                flush=True,
            )
            print(f"AAD size: {args.aad_mib} MiB", flush=True)
            print("Running GCM encryption", flush=True)

            encrypt_file(
                source, encrypted, KEY,
                aad_path=aad,
            )

            data = encrypted.read_bytes()
            reference = AES.new(
                KEY, AES.MODE_GCM,
                nonce=data[:12], mac_len=16,
            )

            with aad.open("rb") as associated:
                while True:
                    chunk = associated.read(8192)

                    if not chunk:
                        break

                    reference.update(chunk)

            ciphertext, tag = reference.encrypt_and_digest(
                source.read_bytes()
            )

            if data[12:] != ciphertext + tag:
                raise ValueError("Несовпадение с библиотечным GCM.")

            print("Running GCM decryption", flush=True)

            decrypt_file(
                encrypted, output, KEY,
                aad_path=aad,
            )

            if output.read_bytes() != source.read_bytes():
                raise ValueError("Неверное расшифрование.")

            print(
                "PASS large AAD round-trip and reference",
                flush=True,
            )

            with aad.open("r+b") as associated:
                first = associated.read(1)
                associated.seek(0)
                associated.write(bytes([first[0] ^ 1]))

            output.unlink()
            print("Running tamper rejection", flush=True)

            try:
                decrypt_file(
                    encrypted, output, KEY,
                    aad_path=aad,
                )
            except AuthenticationError:
                if output.exists():
                    raise ValueError(
                        "При отказе создан выходной файл."
                    )
            else:
                raise ValueError("Изменённый AAD принят.")

            print(
                "PASS large AAD tamper rejection",
                flush=True,
            )

    except (OSError, ValueError, MemoryError) as error:
        print(
            f"FAIL {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())