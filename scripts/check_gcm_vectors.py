"""Проверка байтовых векторов NIST GCM CAVP."""

import argparse
from pathlib import Path
import sys

from cryptocore.aead import AuthenticationError
from cryptocore.aead.gcm import GCM


def records(path):
    fields = {}

    with path.open("r", encoding="utf-8-sig") as source:
        for line in source:
            line = line.strip()

            if not line or line.startswith(("#", "[")):
                continue

            if line.startswith("Count"):
                if fields:
                    yield fields

                fields = {}
                continue

            if line == "FAIL":
                fields["FAIL"] = True
            elif "=" in line:
                name, value = line.split("=", 1)
                fields[name.strip()] = value.strip()

    if fields:
        yield fields


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()

    total = 0
    negatives = 0

    try:
        paths = sorted(args.directory.rglob("*.rsp"))

        if not paths:
            raise ValueError("Не найдены файлы .rsp.")

        for path in paths:
            count = 0
            failed_vectors = 0

            for record in records(path):
                required = ("Key", "IV", "AAD", "CT", "Tag")

                if not all(name in record for name in required):
                    continue

                key = bytes.fromhex(record["Key"])
                nonce = bytes.fromhex(record["IV"])
                tag = bytes.fromhex(record["Tag"])

                if len(key) != 16 or len(tag) != 16:
                    continue

                aad = bytes.fromhex(record["AAD"])
                ciphertext = bytes.fromhex(record["CT"])
                result = GCM(key, nonce)

                if record.get("FAIL"):
                    try:
                        result.decrypt_detached(ciphertext, tag, aad)
                    except AuthenticationError:
                        failed_vectors += 1
                    else:
                        raise ValueError(
                            f"{path.name}: принят неверный тег."
                        )
                else:
                    if "PT" not in record:
                        raise ValueError(
                            f"{path.name}: отсутствует PT."
                        )

                    plaintext = bytes.fromhex(record["PT"])
                    actual, actual_tag = result.encrypt_detached(
                        plaintext, aad
                    )

                    if actual != ciphertext or actual_tag != tag:
                        raise ValueError(
                            f"{path.name}: несовпадение вектора."
                        )

                    if result.decrypt_detached(
                        ciphertext, tag, aad
                    ) != plaintext:
                        raise ValueError(
                            f"{path.name}: ошибка расшифрования."
                        )

                count += 1

            if count:
                print(
                    f"PASS {path.name}: {count}, "
                    f"negative: {failed_vectors}"
                )

            total += count
            negatives += failed_vectors

        if total == 0:
            raise ValueError(
                "Нет векторов AES-128 с тегом 128 бит."
            )

    except (OSError, ValueError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1

    print(f"PASS total: {total}")
    print(f"PASS negative vectors: {negatives}")
    return 0


if __name__ == "__main__":
    sys.exit(main())