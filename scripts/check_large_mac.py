"""Проверка MAC при ограничении памяти процесса."""

import argparse
import hashlib
import hmac
import sys
import tempfile
import time
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import CMAC as ReferenceCMAC

from cryptocore.mac import mac_file


MIB = 1024 * 1024
KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


def create_input(path: Path, size: int) -> None:
    chunk = bytes(range(256)) * 4096
    remaining = size

    with path.open("wb") as destination:
        while remaining:
            part = chunk[:min(len(chunk), remaining)]
            destination.write(part)
            remaining -= len(part)


def reference_mac(path: Path, kind: str) -> bytes:
    if kind == "hmac":
        result = hmac.new(KEY, digestmod=hashlib.sha256)
    else:
        result = ReferenceCMAC.new(KEY, ciphermod=AES)

    with path.open("rb") as source:
        while True:
            chunk = source.read(8192)

            if not chunk:
                break

            result.update(chunk)

    return result.digest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--size-mib", type=int, default=257)
    parser.add_argument("--memory-limit-mib", type=int, default=128)
    parser.add_argument(
        "--kind",
        choices=["hmac", "cmac", "all"],
        default="all",
    )

    args = parser.parse_args()

    if args.memory_limit_mib <= 0:
        parser.error("Memory limit must be positive.")

    if args.size_mib <= args.memory_limit_mib:
        parser.error("File size must exceed the memory limit.")

    if not sys.platform.startswith("linux"):
        parser.error("Run this test in Linux or Ubuntu WSL.")

    import resource

    limit = args.memory_limit_mib * MIB

    try:
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))

        kinds = (
            ["hmac", "cmac"]
            if args.kind == "all"
            else [args.kind]
        )

        print(
            f"Memory limit: {args.memory_limit_mib} MiB",
            flush=True,
        )
        print(f"Input size: {args.size_mib} MiB", flush=True)

        with tempfile.TemporaryDirectory(
            prefix="cryptocore-mac-"
        ) as directory:
            path = Path(directory) / "input.bin"
            create_input(path, args.size_mib * MIB)

            for kind in kinds:
                print(f"Running {kind}", flush=True)
                started = time.perf_counter()

                actual = mac_file(path, kind, KEY)
                expected = reference_mac(path, kind)

                if actual != expected:
                    raise ValueError(f"{kind}: MAC mismatch.")

                elapsed = time.perf_counter() - started

                print(
                    f"PASS {kind}: {actual.hex()}",
                    flush=True,
                )
                print(
                    f"Seconds: {elapsed:.3f}",
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