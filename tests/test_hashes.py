"""Проверки хеширования."""

import hashlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptocore.hashes import CHUNK_SIZE
from cryptocore.hashes import hash_file
from cryptocore.hashes import hash_stream
from cryptocore.hashes.sha256 import SHA256
from cryptocore.hashes.sha3_256 import SHA3_256


IMPLEMENTATIONS = (
    ("sha256", SHA256, hashlib.sha256),
    ("sha3-256", SHA3_256, hashlib.sha3_256),
)


class HashTests(unittest.TestCase):
    def test_known_answers(self):
        vectors = (
            (
                SHA256,
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427"
                "ae41e4649b934ca495991b7852b855",
            ),
            (
                SHA256,
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223"
                "b00361a396177a9cb410ff61f20015ad",
            ),
            (
                SHA256,
                b"abcdbcdecdefdefgefghfghighijhijk"
                b"ijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039"
                "a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                SHA3_256,
                b"",
                "a7ffc6f8bf1ed76651c14756a061d662"
                "f580ff4de43b49fa82d80a4b80f8434a",
            ),
            (
                SHA3_256,
                b"abc",
                "3a985da74fe225b2045c172d6bd390bd"
                "855f086e3e9d525b46bfe24511431532",
            ),
        )

        for constructor, message, expected in vectors:
            with self.subTest(
                algorithm=constructor.__name__,
                size=len(message),
            ):
                self.assertEqual(
                    constructor(message).hexdigest(),
                    expected,
                )

    def test_boundary_lengths(self):
        lengths = (
            0, 1, 55, 56, 63, 64, 65,
            127, 128, 135, 136, 137,
            255, 256, 8191, 8192, 8193,
        )

        for name, constructor, reference in IMPLEMENTATIONS:
            for length in lengths:
                with self.subTest(algorithm=name, size=length):
                    message = bytes(
                        index % 256
                        for index in range(length)
                    )

                    self.assertEqual(
                        constructor(message).hexdigest(),
                        reference(message).hexdigest(),
                    )

    def test_incremental_updates(self):
        message = bytes(range(256)) * 4

        for name, constructor, reference in IMPLEMENTATIONS:
            for step in (1, 7, 64, 136, 257):
                with self.subTest(algorithm=name, step=step):
                    hasher = constructor()

                    for position in range(0, len(message), step):
                        hasher.update(
                            message[position:position + step]
                        )

                    self.assertEqual(
                        hasher.hexdigest(),
                        reference(message).hexdigest(),
                    )

    def test_digest_does_not_change_state(self):
        for name, constructor, reference in IMPLEMENTATIONS:
            with self.subTest(algorithm=name):
                hasher = constructor(b"abc")
                first = hasher.hexdigest()

                self.assertEqual(hasher.hexdigest(), first)

                hasher.update(b"def")

                self.assertEqual(
                    hasher.hexdigest(),
                    reference(b"abcdef").hexdigest(),
                )

    def test_avalanche_one_bit(self):
        original = b"Hello, world!"
        modified = bytearray(original)
        modified[0] ^= 1

        for name, constructor, _ in IMPLEMENTATIONS:
            with self.subTest(algorithm=name):
                first = constructor(original).digest()
                second = constructor(bytes(modified)).digest()

                changed = sum(
                    bin(left ^ right).count("1")
                    for left, right in zip(first, second)
                )

                self.assertNotEqual(first, second)
                self.assertGreaterEqual(changed, 90)
                self.assertLessEqual(changed, 166)

    def test_bounded_reads(self):
        class CheckedStream(io.BytesIO):
            def read(self, size=-1):
                if not 0 < size <= CHUNK_SIZE:
                    raise AssertionError(
                        "Нарушено ограничение размера чтения."
                    )

                return super().read(size)

        message = bytes(range(256)) * 40

        for name, _, reference in IMPLEMENTATIONS:
            with self.subTest(algorithm=name):
                result = hash_stream(
                    CheckedStream(message),
                    name,
                )

                self.assertEqual(
                    result,
                    reference(message).hexdigest(),
                )


class DigestCLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

        self.directory = Path(self.temporary.name)
        self.source = self.directory / "input file.bin"
        self.source.write_bytes(bytes(range(37)))

    def run_cli(self, *arguments, input_data=None):
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "cryptocore.cli",
                "dgst",
                *map(str, arguments),
            ],
            input=input_data,
            capture_output=True,
            check=False,
        )

    def test_stdout_format(self):
        for name, _, reference in IMPLEMENTATIONS:
            with self.subTest(algorithm=name):
                result = self.run_cli(
                    "--algorithm", name,
                    "--input", self.source,
                )

                expected = (
                    f"{reference(self.source.read_bytes()).hexdigest()}"
                    f"  {self.source}\n"
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    result.stdout.decode().splitlines(),
                    expected.splitlines(),
                )

    def test_output_file(self):
        for name, _, reference in IMPLEMENTATIONS:
            with self.subTest(algorithm=name):
                output = self.directory / f"{name}.txt"

                result = self.run_cli(
                    "--algorithm", name,
                    "--input", self.source,
                    "--output", output,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"")

                expected = (
                    f"{reference(self.source.read_bytes()).hexdigest()}"
                    f"  {self.source}\n"
                )

                self.assertEqual(
                    output.read_text(encoding="utf-8"),
                    expected,
                )

    def test_stdin(self):
        for name, _, reference in IMPLEMENTATIONS:
            with self.subTest(algorithm=name):
                result = self.run_cli(
                    "--algorithm", name,
                    "--input", "-",
                    input_data=b"abc",
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    result.stdout.decode().strip(),
                    f"{reference(b'abc').hexdigest()}  -",
                )

    def test_empty_file(self):
        empty = self.directory / "empty.bin"
        empty.write_bytes(b"")

        for name, _, reference in IMPLEMENTATIONS:
            with self.subTest(algorithm=name):
                self.assertEqual(
                    hash_file(empty, name),
                    reference(b"").hexdigest(),
                )

    def test_encryption_options_are_rejected(self):
        options = (
            ("--key", "00" * 16),
            ("--mode", "cbc"),
            ("--iv", "00" * 16),
            ("--encrypt",),
            ("--decrypt",),
        )

        for option in options:
            with self.subTest(option=option):
                result = self.run_cli(
                    "--algorithm", "sha256",
                    "--input", self.source,
                    *option,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertNotEqual(result.stderr, b"")

    def test_missing_input(self):
        result = self.run_cli(
            "--algorithm", "sha256",
            "--input", self.directory / "missing.bin",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.stderr, b"")

    def test_invalid_algorithm(self):
        result = self.run_cli(
            "--algorithm", "md5",
            "--input", self.source,
        )

        self.assertNotEqual(result.returncode, 0)

    def test_missing_required_arguments(self):
        for arguments in (
            (),
            ("--algorithm", "sha256"),
            ("--input", str(self.source)),
        ):
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments)
                self.assertNotEqual(result.returncode, 0)

    def test_same_input_output_is_rejected(self):
        original = self.source.read_bytes()

        result = self.run_cli(
            "--algorithm", "sha256",
            "--input", self.source,
            "--output", self.source,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.source.read_bytes(), original)

    def test_invalid_output_directory(self):
        result = self.run_cli(
            "--algorithm", "sha256",
            "--input", self.source,
            "--output", self.directory / "missing" / "hash.txt",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.stderr, b"")


if __name__ == "__main__":
    unittest.main()