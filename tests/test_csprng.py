"""Проверки генерации случайных данных и ключей"""

import contextlib
import io
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptocore.cli import encrypt_data
from cryptocore.cli import main
from cryptocore.csprng import generate_random_bytes
from cryptocore.csprng import RandomSourceError
from cryptocore.modes.ecb import decrypt as ecb_decrypt
from cryptocore.modes.gcm import encrypt as gcm_encrypt


KEY_HEX = "d4c3b2a1908f7e6d5c4b3a291807f6e5"
KEY = bytes.fromhex(KEY_HEX)


class RandomBytesTests(unittest.TestCase):
    def test_output_lengths(self):
        for size in (0, 1, 16, 32, 4096):
            with self.subTest(size=size):
                data = generate_random_bytes(size)
                self.assertIsInstance(data, bytes)
                self.assertEqual(len(data), size)

    def test_negative_size(self):
        with self.assertRaises(ValueError):
            generate_random_bytes(-1)

    def test_invalid_size_type(self):
        for value in ("16", 1.5, True, None):
            with self.subTest(value=value):
                with self.assertRaises(TypeError):
                    generate_random_bytes(value)

    def test_os_random_source(self):
        with patch(
            "cryptocore.csprng.os.urandom",
            return_value=b"x" * 16,
        ) as source:
            self.assertEqual(generate_random_bytes(16), b"x" * 16)
            source.assert_called_once_with(16)

    def test_source_failure(self):
        with patch(
            "cryptocore.csprng.os.urandom",
            side_effect=OSError("source unavailable"),
        ):
            with self.assertRaises(RandomSourceError):
                generate_random_bytes(16)

    def test_wrong_source_length(self):
        with patch(
            "cryptocore.csprng.os.urandom",
            return_value=b"x",
        ):
            with self.assertRaises(RandomSourceError):
                generate_random_bytes(16)

    def test_1000_unique_keys(self):
        keys = [generate_random_bytes(16) for _ in range(1000)]

        self.assertTrue(all(len(key) == 16 for key in keys))
        self.assertEqual(len(set(keys)), 1000)

    def test_hamming_weight(self):
        data = b"".join(
            generate_random_bytes(16)
            for _ in range(1000)
        )

        ones = sum(bin(byte).count("1") for byte in data)
        ratio = ones / (len(data) * 8)

        self.assertGreater(ratio, 0.48)
        self.assertLess(ratio, 0.52)

    def test_modes_use_csprng_for_iv(self):
        iv = b"\x42" * 16

        for mode in ("cbc", "cfb", "ofb", "ctr"):
            with self.subTest(mode=mode):
                with patch(
                    "cryptocore.cli.generate_random_bytes",
                    return_value=iv,
                ) as source:
                    encrypted = encrypt_data(mode, b"message", KEY)

                source.assert_called_once_with(16)
                self.assertEqual(encrypted[:16], iv)

    def test_gcm_uses_csprng_for_nonce(self):
        nonce = b"\x42" * 12

        with patch(
            "cryptocore.modes.gcm.generate_random_bytes",
            return_value=nonce,
        ) as source:
            encrypted = gcm_encrypt(b"message", KEY)

        source.assert_called_once_with(12)
        self.assertEqual(encrypted[4:16], nonce)


class GeneratedKeyCLITests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)

        self.directory = Path(self.temporary_directory.name)
        self.input_file = self.directory / "original.bin"
        self.input_file.write_bytes(bytes(range(37)) + b"\x00\xff")

    def run_cli(self, *arguments):
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "cryptocore.cli",
                *map(str, arguments),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )

    def test_generated_key_round_trip_all_modes(self):
        for mode in ("ecb", "cbc", "cfb", "ofb", "ctr", "gcm"):
            with self.subTest(mode=mode):
                encrypted = self.directory / f"{mode}.enc"
                restored = self.directory / f"{mode}.dec"

                result = self.run_cli(
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--encrypt",
                    "--input", self.input_file,
                    "--output", encrypted,
                )

                self.assertEqual(result.returncode, 0, result.stderr)

                match = re.fullmatch(
                    r"Generated random key: ([0-9a-f]{32})\r?\n",
                    result.stdout,
                )
                self.assertIsNotNone(match, result.stdout)

                generated_key = match.group(1)
                self.assertEqual(len(bytes.fromhex(generated_key)), 16)

                result = self.run_cli(
                    "--algorithm", "aes",
                    "--mode", mode,
                    "--decrypt",
                    "--key", generated_key,
                    "--input", encrypted,
                    "--output", restored,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    restored.read_bytes(),
                    self.input_file.read_bytes(),
                )

    def test_decryption_requires_key(self):
        output_file = self.directory / "result.bin"

        result = self.run_cli(
            "--algorithm", "aes",
            "--mode", "ctr",
            "--decrypt",
            "--input", self.input_file,
            "--output", output_file,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--key", result.stderr)
        self.assertFalse(output_file.exists())

    def test_supplied_key_is_not_replaced(self):
        output_file = self.directory / "encrypted.bin"

        result = self.run_cli(
            "--algorithm", "aes",
            "--mode", "ecb",
            "--encrypt",
            "--key", KEY_HEX,
            "--input", self.input_file,
            "--output", output_file,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            ecb_decrypt(output_file.read_bytes(), KEY),
            self.input_file.read_bytes(),
        )

    def test_weak_keys_produce_warning(self):
        weak_keys = [
            "00" * 16,
            bytes(range(16)).hex(),
            bytes(range(15, -1, -1)).hex(),
        ]

        for key in weak_keys:
            with self.subTest(key=key):
                result = self.run_cli(
                    "--algorithm", "aes",
                    "--mode", "ecb",
                    "--encrypt",
                    "--key", key,
                    "--input", self.input_file,
                    "--output", self.directory / "weak.enc",
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotEqual(result.stderr, "")
                self.assertIn("--key", result.stderr)
                self.assertEqual(result.stdout, "")

    def test_generated_key_is_not_added_to_ciphertext(self):
        output_file = self.directory / "generated-ecb.bin"

        result = self.run_cli(
            "--algorithm", "aes",
            "--mode", "ecb",
            "--encrypt",
            "--input", self.input_file,
            "--output", output_file,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

        match = re.fullmatch(
            r"Generated random key: ([0-9a-f]{32})\r?\n",
            result.stdout,
        )
        self.assertIsNotNone(match, result.stdout)

        key = bytes.fromhex(match.group(1))
        original = self.input_file.read_bytes()
        ciphertext = output_file.read_bytes()

        expected_size = (len(original) // 16 + 1) * 16

        self.assertEqual(len(ciphertext), expected_size)
        self.assertEqual(ecb_decrypt(ciphertext, key), original)

    def test_cli_handles_random_source_failure(self):
        output_file = self.directory / "failed.bin"

        arguments = [
            "cryptocore",
            "--algorithm", "aes",
            "--mode", "ctr",
            "--encrypt",
            "--input", str(self.input_file),
            "--output", str(output_file),
        ]

        stderr = io.StringIO()

        with patch.object(sys, "argv", arguments):
            with patch(
                "cryptocore.cli.generate_random_bytes",
                side_effect=RandomSourceError("source unavailable"),
            ):
                with contextlib.redirect_stderr(stderr):
                    result = main()

        self.assertEqual(result, 1)
        self.assertIn("source unavailable", stderr.getvalue())
        self.assertFalse(output_file.exists())


if __name__ == "__main__":
    unittest.main()