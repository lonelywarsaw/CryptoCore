"""Проверки режимов CryptoCore"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

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

KEY_HEX = "000102030405060708090a0b0c0d0e0f"
KEY = bytes.fromhex(KEY_HEX)

IV_HEX = "AABBCCDDEEFF00112233445566778899"
IV = bytes.fromhex(IV_HEX)


class ModeTests(unittest.TestCase):
    def test_ecb_round_trip(self):
        samples = [
            b"",
            b"one byte",
            b"short message",
            bytes(range(256)),
        ]

        for original in samples:
            with self.subTest(size=len(original)):
                encrypted = ecb_encrypt(original, KEY)
                restored = ecb_decrypt(encrypted, KEY)
                self.assertEqual(restored, original)

    def test_cbc_round_trip(self):
        samples = [
            b"",
            b"one byte",
            b"not aligned to block",
            bytes(range(256)),
        ]

        for original in samples:
            with self.subTest(size=len(original)):
                encrypted = cbc_encrypt(original, KEY, IV)
                restored = cbc_decrypt(encrypted, KEY, IV)
                self.assertEqual(restored, original)

    def test_cfb_round_trip(self):
        samples = [
            b"",
            b"a",
            b"1234567890123456",
            bytes(range(37)),
        ]

        for original in samples:
            with self.subTest(size=len(original)):
                encrypted = cfb_encrypt(original, KEY, IV)
                restored = cfb_decrypt(encrypted, KEY, IV)

                self.assertEqual(len(encrypted), len(original))
                self.assertEqual(restored, original)

    def test_ofb_round_trip(self):
        samples = [
            b"",
            b"a",
            b"1234567890123456",
            bytes(range(37)),
        ]

        for original in samples:
            with self.subTest(size=len(original)):
                encrypted = ofb_crypt(original, KEY, IV)
                restored = ofb_crypt(encrypted, KEY, IV)

                self.assertEqual(len(encrypted), len(original))
                self.assertEqual(restored, original)

    def test_ctr_round_trip(self):
        samples = [
            b"",
            b"a",
            b"1234567890123456",
            bytes(range(37)),
        ]

        for original in samples:
            with self.subTest(size=len(original)):
                encrypted = ctr_crypt(original, KEY, IV)
                restored = ctr_crypt(encrypted, KEY, IV)

                self.assertEqual(len(encrypted), len(original))
                self.assertEqual(restored, original)

    def test_gcm_round_trip(self):
        original = bytes(range(100))

        encrypted = gcm_encrypt(original, KEY)
        restored = gcm_decrypt(encrypted, KEY)

        self.assertEqual(restored, original)

    def test_gcm_rejects_changed_data(self):
        original = b"file contents"
        encrypted = bytearray(gcm_encrypt(original, KEY))

        encrypted[-1] ^= 1

        with self.assertRaises(ValueError):
            gcm_decrypt(bytes(encrypted), KEY)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.directory = Path(self.temp_directory.name)

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
            check=False,
        )

    def test_all_modes_round_trip(self):
        original = self.directory / "original.bin"
        original.write_bytes(bytes(range(40)) + b"\x00\xff")

        for mode in ("ecb", "cbc", "cfb", "ofb", "ctr", "gcm"):
            with self.subTest(mode=mode):
                encrypted = self.directory / f"{mode}.bin"
                decrypted = self.directory / f"{mode}.out"

                encryption = self.run_cli(
                    "--algorithm",
                    "aes",
                    "--mode",
                    mode,
                    "--encrypt",
                    "--key",
                    KEY_HEX,
                    "--input",
                    original,
                    "--output",
                    encrypted,
                )

                self.assertEqual(
                    encryption.returncode,
                    0,
                    encryption.stderr,
                )

                decryption = self.run_cli(
                    "--algorithm",
                    "aes",
                    "--mode",
                    mode,
                    "--decrypt",
                    "--key",
                    KEY_HEX,
                    "--input",
                    encrypted,
                    "--output",
                    decrypted,
                )

                self.assertEqual(
                    decryption.returncode,
                    0,
                    decryption.stderr,
                )
                self.assertEqual(
                    decrypted.read_bytes(),
                    original.read_bytes(),
                )

    def test_explicit_iv(self):
        original = self.directory / "original.txt"
        ciphertext = self.directory / "ciphertext.bin"
        decrypted = self.directory / "decrypted.txt"

        original.write_bytes(b"test message")

        encryption = self.run_cli(
            "--algorithm",
            "aes",
            "--mode",
            "cbc",
            "--encrypt",
            "--key",
            KEY_HEX,
            "--input",
            original,
            "--output",
            ciphertext,
        )

        self.assertEqual(encryption.returncode, 0)

        encrypted_data = ciphertext.read_bytes()
        iv = encrypted_data[:16]
        ciphertext_only = self.directory / "ciphertext-only.bin"
        ciphertext_only.write_bytes(encrypted_data[16:])

        decryption = self.run_cli(
            "--algorithm",
            "aes",
            "--mode",
            "cbc",
            "--decrypt",
            "--key",
            KEY_HEX,
            "--iv",
            iv.hex(),
            "--input",
            ciphertext_only,
            "--output",
            decrypted,
        )

        self.assertEqual(decryption.returncode, 0, decryption.stderr)
        self.assertEqual(
            decrypted.read_bytes(),
            original.read_bytes(),
        )

    def test_iv_is_not_allowed_during_encryption(self):
        original = self.directory / "original.txt"
        original.write_bytes(b"data")

        result = self.run_cli(
            "--algorithm",
            "aes",
            "--mode",
            "cbc",
            "--encrypt",
            "--key",
            KEY_HEX,
            "--iv",
            IV_HEX,
            "--input",
            original,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--iv", result.stderr)

    def test_invalid_key(self):
        result = self.run_cli(
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--encrypt",
            "--key",
            "wrong-key",
            "--input",
            "input.bin",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--key", result.stderr)

    def test_missing_input_file(self):
        result = self.run_cli(
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--encrypt",
            "--key",
            KEY_HEX,
            "--input",
            self.directory / "missing.bin",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Ошибка", result.stderr)

    def test_short_encrypted_file(self):
        encrypted = self.directory / "short.bin"
        decrypted = self.directory / "decrypted.bin"
        encrypted.write_bytes(b"short")

        result = self.run_cli(
            "--algorithm",
            "aes",
            "--mode",
            "cbc",
            "--decrypt",
            "--key",
            KEY_HEX,
            "--input",
            encrypted,
            "--output",
            decrypted,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("IV", result.stderr)


if __name__ == "__main__":
    unittest.main()