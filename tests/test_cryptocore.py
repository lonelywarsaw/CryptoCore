"""Проверки шифрования, CLI и совместимости с OpenSSL."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptocore.modes.ecb import decrypt, encrypt

KEY_HEX = "000102030405060708090a0b0c0d0e0f"
KEY = bytes.fromhex(KEY_HEX)


class ECBTests(unittest.TestCase):
    def test_round_trip_for_empty_text_and_binary_data(self):
        samples = [
            b"",
            "Привет, CryptoCore!".encode("utf-8"),
            bytes(range(256)),
            b"x" * 16,
        ]

        for original in samples:
            with self.subTest(length=len(original)):
                ciphertext = encrypt(original, KEY)

                self.assertEqual(len(ciphertext) % 16, 0)
                self.assertGreater(len(ciphertext), len(original))
                self.assertEqual(decrypt(ciphertext, KEY), original)

    def test_wrong_key_length(self):
        with self.assertRaises(ValueError):
            encrypt(b"data", b"short")

    def test_invalid_ciphertext_length(self):
        with self.assertRaises(ValueError):
            decrypt(b"", KEY)

        with self.assertRaises(ValueError):
            decrypt(b"invalid", KEY)

    def test_invalid_padding(self):
        # Этот блок после расшифрования оканчивается нулём.
        # Ноль не является допустимой длиной дополнения PKCS#7.
        from Crypto.Cipher import AES

        malformed = b"\x00" * 16
        ciphertext = AES.new(KEY, AES.MODE_ECB).encrypt(malformed)

        with self.assertRaisesRegex(ValueError, "PKCS#7"):
            decrypt(ciphertext, KEY)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.directory = Path(self.temporary_directory.name)

    def run_cli(self, *arguments):
        return subprocess.run(
            [sys.executable, "-m", "cryptocore.cli", *map(str, arguments)],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_file_round_trip(self):
        original = self.directory / "original.bin"
        encrypted = self.directory / "encrypted.bin"
        decrypted = self.directory / "decrypted.bin"
        content = bytes(range(256)) + b"\x00\xff"
        original.write_bytes(content)

        encryption = self.run_cli(
            "--algorithm", "aes",
            "--mode", "ecb",
            "--encrypt",
            "--key", KEY_HEX,
            "--input", original,
            "--output", encrypted,
        )
        self.assertEqual(encryption.returncode, 0, encryption.stderr)

        decryption = self.run_cli(
            "--algorithm", "aes",
            "--mode", "ecb",
            "--decrypt",
            "--key", KEY_HEX,
            "--input", encrypted,
            "--output", decrypted,
        )
        self.assertEqual(decryption.returncode, 0, decryption.stderr)
        self.assertEqual(decrypted.read_bytes(), content)

    def test_default_output_name(self):
        original = self.directory / "sample.bin"
        original.write_bytes(b"sample")

        result = self.run_cli(
            "--algorithm", "aes",
            "--mode", "ecb",
            "--encrypt",
            "--key", KEY_HEX,
            "--input", original,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(Path(str(original) + ".enc").is_file())

    def test_conflicting_operations(self):
        result = self.run_cli(
            "--algorithm", "aes",
            "--mode", "ecb",
            "--encrypt",
            "--decrypt",
            "--key", KEY_HEX,
            "--input", "data.bin",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("error:", result.stderr)

    def test_invalid_key(self):
        result = self.run_cli(
            "--algorithm", "aes",
            "--mode", "ecb",
            "--encrypt",
            "--key", "not-a-hex-key",
            "--input", "data.bin",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--key", result.stderr)

    def test_missing_input(self):
        result = self.run_cli(
            "--algorithm", "aes",
            "--mode", "ecb",
            "--encrypt",
            "--key", KEY_HEX,
            "--input", self.directory / "missing.bin",
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Ошибка:", result.stderr)

    def test_same_input_and_output(self):
        original = self.directory / "original.bin"
        original.write_bytes(b"unchanged")

        result = self.run_cli(
            "--algorithm", "aes",
            "--mode", "ecb",
            "--encrypt",
            "--key", KEY_HEX,
            "--input", original,
            "--output", original,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(original.read_bytes(), b"unchanged")

    @unittest.skipUnless(shutil.which("openssl"), "OpenSSL не установлен")
    def test_ciphertext_matches_openssl(self):
        original = self.directory / "original.bin"
        encrypted = self.directory / "cryptocore.bin"
        reference = self.directory / "openssl.bin"
        original.write_bytes(bytes(range(35)))

        result = self.run_cli(
            "--algorithm", "aes",
            "--mode", "ecb",
            "--encrypt",
            "--key", KEY_HEX,
            "--input", original,
            "--output", encrypted,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

        openssl_result = subprocess.run(
            [
                "openssl", "enc", "-aes-128-ecb",
                "-K", KEY_HEX,
                "-in", str(original),
                "-out", str(reference),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            openssl_result.returncode,
            0,
            openssl_result.stderr,
        )
        self.assertEqual(encrypted.read_bytes(), reference.read_bytes())


if __name__ == "__main__":
    unittest.main()