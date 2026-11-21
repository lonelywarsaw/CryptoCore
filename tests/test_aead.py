"""Проверки AEAD."""

import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Crypto.Cipher import AES

from cryptocore.aead import AuthenticationError
from cryptocore.aead.etm import derive_keys
from cryptocore.aead.files import decrypt_file
from cryptocore.aead.files import encrypt_file
from cryptocore.aead.gcm import GCM
from cryptocore.aead.gcm import GCMContext
from cryptocore.aead.gcm import GHASH
from cryptocore.aead.gcm import multiply_gf


KEY = bytes(range(16))
MASTER = bytes(range(32))
NONCE = bytes(range(12))


class GCMTests(unittest.TestCase):
    def test_known_answers(self):
        vectors = (
            (
                b"",
                "",
                "58e2fccefa7e3061367f1d57a4e7455a",
            ),
            (
                b"\x00" * 16,
                "0388dace60b6a392f328c2b971b2fe78",
                "ab6e47d42cec13bdf53a67b21257bddf",
            ),
        )

        for plaintext, ciphertext, tag in vectors:
            with self.subTest(length=len(plaintext)):
                result = GCM(b"\x00" * 16, b"\x00" * 12)
                actual, actual_tag = result.encrypt_detached(plaintext)

                self.assertEqual(actual.hex(), ciphertext)
                self.assertEqual(actual_tag.hex(), tag)
                self.assertEqual(
                    result.decrypt_detached(actual, actual_tag),
                    plaintext,
                )

    def test_known_answer_with_aad(self):
        key = bytes.fromhex("feffe9928665731c6d6a8f9467308308")
        nonce = bytes.fromhex("cafebabefacedbaddecaf888")
        aad = bytes.fromhex(
            "feedfacedeadbeeffeedfacedeadbeefabaddad2"
        )
        plaintext = bytes.fromhex(
            "d9313225f88406e5a55909c5aff5269a"
            "86a7a9531534f7da2e4c303d8a318a72"
            "1c3c0c95956809532fcf0e2449a6b525"
            "b16aedf5aa0de657ba637b39"
        )

        ciphertext, tag = GCM(key, nonce).encrypt_detached(
            plaintext, aad
        )

        self.assertEqual(
            ciphertext.hex(),
            "42831ec2217774244b7221b784d0d49c"
            "e3aa212f2c02a4e035c17e2329aca12e"
            "21d514b25466931c7d8f6a5aac84aa05"
            "1ba30b396a0aac973d58e091",
        )
        self.assertEqual(
            tag.hex(),
            "5bc94fbc3221a5db94fae95ae7121a47",
        )

    def test_reference_boundaries(self):
        for nonce_size in (8, 12, 16, 31):
            for text_size in (0, 1, 15, 16, 17, 63):
                for aad_size in (0, 1, 15, 16, 17, 39):
                    with self.subTest(
                        nonce=nonce_size,
                        text=text_size,
                        aad=aad_size,
                    ):
                        nonce = bytes(range(nonce_size))
                        text = bytes(range(text_size))
                        aad = bytes(range(aad_size))

                        reference = AES.new(
                            KEY, AES.MODE_GCM, nonce=nonce
                        )
                        reference.update(aad)
                        expected, expected_tag = (
                            reference.encrypt_and_digest(text)
                        )

                        result = GCM(KEY, nonce)
                        actual, tag = result.encrypt_detached(text, aad)

                        self.assertEqual(actual, expected)
                        self.assertEqual(tag, expected_tag)
                        self.assertEqual(
                            result.decrypt_detached(actual, tag, aad),
                            text,
                        )

    def test_table_multiplication(self):
        hash_key = AES.new(KEY, AES.MODE_ECB).encrypt(b"\x00" * 16)
        result = GHASH(hash_key)
        multiplier = int.from_bytes(hash_key, "big")

        for value in (
            0,
            1,
            1 << 127,
            (1 << 128) - 1,
            int.from_bytes(bytes(range(16)), "big"),
        ):
            self.assertEqual(
                result.multiply(value),
                multiply_gf(value, multiplier),
            )

    def test_every_bit_tamper(self):
        original = GCM(KEY, NONCE).encrypt(
            b"Small message", b"header"
        )

        for position in range(len(original)):
            for bit in range(8):
                with self.subTest(position=position, bit=bit):
                    changed = bytearray(original)
                    changed[position] ^= 1 << bit

                    with self.assertRaises(AuthenticationError):
                        GCM(KEY).decrypt(bytes(changed), b"header")

    def test_unique_nonces(self):
        nonces = {GCM(KEY).nonce for _ in range(1000)}
        self.assertEqual(len(nonces), 1000)

    def test_chunked_aad(self):
        class CheckedStream(io.BytesIO):
            def read(self, size=-1):
                if not 0 < size <= 8192:
                    raise AssertionError("Неверный размер чтения.")

                return super().read(size)

        aad = b"header" * 3000
        text = b"message"

        context = GCMContext(KEY, NONCE, CheckedStream(aad))
        ciphertext = context.counter.transform(text)
        context.update(ciphertext)

        expected, expected_tag = GCM(
            KEY, NONCE
        ).encrypt_detached(text, aad)

        self.assertEqual(ciphertext, expected)
        self.assertEqual(context.tag(), expected_tag)

    def test_openssl_compatibility(self):
        from cryptography.hazmat.backends.openssl.backend import backend
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self.assertIn("OpenSSL", backend.openssl_version_text())

        text = b"OpenSSL compatibility"
        aad = b"header"

        reference = AESGCM(KEY)
        ours = GCM(KEY, NONCE).encrypt(text, aad)
        theirs = reference.encrypt(NONCE, text, aad)

        self.assertEqual(ours[12:], theirs)
        self.assertEqual(
            reference.decrypt(NONCE, ours[12:], aad),
            text,
        )
        self.assertEqual(
            GCM(KEY).decrypt(NONCE + theirs, aad),
            text,
        )


class FileTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temporary = temporary
        self.directory = Path(temporary.name)

        self.source = self.directory / "input.bin"
        self.encrypted = self.directory / "encrypted.bin"
        self.output = self.directory / "output.bin"
        self.aad = self.directory / "aad.bin"

        self.source.write_bytes(bytes(range(256)) * 40 + b"end")
        self.aad.write_bytes(b"metadata" * 2000)

    def test_round_trip(self):
        for mode, key in (("gcm", KEY), ("etm", MASTER)):
            for aad in (b"", b"header"):
                with self.subTest(mode=mode, aad=aad):
                    encrypt_file(
                        self.source, self.encrypted, key,
                        mode=mode, aad=aad,
                    )
                    decrypt_file(
                        self.encrypted, self.output, key,
                        mode=mode, aad=aad,
                    )
                    self.assertEqual(
                        self.output.read_bytes(),
                        self.source.read_bytes(),
                    )

    def test_aad_file(self):
        for mode, key in (("gcm", KEY), ("etm", MASTER)):
            with self.subTest(mode=mode):
                encrypt_file(
                    self.source, self.encrypted, key,
                    mode=mode, aad_path=self.aad,
                )
                decrypt_file(
                    self.encrypted, self.output, key,
                    mode=mode, aad_path=self.aad,
                )
                self.assertEqual(
                    self.output.read_bytes(),
                    self.source.read_bytes(),
                )

    def test_empty_file(self):
        self.source.write_bytes(b"")

        for mode, key, tag_size in (
            ("gcm", KEY, 16),
            ("etm", MASTER, 32),
        ):
            with self.subTest(mode=mode):
                encrypt_file(
                    self.source, self.encrypted, key, mode=mode
                )
                self.assertEqual(
                    self.encrypted.stat().st_size,
                    12 + tag_size,
                )
                decrypt_file(
                    self.encrypted, self.output, key, mode=mode
                )
                self.assertEqual(self.output.read_bytes(), b"")

    def test_wrong_aad_preserves_output(self):
        for mode, key in (("gcm", KEY), ("etm", MASTER)):
            with self.subTest(mode=mode):
                encrypt_file(
                    self.source, self.encrypted, key,
                    mode=mode, aad=b"correct",
                )

                if self.output.exists():
                    self.output.unlink()

                with self.assertRaises(AuthenticationError):
                    decrypt_file(
                        self.encrypted, self.output, key,
                        mode=mode, aad=b"wrong",
                    )

                self.assertFalse(self.output.exists())
                self.output.write_bytes(b"KEEP")

                with self.assertRaises(AuthenticationError):
                    decrypt_file(
                        self.encrypted, self.output, key,
                        mode=mode, aad=b"wrong",
                    )

                self.assertEqual(self.output.read_bytes(), b"KEEP")

    def test_wrong_key_and_tamper(self):
        for mode, key in (("gcm", KEY), ("etm", MASTER)):
            with self.subTest(mode=mode):
                encrypt_file(
                    self.source, self.encrypted, key, mode=mode
                )
                original = self.encrypted.read_bytes()

                for position in (0, 12, len(original) - 1):
                    changed = bytearray(original)
                    changed[position] ^= 1
                    self.encrypted.write_bytes(changed)

                    with self.assertRaises(AuthenticationError):
                        decrypt_file(
                            self.encrypted, self.output, key,
                            mode=mode,
                        )

                self.encrypted.write_bytes(original)

                with self.assertRaises(AuthenticationError):
                    decrypt_file(
                        self.encrypted, self.output,
                        b"\xff" * len(key), mode=mode,
                    )

    def test_external_nonce(self):
        encrypt_file(self.source, self.encrypted, KEY)
        original = self.encrypted.read_bytes()

        self.encrypted.write_bytes(original[12:])

        decrypt_file(
            self.encrypted, self.output, KEY,
            nonce=original[:12],
        )
        self.assertEqual(
            self.output.read_bytes(),
            self.source.read_bytes(),
        )

    def test_short_files(self):
        for mode, key in (("gcm", KEY), ("etm", MASTER)):
            for length in (0, 11, 12, 20):
                with self.subTest(mode=mode, length=length):
                    self.encrypted.write_bytes(b"\x00" * length)

                    with self.assertRaises(AuthenticationError):
                        decrypt_file(
                            self.encrypted, self.output, key,
                            mode=mode,
                        )

    def test_csprng(self):
        with patch(
            "cryptocore.csprng.generate_random_bytes",
            return_value=NONCE,
        ) as source:
            encrypt_file(self.source, self.encrypted, KEY)

        source.assert_called_once_with(12)
        self.assertEqual(
            self.encrypted.read_bytes()[:12],
            NONCE,
        )

    def test_same_path(self):
        with self.assertRaises(ValueError):
            encrypt_file(self.source, self.source, KEY)

    def test_distinct_derived_keys(self):
        encryption_key, mac_key = derive_keys(MASTER)
        self.assertEqual(len(encryption_key), 16)
        self.assertEqual(len(mac_key), 32)
        self.assertNotEqual(encryption_key, mac_key[:16])


class CLITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.temporary = temporary

        directory = Path(temporary.name)
        self.source = directory / "input.bin"
        self.encrypted = directory / "encrypted.bin"
        self.output = directory / "output.bin"
        self.source.write_bytes(b"Secret message")

    def run_cli(self, mode, action, source, output, *extra):
        return subprocess.run(
            [
                sys.executable,
                "-m", "cryptocore.cli",
                "--algorithm", "aes",
                "--mode", mode,
                action,
                "--input", str(source),
                "--output", str(output),
                *extra,
            ],
            capture_output=True,
            check=False,
        )

    def test_success_and_wrong_aad(self):
        for mode, key in (("gcm", KEY), ("etm", MASTER)):
            with self.subTest(mode=mode):
                result = self.run_cli(
                    mode, "--encrypt",
                    self.source, self.encrypted,
                    "--key", key.hex(), "--aad", "aabb",
                )
                self.assertEqual(result.returncode, 0, result.stderr)

                result = self.run_cli(
                    mode, "--decrypt",
                    self.encrypted, self.output,
                    "--key", key.hex(), "--aad", "aabb",
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    self.output.read_bytes(),
                    self.source.read_bytes(),
                )

                self.output.unlink()

                result = self.run_cli(
                    mode, "--decrypt",
                    self.encrypted, self.output,
                    "--key", key.hex(), "--aad", "aabc",
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"Authentication failed", result.stderr)
                self.assertFalse(self.output.exists())

    def test_generated_key(self):
        for mode, size in (("gcm", 16), ("etm", 32)):
            with self.subTest(mode=mode):
                result = self.run_cli(
                    mode, "--encrypt",
                    self.source, self.encrypted,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

                key = result.stdout.decode().strip().split()[-1]
                self.assertEqual(len(bytes.fromhex(key)), size)

                result = self.run_cli(
                    mode, "--decrypt",
                    self.encrypted, self.output,
                    "--key", key,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_options(self):
        for options in (
            ("--aad", "nothex"),
            ("--nonce", NONCE.hex()),
            ("--iv", NONCE.hex()),
            ("--aad", "aa", "--aad-file", "metadata.bin"),
        ):
            with self.subTest(options=options):
                result = self.run_cli(
                    "gcm", "--encrypt",
                    self.source, self.encrypted,
                    "--key", KEY.hex(),
                    *options,
                )
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()