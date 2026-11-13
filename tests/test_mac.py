"""Проверки HMAC и AES-CMAC."""

import hashlib
import hmac as reference_hmac
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from Crypto.Hash import CMAC as ReferenceCMAC
from Crypto.Cipher import AES

from cryptocore.mac import CHUNK_SIZE
from cryptocore.mac import mac_file
from cryptocore.mac import mac_stream
from cryptocore.mac.cmac import CMAC
from cryptocore.mac.hmac import HMAC


KEY = bytes.fromhex("00112233445566778899aabbccddeeff")

RFC_VECTORS = (
    (
        b"\x0b" * 20,
        b"Hi There",
        "b0344c61d8db38535ca8afceaf0bf12b8"
        "81dc200c9833da726e9376c2e32cff7",
    ),
    (
        b"Jefe",
        b"what do ya want for nothing?",
        "5bdcc146bf60754e6a042426089575c75"
        "a003f089d2739839dec58b964ec3843",
    ),
    (
        b"\xaa" * 20,
        b"\xdd" * 50,
        "773ea91e36800e46854db8ebd09181a72"
        "959098b3ef8c122d9635514ced565fe",
    ),
    (
        bytes(range(1, 26)),
        b"\xcd" * 50,
        "82558a389a443c0ea4cc819899f2083a8"
        "5f0faa3e578f8077a2e3ff46729665b",
    ),
    (
        b"\x0c" * 20,
        b"Test With Truncation",
        "a3b6167473100ee06e0c796c2955552b",
    ),
    (
        b"\xaa" * 131,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "60e431591ee0b67f0d8a26aacbf5b77f"
        "8e0bc6213728c5140546040f0ee37f54",
    ),
    (
        b"\xaa" * 131,
        b"This is a test using a larger than block-size key "
        b"and a larger than block-size data. The key needs "
        b"to be hashed before being used by the HMAC algorithm.",
        "9b09ffa71b942fcb27635fbcd5b0e944b"
        "fdc63644f0713938a7f51535c3a35e2",
    ),
)

CMAC_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")

CMAC_MESSAGE = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)


class HMACTests(unittest.TestCase):
    def test_rfc4231(self):
        for number, (key, message, expected) in enumerate(
            RFC_VECTORS, 1
        ):
            with self.subTest(case=number):
                actual = HMAC(key).compute(message)

                if number == 5:
                    actual = actual[:32]

                self.assertEqual(actual, expected)

    def test_key_sizes_and_empty_input(self):
        for size in (0, 1, 16, 63, 64, 65, 100, 131, 1024):
            key = bytes(index % 256 for index in range(size))

            for message in (b"", b"abc", bytes(range(256))):
                with self.subTest(key_size=size, size=len(message)):
                    actual = HMAC(key).compute(message)
                    expected = reference_hmac.new(
                        key,
                        message,
                        hashlib.sha256,
                    ).hexdigest()

                    self.assertEqual(actual, expected)

    def test_incremental_updates(self):
        message = bytes(range(256)) * 4

        for step in (1, 7, 63, 64, 65, 257):
            with self.subTest(step=step):
                result = HMAC(KEY)

                for position in range(0, len(message), step):
                    result.update(message[position:position + step])

                self.assertEqual(
                    result.hexdigest(),
                    reference_hmac.new(
                        KEY, message, hashlib.sha256
                    ).hexdigest(),
                )

    def test_digest_and_copy(self):
        result = HMAC(KEY)
        result.update(b"abc")

        first = result.digest()
        self.assertEqual(result.digest(), first)

        copied = result.copy()
        copied.update(b"def")

        self.assertEqual(
            result.digest(),
            reference_hmac.new(
                KEY, b"abc", hashlib.sha256
            ).digest(),
        )
        self.assertEqual(
            copied.digest(),
            reference_hmac.new(
                KEY, b"abcdef", hashlib.sha256
            ).digest(),
        )

        self.assertTrue(result.verify(first))
        self.assertFalse(result.verify(b"\x00" * 32))


class CMACTests(unittest.TestCase):
    def test_nist_vectors(self):
        vectors = (
            (0, "bb1d6929e95937287fa37d129b756746"),
            (16, "070a16b46b4d4144f79bdd9dd04a287c"),
            (40, "dfa66747de9ae63030ca32611497c827"),
            (64, "51f0bebf7e3b9d92fc49741779363cfe"),
        )

        for length, expected in vectors:
            with self.subTest(length=length):
                self.assertEqual(
                    CMAC(CMAC_KEY).compute(CMAC_MESSAGE[:length]),
                    expected,
                )

    def test_incremental_boundaries(self):
        for length in (0, 1, 15, 16, 17, 31, 32, 33, 137):
            message = bytes(index % 256 for index in range(length))

            reference = ReferenceCMAC.new(KEY, ciphermod=AES)
            reference.update(message)

            for step in (1, 7, 16, 17, 64):
                with self.subTest(length=length, step=step):
                    result = CMAC(KEY)

                    for position in range(0, len(message), step):
                        result.update(message[position:position + step])

                    result.update(b"")
                    self.assertEqual(
                        result.digest(),
                        reference.digest(),
                    )

    def test_digest_and_copy(self):
        result = CMAC(KEY)
        result.update(b"abc")
        first = result.digest()

        self.assertEqual(result.digest(), first)

        copied = result.copy()
        copied.update(b"def")

        reference = ReferenceCMAC.new(KEY, ciphermod=AES)
        reference.update(b"abcdef")

        self.assertEqual(copied.digest(), reference.digest())
        self.assertEqual(result.digest(), first)
        self.assertTrue(result.verify(first))
        self.assertFalse(result.verify(b"\x00" * 16))

    def test_invalid_key(self):
        for size in (0, 15, 17, 32):
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    CMAC(b"x" * size)


class StreamingTests(unittest.TestCase):
    def test_bounded_reads(self):
        class CheckedStream(io.BytesIO):
            def read(self, size=-1):
                if not 0 < size <= CHUNK_SIZE:
                    raise AssertionError("Неверный размер чтения.")

                return super().read(size)

        message = bytes(range(256)) * 40

        for kind in ("hmac", "cmac"):
            with self.subTest(kind=kind):
                actual = mac_stream(
                    CheckedStream(message), kind, KEY
                )

                if kind == "hmac":
                    expected = reference_hmac.new(
                        KEY, message, hashlib.sha256
                    ).digest()
                else:
                    reference = ReferenceCMAC.new(KEY, ciphermod=AES)
                    reference.update(message)
                    expected = reference.digest()

                self.assertEqual(actual, expected)


class MACCLITests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

        self.source = self.directory / "message with spaces.bin"
        self.source.write_bytes(bytes(range(37)))
        self.tag_file = self.directory / "expected.mac"

    def run_cli(self, *arguments, data=None):
        return subprocess.run(
            [
                sys.executable,
                "-m",
                "cryptocore.cli",
                "dgst",
                *map(str, arguments),
            ],
            input=data,
            capture_output=True,
            check=False,
        )

    def options(self, kind):
        return [
            "--algorithm", "sha256" if kind == "hmac" else "aes",
            f"--{kind}",
            "--key", KEY.hex(),
            "--input", str(self.source),
        ]

    def generate(self, kind):
        result = self.run_cli(
            *self.options(kind),
            "--output", self.tag_file,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"")

    def test_output_format_and_verification(self):
        for kind in ("hmac", "cmac"):
            with self.subTest(kind=kind):
                expected = mac_file(self.source, kind, KEY).hex()

                result = self.run_cli(*self.options(kind))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    result.stdout.decode().splitlines(),
                    [f"{expected} {self.source}"],
                )

                self.generate(kind)

                self.assertEqual(
                    self.tag_file.read_text(encoding="utf-8"),
                    f"{expected} {self.source}\n",
                )

                result = self.run_cli(
                    *self.options(kind),
                    "--verify", self.tag_file,
                )

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(b"[OK]", result.stdout)

    def test_changed_file(self):
        for kind in ("hmac", "cmac"):
            with self.subTest(kind=kind):
                original = bytes(range(37))
                self.source.write_bytes(original)
                self.generate(kind)

                changed = bytearray(original)
                changed[0] ^= 1
                self.source.write_bytes(changed)

                result = self.run_cli(
                    *self.options(kind),
                    "--verify", self.tag_file,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"[ERROR]", result.stderr)

    def test_wrong_key(self):
        for kind in ("hmac", "cmac"):
            with self.subTest(kind=kind):
                self.generate(kind)
                options = self.options(kind)
                options[options.index("--key") + 1] = "ff" * 16

                result = self.run_cli(
                    *options,
                    "--verify", self.tag_file,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"[ERROR]", result.stderr)

    def test_flexible_expected_format(self):
        for kind in ("hmac", "cmac"):
            with self.subTest(kind=kind):
                expected = mac_file(self.source, kind, KEY).hex()

                self.tag_file.write_text(
                    f"\n  {expected.upper()}\t ignored filename.bin  \n",
                    encoding="utf-8-sig",
                )

                result = self.run_cli(
                    *self.options(kind),
                    "--verify", self.tag_file,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_invalid_expected_files(self):
        cases = (
            "",
            "not-a-mac file.bin\n",
            "00 file.bin\n",
            ("00" * 32) + " file.bin\nsecond entry\n",
        )

        for content in cases:
            with self.subTest(content=content):
                self.tag_file.write_text(content, encoding="utf-8")

                result = self.run_cli(
                    *self.options("hmac"),
                    "--verify", self.tag_file,
                )

                self.assertNotEqual(result.returncode, 0)

    def test_missing_expected_file(self):
        result = self.run_cli(
            *self.options("hmac"),
            "--verify", self.directory / "missing.mac",
        )
        self.assertNotEqual(result.returncode, 0)

    def test_missing_input_file(self):
        options = self.options("hmac")
        options[-1] = str(self.directory / "missing.bin")

        result = self.run_cli(*options)
        self.assertNotEqual(result.returncode, 0)

    def test_invalid_output(self):
        result = self.run_cli(
            *self.options("hmac"),
            "--output", self.directory / "missing" / "tag.mac",
        )
        self.assertNotEqual(result.returncode, 0)

    def test_same_input_output(self):
        original = self.source.read_bytes()

        result = self.run_cli(
            *self.options("hmac"),
            "--output", self.source,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.source.read_bytes(), original)

    def test_missing_and_invalid_keys(self):
        result = self.run_cli(
            "--algorithm", "sha256",
            "--hmac",
            "--input", self.source,
        )
        self.assertNotEqual(result.returncode, 0)

        for key in ("0", "gg", "00 11"):
            with self.subTest(key=key):
                result = self.run_cli(
                    "--algorithm", "sha256",
                    "--hmac",
                    "--key", key,
                    "--input", self.source,
                )
                self.assertNotEqual(result.returncode, 0)

    def test_cli_hmac_key_sizes(self):
        for size in (16, 64, 100):
            with self.subTest(size=size):
                key = bytes(range(size))

                result = self.run_cli(
                    "--algorithm", "sha256",
                    "--hmac",
                    "--key", key.hex(),
                    "--input", self.source,
                )

                expected = reference_hmac.new(
                    key,
                    self.source.read_bytes(),
                    hashlib.sha256,
                ).hexdigest()

                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    result.stdout.decode().split()[0],
                    expected,
                )

    def test_empty_file(self):
        self.source.write_bytes(b"")

        for kind in ("hmac", "cmac"):
            with self.subTest(kind=kind):
                self.generate(kind)

                result = self.run_cli(
                    *self.options(kind),
                    "--verify", self.tag_file,
                )

                self.assertEqual(result.returncode, 0, result.stderr)

    def test_stdin(self):
        result = self.run_cli(
            "--algorithm", "sha256",
            "--hmac",
            "--key", KEY.hex(),
            "--input", "-",
            data=b"abc",
        )

        expected = reference_hmac.new(
            KEY, b"abc", hashlib.sha256
        ).hexdigest()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.decode().strip(),
            f"{expected} -",
        )

    def test_invalid_combinations(self):
        cases = (
            [
                "--algorithm", "sha3-256",
                "--hmac", "--key", KEY.hex(),
            ],
            [
                "--algorithm", "sha256",
                "--cmac", "--key", KEY.hex(),
            ],
            [
                "--algorithm", "aes",
                "--cmac", "--key", "00",
            ],
            [
                "--algorithm", "sha256",
                "--hmac", "--cmac", "--key", KEY.hex(),
            ],
            [
                "--algorithm", "sha256",
                "--key", KEY.hex(),
            ],
            [
                "--algorithm", "sha256",
                "--verify", str(self.tag_file),
            ],
            [
                "--algorithm", "sha256",
                "--hmac", "--key", KEY.hex(),
                "--verify", str(self.tag_file),
                "--output", str(self.directory / "result.mac"),
            ],
        )

        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = self.run_cli(
                    *arguments,
                    "--input", self.source,
                )
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()