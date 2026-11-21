"""Потоковые файловые операции AEAD."""

from contextlib import contextmanager
from hmac import compare_digest
import io
import os
from pathlib import Path
import tempfile

from cryptocore import csprng
from cryptocore.aead import AuthenticationError
from cryptocore.aead.etm import ETMContext
from cryptocore.aead.gcm import GCMContext


CHUNK_SIZE = 8192


def check_paths(input_path, output_path) -> None:
    source = os.path.normcase(os.path.realpath(input_path))
    destination = os.path.normcase(os.path.realpath(output_path))

    if source == destination:
        raise ValueError(
            "Входной и выходной файлы должны различаться."
        )

    if os.path.exists(input_path) and os.path.exists(output_path):
        if os.path.samefile(input_path, output_path):
            raise ValueError(
                "Входной и выходной файлы должны различаться."
            )


@contextmanager
def atomic_output(path):
    path = Path(path)
    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=str(path.parent),
            prefix=".cryptocore-",
            delete=False,
        ) as destination:
            temporary_path = destination.name
            yield destination

        os.replace(temporary_path, path)
        temporary_path = None

    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


@contextmanager
def open_aad(aad=b"", aad_path=None):
    if aad_path is None:
        with io.BytesIO(aad) as source:
            yield source
    else:
        if aad:
            raise ValueError(
                "Нельзя одновременно передавать aad и aad_path."
            )

        with open(aad_path, "rb") as source:
            yield source


def create_context(mode, key, nonce, aad_stream):
    if mode == "gcm":
        return GCMContext(key, nonce, aad_stream)

    if mode == "etm":
        return ETMContext(key, nonce, aad_stream)

    raise ValueError(f"Неизвестный AEAD-режим: {mode}")


def encrypt_file(
    input_path,
    output_path,
    key,
    mode="gcm",
    aad=b"",
    aad_path=None,
):
    check_paths(input_path, output_path)

    if aad_path is not None:
        check_paths(aad_path, output_path)

    nonce = csprng.generate_random_bytes(12)

    with open_aad(aad, aad_path) as associated:
        context = create_context(mode, key, nonce, associated)

        with open(input_path, "rb") as source:
            with atomic_output(output_path) as destination:
                destination.write(nonce)

                while True:
                    chunk = source.read(CHUNK_SIZE)

                    if not chunk:
                        break

                    ciphertext = context.counter.transform(chunk)
                    context.update(ciphertext)
                    destination.write(ciphertext)

                destination.write(context.tag())


def decrypt_file(
    input_path,
    output_path,
    key,
    mode="gcm",
    aad=b"",
    aad_path=None,
    nonce=None,
):
    check_paths(input_path, output_path)

    if aad_path is not None:
        check_paths(aad_path, output_path)

    if nonce is not None and len(nonce) != 12:
        raise ValueError(
            "В файловом интерфейсе nonce должен содержать 12 байт."
        )

    with open(input_path, "rb") as source:
        actual_nonce = (
            source.read(12)
            if nonce is None
            else bytes(nonce)
        )

        if len(actual_nonce) != 12:
            raise AuthenticationError(
                "Слишком короткий AEAD-файл."
            )

        with open_aad(aad, aad_path) as associated:
            context = create_context(
                mode,
                key,
                actual_nonce,
                associated,
            )

            # Снимок шифртекста исключает его замену
            # между проверкой и расшифрованием.
            with tempfile.TemporaryFile(mode="w+b") as snapshot:
                pending = b""

                while True:
                    chunk = source.read(CHUNK_SIZE)

                    if not chunk:
                        break

                    pending += chunk

                    if len(pending) > context.tag_size:
                        part = pending[:-context.tag_size]
                        pending = pending[-context.tag_size:]

                        context.update(part)
                        snapshot.write(part)

                if len(pending) != context.tag_size:
                    raise AuthenticationError(
                        "Отсутствует полный тег аутентификации."
                    )

                if not compare_digest(context.tag(), pending):
                    raise AuthenticationError(
                        "Authentication failed: неверный ключ, "
                        "AAD или изменённые данные."
                    )

                snapshot.seek(0)

                # Создаётся только после успешной аутентификации.
                with atomic_output(output_path) as destination:
                    while True:
                        chunk = snapshot.read(CHUNK_SIZE)

                        if not chunk:
                            break

                        destination.write(
                            context.counter.transform(chunk)
                        )