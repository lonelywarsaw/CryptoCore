"""Команда dgst."""

import argparse
import os
import sys

from cryptocore.hashes import ALGORITHMS
from cryptocore.hashes import hash_file
from cryptocore.hashes import hash_stream


def check_output_path(input_path: str, output_path: str) -> None:
    if input_path == "-":
        return

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


def main(arguments=None) -> int:
    parser = argparse.ArgumentParser(
        prog="cryptocore dgst",
        description="Вычисление хеша файла.",
        allow_abbrev=False,
    )

    parser.add_argument(
        "--algorithm",
        required=True,
        choices=sorted(ALGORITHMS),
    )
    parser.add_argument("--input", required=True)
    parser.add_argument("--output")

    args = parser.parse_args(arguments)

    try:
        if args.output is not None:
            check_output_path(args.input, args.output)

        if args.input == "-":
            digest = hash_stream(
                sys.stdin.buffer,
                args.algorithm,
            )
        else:
            digest = hash_file(args.input, args.algorithm)

        line = f"{digest}  {args.input}\n"

        if args.output is None:
            sys.stdout.write(line)
        else:
            with open(
                args.output,
                "w",
                encoding="utf-8",
                newline="\n",
            ) as destination:
                destination.write(line)

    except (OSError, ValueError) as error:
        print(f"Ошибка хеширования: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())