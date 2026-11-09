"""Command line interface for logveil-shield."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .detectors import DETECTORS, build_custom_detector
from .engine import MODES, Redactor


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logveil-shield",
        description=(
            "Scrub secrets and sensitive data from logs and config files "
            "before sharing them. Reads files, directories, or stdin."
        ),
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        metavar="PATH",
        help="Files to scrub. Directories need --recursive. Reads stdin when omitted.",
    )
    parser.add_argument(
        "--mode",
        choices=MODES,
        default="redact",
        help="redact: [REDACTED:TYPE] (default). tokenize: consistent [TYPE_N] "
        "pseudonyms per unique value. hash: [HASH:TYPE:abcdef123456].",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Print a summary table of redactions by type to stderr.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if any sensitive data is found (for CI or pre-commit hooks). "
        "Prints no scrubbed output.",
    )
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Rewrite each input file with its scrubbed content.",
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="Write scrubbed output to FILE instead of stdout.",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Descend into directories given as inputs.",
    )
    parser.add_argument(
        "-p",
        "--pattern",
        action="append",
        default=[],
        metavar="NAME=PATTERN",
        help="Add a custom redaction regex. Repeatable. Example: -p SESSION_ID='sess_[a-z0-9]{16}'.",
    )
    parser.add_argument(
        "--list-detectors",
        action="store_true",
        help="List the built-in detectors and exit.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def _parse_custom_patterns(raw_patterns: list[str]):
    detectors = []
    for raw in raw_patterns:
        if "=" not in raw:
            raise ValueError(f"--pattern must be NAME=PATTERN, got {raw!r}")
        name, pattern = raw.split("=", 1)
        name = name.strip()
        if not name:
            raise ValueError(f"--pattern must be NAME=PATTERN, got {raw!r}")
        detectors.append(build_custom_detector(name, pattern))
    return detectors


def _iter_input_files(inputs: list[str], recursive: bool):
    """Yield (label, path or None) for each input. path is None for stdin."""
    if not inputs:
        yield ("<stdin>", None)
        return
    for item in inputs:
        if item == "-":
            yield ("<stdin>", None)
            continue
        if not os.path.exists(item):
            raise FileNotFoundError(f"no such file or directory: {item}")
        if os.path.isdir(item):
            if not recursive:
                raise IsADirectoryError(
                    f"{item} is a directory; pass --recursive to scrub it"
                )
            for root, _dirs, files in os.walk(item):
                for name in sorted(files):
                    path = os.path.join(root, name)
                    yield (path, path)
        else:
            yield (item, item)


def _read_text(path: str | None) -> str:
    if path is None:
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _print_report(counts: dict[str, int], stream) -> None:
    total = sum(counts.values())
    stream.write(f"\n{'TYPE':<22}{'COUNT':>8}\n")
    stream.write(f"{'-' * 22}{' ' + '-' * 7:>8}\n")
    for name, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        stream.write(f"{name:<22}{count:>8}\n")
    stream.write(f"{'-' * 22}{' ' + '-' * 7:>8}\n")
    stream.write(f"{'TOTAL':<22}{total:>8}\n")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_detectors:
        for detector in DETECTORS:
            print(f"{detector.name:<20} {detector.description}")
        return 0

    try:
        extra = _parse_custom_patterns(args.pattern)
    except ValueError as exc:
        parser.error(str(exc))

    redactor = Redactor(mode=args.mode, extra_detectors=extra)

    try:
        sources = list(_iter_input_files(args.inputs, args.recursive))
    except (FileNotFoundError, IsADirectoryError) as exc:
        parser.error(str(exc))

    if args.in_place and any(path is None for _, path in sources):
        parser.error("--in-place cannot be used with stdin input")

    outputs: list[tuple[str, str]] = []
    checked_files = 0
    for label, path in sources:
        text = _read_text(path)
        if args.check:
            if redactor.found_any(text):
                checked_files += 1
        else:
            outputs.append((label, redactor.scrub(text)))

    if args.check:
        if checked_files:
            sys.stderr.write(
                f"logveil-shield: sensitive data found in {checked_files} input(s)\n"
            )
            return 1
        sys.stderr.write("logveil-shield: no sensitive data found\n")
        return 0

    if args.in_place:
        for label, scrubbed in outputs:
            with open(label, "w", encoding="utf-8") as fh:
                fh.write(scrubbed)
    elif args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            for _label, scrubbed in outputs:
                fh.write(scrubbed)
    else:
        out = sys.stdout
        for i, (_label, scrubbed) in enumerate(outputs):
            if i:
                out.write("\n")
            out.write(scrubbed)
            if scrubbed and not scrubbed.endswith("\n"):
                out.write("\n")

    if args.report:
        _print_report(redactor.counts, sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
