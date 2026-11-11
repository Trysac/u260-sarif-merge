"""Command-line interface for sarif-merge."""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import SarifError, compare_baseline, load_sarif, merge

logger = logging.getLogger(__name__)


def _read_sarif_file(path: str) -> dict[str, Any]:
    """Read and parse a SARIF file, propagating errors."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        logger.error("Error reading %s: %s", path, e)
        raise
    return load_sarif(text)


def _write_output(log: dict[str, Any], output_path: str) -> int:
    """Write a SARIF log to a file, returning 0 on success, 2 on failure."""
    try:
        Path(output_path).write_text(
            json.dumps(log, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return 0
    except OSError as e:
        logger.error("Error writing %s: %s", output_path, e)
        return 2


def _parse_merge_args(args: list[str]) -> tuple[list[str], str] | None:
    """Parse arguments for the merge subcommand."""
    output: str | None = None
    files: list[str] = []
    it = iter(args)
    for arg in it:
        if arg == "--output":
            try:
                output = next(it)
            except StopIteration:
                return None
        elif arg.startswith("--output="):
            output = arg.split("=", 1)[1]
        else:
            files.append(arg)
    if output is None or not files:
        return None
    return files, output


def _parse_baseline_args(args: list[str]) -> tuple[str, str, str, bool] | None:
    """Parse arguments for the baseline subcommand."""
    fail_on_new = "--fail-on-new" in args
    args = [a for a in args if a != "--fail-on-new"]
    output: str | None = None
    positional: list[str] = []
    it = iter(args)
    for arg in it:
        if arg == "--output":
            try:
                output = next(it)
            except StopIteration:
                return None
        elif arg.startswith("--output="):
            output = arg.split("=", 1)[1]
        else:
            positional.append(arg)
    if output is None or len(positional) != 2:
        return None
    return positional[0], positional[1], output, fail_on_new


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the CLI.

    Returns 0 on success, 1 when ``--fail-on-new`` is used and new results are found,
    2 on any error (usage, IO, invalid SARIF).
    """
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        print("Usage: sarif-merge merge FILES... --output PATH", file=sys.stderr)
        print(
            "       sarif-merge baseline CURRENT BASELINE --output PATH [--fail-on-new]",
            file=sys.stderr,
        )
        return 2
    subcommand = argv[0]
    args = list(argv[1:])
    try:
        if subcommand == "merge":
            parsed = _parse_merge_args(args)
            if parsed is None:
                print("usage: sarif-merge merge FILES... --output PATH", file=sys.stderr)
                return 2
            files, output = parsed
            logs: list[dict[str, Any]] = []
            for file_path in files:
                logs.append(_read_sarif_file(file_path))
            merged = merge(logs)
            return _write_output(merged, output)
        elif subcommand == "baseline":
            baseline_parsed = _parse_baseline_args(args)
            if baseline_parsed is None:
                print(
                    "usage: sarif-merge baseline CURRENT BASELINE --output PATH [--fail-on-new]",
                    file=sys.stderr,
                )
                return 2
            current_path, baseline_path, output, fail_on_new = baseline_parsed
            current_log = _read_sarif_file(current_path)
            baseline_log = _read_sarif_file(baseline_path)
            compared = compare_baseline(current_log, baseline_log)
            write_rc = _write_output(compared, output)
            if write_rc != 0:
                return write_rc
            if fail_on_new:
                for run in compared["runs"]:
                    for result in run.get("results", []):
                        if result.get("baselineState") == "new":
                            return 1
                return 0
            return 0
        else:
            print(f"unknown subcommand: {subcommand}", file=sys.stderr)
            return 2
    except (OSError, SarifError, json.JSONDecodeError) as e:
        logger.error("error: %s", e)
        return 2
