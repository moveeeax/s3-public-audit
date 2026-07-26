"""Command-line entry point for s3-public-audit."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from . import __version__
from .evaluator import evaluate_bucket
from .models import BucketFinding, Classification
from .provider import Boto3S3Provider, FileS3Provider, S3Provider
from .report import render

# Exit codes
EXIT_CLEAN = 0
EXIT_FINDINGS = 2
EXIT_ERROR = 1


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="s3-public-audit",
        description="Scan S3 buckets for public exposure and plan remediation.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="scan buckets for public exposure")
    scan.add_argument("--profile", help="AWS profile name")
    scan.add_argument("--region", help="AWS region")
    scan.add_argument(
        "--input",
        help="read buckets from a JSON fixture instead of AWS (offline)",
    )
    scan.add_argument(
        "--bucket",
        action="append",
        default=None,
        help="limit to this bucket (repeatable)",
    )
    scan.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="output format (default: table)",
    )
    scan.add_argument("--output", help="write the report to this file")
    scan.add_argument(
        "--fail-on",
        choices=["public", "conditional", "never"],
        default="public",
        help="exposure level that triggers a non-zero exit (default: public)",
    )
    return parser


def _make_provider(args: argparse.Namespace) -> S3Provider:
    if args.input:
        return FileS3Provider.from_path(args.input)
    return Boto3S3Provider(profile=args.profile, region=args.region)


def scan(provider: S3Provider, only: Optional[List[str]] = None) -> List[BucketFinding]:
    names = provider.list_buckets()
    if only:
        wanted = set(only)
        names = [n for n in names if n in wanted]
    findings = [evaluate_bucket(provider.describe_bucket(n)) for n in names]
    # Worst first, then by name, for a stable, readable report.
    order = {
        Classification.PUBLIC: 0,
        Classification.CONDITIONAL: 1,
        Classification.PRIVATE: 2,
    }
    findings.sort(key=lambda f: (order[f.classification], f.name))
    return findings


def _exit_code(findings: List[BucketFinding], fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_CLEAN
    has_public = any(f.classification is Classification.PUBLIC for f in findings)
    has_conditional = any(
        f.classification is Classification.CONDITIONAL for f in findings
    )
    if fail_on == "public" and has_public:
        return EXIT_FINDINGS
    if fail_on == "conditional" and (has_public or has_conditional):
        return EXIT_FINDINGS
    return EXIT_CLEAN


def run(args: argparse.Namespace) -> int:
    provider = _make_provider(args)
    findings = scan(provider, only=args.bucket)
    output = render(findings, args.format)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
    else:
        print(output)
    return _exit_code(findings, args.fail_on)


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.print_help()
        return EXIT_ERROR
    try:
        return run(args)
    except FileNotFoundError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # pragma: no cover - top-level guard
        print("error: {}".format(exc), file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
