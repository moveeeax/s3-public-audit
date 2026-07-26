"""Render findings as a table, JSON, or SARIF."""

from __future__ import annotations

import json
from typing import Any, Dict, List

from .models import BucketFinding, Classification

_SYMBOL = {
    Classification.PUBLIC: "PUBLIC",
    Classification.CONDITIONAL: "COND",
    Classification.PRIVATE: "ok",
}
_COLOR = {
    Classification.PUBLIC: "bold red",
    Classification.CONDITIONAL: "yellow",
    Classification.PRIVATE: "green",
}


def render_json(findings: List[BucketFinding]) -> str:
    payload = {
        "summary": _summary(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def _summary(findings: List[BucketFinding]) -> Dict[str, int]:
    summary = {c.value: 0 for c in Classification}
    for f in findings:
        summary[f.classification.value] += 1
    summary["total"] = len(findings)
    return summary


def render_table(findings: List[BucketFinding]) -> str:
    """Rich table if available, otherwise a plain-text fallback."""
    try:
        import io

        from rich.console import Console
        from rich.table import Table
    except Exception:  # pragma: no cover - rich is a declared dependency
        return _render_table_plain(findings)

    table = Table(title="S3 public-exposure audit")
    table.add_column("Bucket", overflow="fold")
    table.add_column("Region")
    table.add_column("Status")
    table.add_column("Why / responsible setting", overflow="fold")

    for f in findings:
        why = "; ".join(r.detail for r in f.reasons) or "no public grants"
        table.add_row(
            f.name,
            f.region or "-",
            "[{color}]{sym}[/{color}]".format(
                color=_COLOR[f.classification], sym=_SYMBOL[f.classification]
            ),
            why,
        )

    # Record into a throwaway buffer so nothing is written to stdout here;
    # the caller decides where the rendered text goes.
    console = Console(record=True, width=120, file=io.StringIO())
    console.print(table)
    return console.export_text().rstrip("\n")


def _render_table_plain(findings: List[BucketFinding]) -> str:
    lines = ["BUCKET\tREGION\tSTATUS\tWHY"]
    for f in findings:
        why = "; ".join(r.detail for r in f.reasons) or "no public grants"
        lines.append(
            "{name}\t{region}\t{status}\t{why}".format(
                name=f.name,
                region=f.region or "-",
                status=_SYMBOL[f.classification],
                why=why,
            )
        )
    return "\n".join(lines)


def render_sarif(findings: List[BucketFinding]) -> str:
    """SARIF 2.1.0 so findings can feed GitHub code scanning."""
    results = []
    for f in findings:
        if not f.classification.is_exposed:
            continue
        level = "error" if f.classification is Classification.PUBLIC else "warning"
        why = "; ".join(r.detail for r in f.reasons)
        fix = " ".join(f.remediation)
        results.append(
            {
                "ruleId": "s3-public-{}".format(f.classification.value),
                "level": level,
                "message": {
                    "text": "Bucket '{name}' is {cls}: {why}. Fix: {fix}".format(
                        name=f.name,
                        cls=f.classification.value,
                        why=why,
                        fix=fix,
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "s3://{name}".format(name=f.name)
                            }
                        }
                    }
                ],
            }
        )
    sarif: Dict[str, Any] = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "s3-public-audit",
                        "informationUri": "https://github.com/moveeeax/s3-public-audit",
                        "rules": [],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render(findings: List[BucketFinding], fmt: str) -> str:
    if fmt == "json":
        return render_json(findings)
    if fmt == "sarif":
        return render_sarif(findings)
    if fmt == "table":
        return render_table(findings)
    raise ValueError("unknown format: {}".format(fmt))
