import json
import os

import pytest

from s3_public_audit.cli import main, scan, _exit_code
from s3_public_audit.models import BucketFinding, Classification
from s3_public_audit.provider import FileS3Provider
from s3_public_audit.report import render

EXAMPLE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "examples", "buckets.json"
)


def _findings():
    provider = FileS3Provider.from_path(EXAMPLE)
    return scan(provider)


def test_example_fixture_classifications():
    findings = {f.name: f.classification for f in _findings()}
    assert findings["public-website-assets"] is Classification.PUBLIC
    assert findings["open-policy-datalake"] is Classification.PUBLIC
    assert findings["cdn-origin-ip-locked"] is Classification.CONDITIONAL
    assert findings["legacy-acl-but-bpa-on"] is Classification.CONDITIONAL
    assert findings["private-app-state"] is Classification.PRIVATE


def test_scan_sorts_worst_first():
    findings = _findings()
    assert findings[0].classification is Classification.PUBLIC
    assert findings[-1].classification is Classification.PRIVATE


def test_exit_code_public():
    findings = _findings()
    assert _exit_code(findings, "public") == 2
    assert _exit_code(findings, "never") == 0


def test_exit_code_conditional_only():
    f = [BucketFinding(name="x", classification=Classification.CONDITIONAL)]
    assert _exit_code(f, "public") == 0
    assert _exit_code(f, "conditional") == 2


def test_render_json_roundtrip():
    out = render(_findings(), "json")
    doc = json.loads(out)
    assert doc["summary"]["public"] == 2
    assert doc["summary"]["total"] == 5
    assert any(x["bucket"] == "public-website-assets" for x in doc["findings"])


def test_render_sarif_structure():
    out = render(_findings(), "sarif")
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    results = doc["runs"][0]["results"]
    # 2 public + 2 conditional == 4 exposed; private is omitted.
    assert len(results) == 4
    levels = {r["level"] for r in results}
    assert "error" in levels and "warning" in levels


def test_render_table_contains_buckets():
    out = render(_findings(), "table")
    assert "public-website-assets" in out
    assert "PUBLIC" in out


def test_render_unknown_format_raises():
    with pytest.raises(ValueError):
        render(_findings(), "xml")


def test_main_scan_json_exit_code(capsys):
    code = main(["scan", "--input", EXAMPLE, "--format", "json"])
    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    assert doc["summary"]["total"] == 5
    assert code == 2  # public buckets present


def test_main_scan_bucket_filter(capsys):
    code = main(
        ["scan", "--input", EXAMPLE, "--format", "json", "--bucket", "private-app-state"]
    )
    captured = capsys.readouterr()
    doc = json.loads(captured.out)
    assert doc["summary"]["total"] == 1
    assert code == 0  # only a private bucket selected


def test_main_missing_input_errors(capsys):
    code = main(["scan", "--input", "/nonexistent/path.json"])
    assert code == 1


def test_main_no_command_prints_help():
    assert main([]) == 1
