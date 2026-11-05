# s3-public-audit

[![ci](https://github.com/moveeeax/s3-public-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/s3-public-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Catch publicly exposed S3 buckets and get a concrete fix plan.

`s3-public-audit` scans your S3 buckets, evaluates **ACLs**, **bucket policies**
and **Block Public Access (BPA)** together — the way AWS actually resolves
public access — classifies every bucket as **public / conditionally-public /
private**, explains *which setting* is responsible, and prints a remediation
plan. It is strictly **read-only**: it only makes `Get`/`List` calls and never
mutates anything. A non-zero exit on public findings makes it drop-in for CI.

## How it works

For each bucket the tool gathers four things and combines them the way S3 does:

- **ACL grants** to `AllUsers` / `AuthenticatedUsers` are public — unless the
  effective `IgnorePublicAcls` BPA toggle neutralizes them.
- **Bucket policy** `Allow` statements with an anonymous `Principal` (`*`) are
  public — unless `RestrictPublicBuckets` restricts them, or the statement is
  gated by a `Condition` (then it is only *conditionally* public).
- **Block Public Access** is evaluated as the logical OR of the account-level
  and bucket-level settings (the *effective* value).

The worst vector wins the bucket's classification. Cloud access sits behind a
small `S3Provider` interface, so the whole classification engine is unit-tested
offline against JSON fixtures — no AWS account required.

## Install

```bash
pip install -e .
```

## Usage

Scan a live account with a named profile:

```bash
s3-public-audit scan --profile prod --format table
```

Scan offline against a fixture (great for demos, tests and CI):

```bash
$ s3-public-audit scan --input examples/buckets.json --format table
                          S3 public-exposure audit
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Bucket                ┃ Region    ┃ Status ┃ Why / responsible setting         ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ open-policy-datalake  │ eu-west-1 │ PUBLIC │ Policy 'PublicRead' Principal '*'  │
│ public-website-assets │ us-east-1 │ PUBLIC │ ACL grants READ to AllUsers       │
│ cdn-origin-ip-locked  │ us-east-1 │ COND   │ Policy gated by a Condition       │
│ legacy-acl-but-bpa-on │ us-west-2 │ COND   │ ACL neutralized by BPA            │
│ private-app-state     │ us-east-1 │ ok     │ no public grants                  │
└───────────────────────┴───────────┴────────┴───────────────────────────────────┘
```

JSON (for pipelines) and SARIF (for GitHub code scanning) are also supported:

```bash
s3-public-audit scan --profile prod --format json  --output report.json
s3-public-audit scan --profile prod --format sarif --output s3.sarif
```

### Flags

| Flag | Description |
| --- | --- |
| `--profile` | AWS profile name (live scan) |
| `--region` | AWS region |
| `--input FILE` | Scan a JSON fixture instead of AWS (offline) |
| `--bucket NAME` | Limit to a bucket (repeatable) |
| `--format` | `table` (default), `json`, or `sarif` |
| `--output FILE` | Write the report to a file |
| `--fail-on` | `public` (default), `conditional`, or `never` |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at or above the `--fail-on` level |
| `2` | Findings at or above the `--fail-on` level |
| `1` | Error (bad input, AWS failure) |

## Remediation plan

Every exposed bucket comes with the exact settings to flip — remove the
anonymous ACL grants or policy statement, and turn on all four Block Public
Access toggles via `put-public-access-block`. The tool never applies changes; it
tells you precisely what to change.

## Development

```bash
make install
make test
make smoke
```

## License

MIT — see [LICENSE](LICENSE).
