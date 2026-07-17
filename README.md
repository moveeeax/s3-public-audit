# s3-public-audit

> Catch publicly exposed S3 buckets and get a concrete fix plan.

**Status:** 🚧 In development

## Overview

Scan S3 buckets for public exposure (ACLs, policies, Block Public Access) and produce a remediation plan.

## Features

- Evaluate bucket ACLs, bucket policies and account/bucket Block Public Access settings
- Classify each bucket as public / conditionally public / private
- Explain *why* a bucket is public (which setting)
- Emit a remediation plan (settings to flip) without applying it
- Table/JSON output and a non-zero exit on public findings

## Stack

Python 3.11, `boto3`, S3 control/policy APIs, `rich`.

## Usage

```bash
s3-public-audit scan --profile prod --format table
```

## License

MIT
