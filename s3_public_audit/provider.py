"""Sources of bucket data.

Cloud access lives behind the :class:`S3Provider` interface so the core logic
stays testable without the network. :class:`FileS3Provider` reads a JSON
fixture (used by the tests, examples and the ``--input`` flag);
:class:`Boto3S3Provider` talks to real AWS.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from .models import BlockPublicAccess, BucketInput


class S3Provider:
    """Interface: list bucket names and describe one bucket."""

    def list_buckets(self) -> List[str]:  # pragma: no cover - interface
        raise NotImplementedError

    def describe_bucket(self, name: str) -> BucketInput:  # pragma: no cover
        raise NotImplementedError


class FileS3Provider(S3Provider):
    """Read buckets from a JSON document.

    Schema::

        {
          "account_bpa": {"BlockPublicAcls": false, ...} | null,
          "buckets": [
            {
              "name": "my-bucket",
              "region": "us-east-1",
              "acl_grants": [{"grantee_uri": "...AllUsers", "permission": "READ"}],
              "policy": { ... } | null,
              "bucket_bpa": {"BlockPublicAcls": false, ...} | null
            }
          ]
        }
    """

    def __init__(self, data: Dict[str, Any]):
        self._account_bpa = BlockPublicAccess.from_aws(data.get("account_bpa"))
        self._buckets: Dict[str, Dict[str, Any]] = {
            b["name"]: b for b in data.get("buckets", [])
        }

    @classmethod
    def from_path(cls, path: str) -> "FileS3Provider":
        with open(path, "r", encoding="utf-8") as fh:
            return cls(json.load(fh))

    def list_buckets(self) -> List[str]:
        return list(self._buckets.keys())

    def describe_bucket(self, name: str) -> BucketInput:
        raw = self._buckets[name]
        return BucketInput(
            name=name,
            region=raw.get("region"),
            acl_grants=raw.get("acl_grants", []),
            policy=raw.get("policy"),
            bucket_bpa=BlockPublicAccess.from_aws(raw.get("bucket_bpa")),
            account_bpa=self._account_bpa,
        )


class Boto3S3Provider(S3Provider):
    """Query live AWS. Read-only: only ``Get``/``List`` calls are made."""

    def __init__(
        self,
        profile: Optional[str] = None,
        region: Optional[str] = None,
        session: Any = None,
    ):
        if session is None:
            import boto3  # lazy: only needed for live scans

            session = boto3.Session(profile_name=profile, region_name=region)
        self._session = session
        self._s3 = session.client("s3")
        self._account_bpa = self._load_account_bpa()

    # -- helpers ---------------------------------------------------------
    def _load_account_bpa(self) -> Optional[BlockPublicAccess]:
        try:
            sts = self._session.client("sts")
            account_id = sts.get_caller_identity()["Account"]
            ctrl = self._session.client("s3control")
            resp = ctrl.get_public_access_block(AccountId=account_id)
            return BlockPublicAccess.from_aws(
                resp.get("PublicAccessBlockConfiguration")
            )
        except Exception:
            # No account-level BPA / no permission: treat as unset.
            return None

    def _bucket_bpa(self, name: str) -> Optional[BlockPublicAccess]:
        try:
            resp = self._s3.get_public_access_block(Bucket=name)
            return BlockPublicAccess.from_aws(
                resp.get("PublicAccessBlockConfiguration")
            )
        except Exception:
            return None

    def _bucket_policy(self, name: str) -> Optional[Dict[str, Any]]:
        try:
            resp = self._s3.get_bucket_policy(Bucket=name)
            return json.loads(resp["Policy"])
        except Exception:
            return None

    def _bucket_acl(self, name: str) -> List[Dict[str, Any]]:
        try:
            resp = self._s3.get_bucket_acl(Bucket=name)
        except Exception:
            return []
        grants = []
        for g in resp.get("Grants", []):
            grantee = g.get("Grantee", {})
            grants.append(
                {
                    "grantee_uri": grantee.get("URI"),
                    "permission": g.get("Permission"),
                }
            )
        return grants

    def _bucket_region(self, name: str) -> Optional[str]:
        try:
            resp = self._s3.get_bucket_location(Bucket=name)
            return resp.get("LocationConstraint") or "us-east-1"
        except Exception:
            return None

    # -- interface -------------------------------------------------------
    def list_buckets(self) -> List[str]:
        resp = self._s3.list_buckets()
        return [b["Name"] for b in resp.get("Buckets", [])]

    def describe_bucket(self, name: str) -> BucketInput:
        return BucketInput(
            name=name,
            region=self._bucket_region(name),
            acl_grants=self._bucket_acl(name),
            policy=self._bucket_policy(name),
            bucket_bpa=self._bucket_bpa(name),
            account_bpa=self._account_bpa,
        )
