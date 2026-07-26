"""Core data model for the S3 public-exposure audit.

Everything here is pure data + light logic. It has no dependency on ``boto3``
or the network, so it can be unit-tested in isolation.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Canonical S3 predefined groups that make an ACL grant "public".
ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
PUBLIC_ACL_GROUPS = frozenset({ALL_USERS_URI, AUTHENTICATED_USERS_URI})


class Classification(str, enum.Enum):
    """How exposed a bucket is, worst-case first."""

    PUBLIC = "public"
    CONDITIONAL = "conditionally-public"
    PRIVATE = "private"

    @property
    def is_exposed(self) -> bool:
        return self is not Classification.PRIVATE


# Ordering so we can pick the worst classification across ACL/policy vectors.
_SEVERITY = {
    Classification.PRIVATE: 0,
    Classification.CONDITIONAL: 1,
    Classification.PUBLIC: 2,
}


def worst(classifications: List[Classification]) -> Classification:
    """Return the most exposed classification in ``classifications``."""
    if not classifications:
        return Classification.PRIVATE
    return max(classifications, key=lambda c: _SEVERITY[c])


@dataclass(frozen=True)
class BlockPublicAccess:
    """The four S3 Block Public Access toggles.

    ``True`` means the protection is on. AWS applies these at both the account
    and bucket level; the *effective* value is the logical OR of the two, which
    :meth:`merged` computes.
    """

    block_public_acls: bool = False
    ignore_public_acls: bool = False
    block_public_policy: bool = False
    restrict_public_buckets: bool = False

    @classmethod
    def all_on(cls) -> "BlockPublicAccess":
        return cls(True, True, True, True)

    @classmethod
    def from_aws(cls, cfg: Optional[Dict[str, Any]]) -> Optional["BlockPublicAccess"]:
        """Build from a ``PublicAccessBlockConfiguration`` dict (or ``None``)."""
        if cfg is None:
            return None
        return cls(
            block_public_acls=bool(cfg.get("BlockPublicAcls", False)),
            ignore_public_acls=bool(cfg.get("IgnorePublicAcls", False)),
            block_public_policy=bool(cfg.get("BlockPublicPolicy", False)),
            restrict_public_buckets=bool(cfg.get("RestrictPublicBuckets", False)),
        )

    def merged(self, other: Optional["BlockPublicAccess"]) -> "BlockPublicAccess":
        """Combine two BPA configs; a protection is effective if either has it."""
        if other is None:
            return self
        return BlockPublicAccess(
            block_public_acls=self.block_public_acls or other.block_public_acls,
            ignore_public_acls=self.ignore_public_acls or other.ignore_public_acls,
            block_public_policy=self.block_public_policy or other.block_public_policy,
            restrict_public_buckets=self.restrict_public_buckets
            or other.restrict_public_buckets,
        )

    def to_dict(self) -> Dict[str, bool]:
        return {
            "BlockPublicAcls": self.block_public_acls,
            "IgnorePublicAcls": self.ignore_public_acls,
            "BlockPublicPolicy": self.block_public_policy,
            "RestrictPublicBuckets": self.restrict_public_buckets,
        }


@dataclass
class BucketInput:
    """Everything the evaluator needs about one bucket.

    Populated either from live AWS calls (:class:`~s3_public_audit.provider.
    Boto3S3Provider`) or from a JSON fixture (:class:`~s3_public_audit.provider.
    FileS3Provider`).
    """

    name: str
    region: Optional[str] = None
    acl_grants: List[Dict[str, Any]] = field(default_factory=list)
    policy: Optional[Dict[str, Any]] = None
    bucket_bpa: Optional[BlockPublicAccess] = None
    account_bpa: Optional[BlockPublicAccess] = None

    def effective_bpa(self) -> BlockPublicAccess:
        base = self.account_bpa or BlockPublicAccess()
        return base.merged(self.bucket_bpa)


@dataclass
class Reason:
    """A single explanation of exposure tied to the responsible setting."""

    vector: str  # "acl" | "policy"
    setting: str  # the AWS setting/field responsible
    detail: str

    def to_dict(self) -> Dict[str, str]:
        return {"vector": self.vector, "setting": self.setting, "detail": self.detail}


@dataclass
class BucketFinding:
    """The result of auditing one bucket."""

    name: str
    classification: Classification
    region: Optional[str] = None
    reasons: List[Reason] = field(default_factory=list)
    remediation: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bucket": self.name,
            "region": self.region,
            "classification": self.classification.value,
            "reasons": [r.to_dict() for r in self.reasons],
            "remediation": self.remediation,
        }
