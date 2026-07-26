"""Turn a :class:`BucketInput` into a :class:`BucketFinding`.

The rules mirror how AWS itself decides whether a bucket is public:

* An **ACL** grant to ``AllUsers``/``AuthenticatedUsers`` is public, unless
  Block Public Access ``IgnorePublicAcls`` is effective (then it is ignored).
* A **bucket policy** ``Allow`` statement with an anonymous ``Principal`` (``*``)
  is public, unless ``RestrictPublicBuckets`` is effective (then anonymous and
  cross-account access is restricted), or unless the statement is gated by a
  ``Condition`` (then it is only *conditionally* public).

The effective Block Public Access value is the OR of the account-level and
bucket-level settings, computed by :meth:`BucketInput.effective_bpa`.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .models import (
    PUBLIC_ACL_GROUPS,
    BlockPublicAccess,
    BucketFinding,
    BucketInput,
    Classification,
    Reason,
    worst,
)


def _principal_is_anonymous(principal: Any) -> bool:
    """True if a policy ``Principal`` grants access to everyone (``*``)."""
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        if aws == "*":
            return True
        if isinstance(aws, list) and "*" in aws:
            return True
    return False


def _evaluate_acl(bucket: BucketInput, bpa: BlockPublicAccess) -> List[Reason]:
    reasons: List[Reason] = []
    for grant in bucket.acl_grants:
        uri = grant.get("grantee_uri") or grant.get("URI")
        if uri in PUBLIC_ACL_GROUPS:
            group = uri.rsplit("/", 1)[-1]
            perm = grant.get("permission") or grant.get("Permission") or "READ"
            if bpa.ignore_public_acls:
                reasons.append(
                    Reason(
                        vector="acl",
                        setting="IgnorePublicAcls",
                        detail=(
                            "ACL grants {perm} to {group}, but is neutralized by "
                            "Block Public Access (IgnorePublicAcls=true)"
                        ).format(perm=perm, group=group),
                    )
                )
            else:
                reasons.append(
                    Reason(
                        vector="acl",
                        setting="Grant:{group}".format(group=group),
                        detail="ACL grants {perm} to {group}".format(
                            perm=perm, group=group
                        ),
                    )
                )
    return reasons


def _public_statements(policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    stmts = policy.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    out = []
    for stmt in stmts:
        if stmt.get("Effect") != "Allow":
            continue
        if _principal_is_anonymous(stmt.get("Principal")):
            out.append(stmt)
    return out


def _evaluate_policy(bucket: BucketInput, bpa: BlockPublicAccess) -> List[Reason]:
    if not bucket.policy:
        return []
    reasons: List[Reason] = []
    for stmt in _public_statements(bucket.policy):
        sid = stmt.get("Sid", "<unnamed>")
        if bpa.restrict_public_buckets:
            reasons.append(
                Reason(
                    vector="policy",
                    setting="RestrictPublicBuckets",
                    detail=(
                        "Policy statement '{sid}' allows anonymous access, but is "
                        "restricted by Block Public Access (RestrictPublicBuckets=true)"
                    ).format(sid=sid),
                )
            )
        elif "Condition" in stmt:
            reasons.append(
                Reason(
                    vector="policy",
                    setting="Policy:Condition",
                    detail=(
                        "Policy statement '{sid}' allows anonymous access gated by a "
                        "Condition (conditionally public)"
                    ).format(sid=sid),
                )
            )
        else:
            reasons.append(
                Reason(
                    vector="policy",
                    setting="Policy:Principal=*",
                    detail=(
                        "Policy statement '{sid}' allows anonymous access "
                        "(Principal '*') with no condition"
                    ).format(sid=sid),
                )
            )
    return reasons


def _classify_reason(reason: Reason) -> Classification:
    """Map a single reason to the exposure it represents."""
    neutralized = reason.setting in ("IgnorePublicAcls", "RestrictPublicBuckets")
    conditional = reason.setting == "Policy:Condition"
    if neutralized or conditional:
        return Classification.CONDITIONAL
    return Classification.PUBLIC


def _remediation(bucket: BucketInput, reasons: List[Reason]) -> List[str]:
    steps: List[str] = []
    vectors = {r.vector for r in reasons if _classify_reason(r) is Classification.PUBLIC}
    if "acl" in vectors:
        steps.append(
            "Remove the AllUsers/AuthenticatedUsers ACL grants "
            "(put-bucket-acl with a private grant set)."
        )
    if "policy" in vectors:
        steps.append(
            "Remove or scope the anonymous (Principal '*') statement in the "
            "bucket policy, or delete the policy."
        )
    if vectors:
        eff = bucket.effective_bpa()
        missing = [k for k, v in eff.to_dict().items() if not v]
        steps.append(
            "Enable Block Public Access on the bucket. Missing toggles: "
            + (", ".join(missing) if missing else "none")
            + ". Recommended: set all four to true via "
            "put-public-access-block: " + str(BlockPublicAccess.all_on().to_dict())
        )
    return steps


def evaluate_bucket(bucket: BucketInput) -> BucketFinding:
    """Audit a single bucket and return its :class:`BucketFinding`."""
    bpa = bucket.effective_bpa()
    reasons = _evaluate_acl(bucket, bpa) + _evaluate_policy(bucket, bpa)
    classification = worst([_classify_reason(r) for r in reasons])
    remediation = _remediation(bucket, reasons)
    return BucketFinding(
        name=bucket.name,
        classification=classification,
        region=bucket.region,
        reasons=reasons,
        remediation=remediation,
    )
