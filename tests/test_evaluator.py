from s3_public_audit.evaluator import evaluate_bucket
from s3_public_audit.models import (
    ALL_USERS_URI,
    AUTHENTICATED_USERS_URI,
    BlockPublicAccess,
    BucketInput,
    Classification,
)


def _bpa_off():
    return BlockPublicAccess(False, False, False, False)


def test_public_acl_grant_is_public():
    b = BucketInput(
        name="web",
        acl_grants=[{"grantee_uri": ALL_USERS_URI, "permission": "READ"}],
        account_bpa=_bpa_off(),
    )
    f = evaluate_bucket(b)
    assert f.classification is Classification.PUBLIC
    assert any(r.vector == "acl" for r in f.reasons)
    assert f.remediation  # a plan is produced


def test_authenticated_users_grant_is_public():
    b = BucketInput(
        name="auth",
        acl_grants=[{"grantee_uri": AUTHENTICATED_USERS_URI, "permission": "READ"}],
        account_bpa=_bpa_off(),
    )
    assert evaluate_bucket(b).classification is Classification.PUBLIC


def test_public_acl_neutralized_by_ignore_public_acls_is_conditional():
    b = BucketInput(
        name="web",
        acl_grants=[{"grantee_uri": ALL_USERS_URI, "permission": "READ"}],
        bucket_bpa=BlockPublicAccess(True, True, True, True),
        account_bpa=_bpa_off(),
    )
    f = evaluate_bucket(b)
    assert f.classification is Classification.CONDITIONAL
    assert any(r.setting == "IgnorePublicAcls" for r in f.reasons)


def test_public_policy_is_public():
    policy = {
        "Statement": [
            {"Sid": "S", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
        ]
    }
    b = BucketInput(name="lake", policy=policy, account_bpa=_bpa_off())
    f = evaluate_bucket(b)
    assert f.classification is Classification.PUBLIC
    assert any(r.setting == "Policy:Principal=*" for r in f.reasons)


def test_policy_principal_aws_star_dict_is_public():
    policy = {
        "Statement": {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "s3:GetObject",
        }
    }
    b = BucketInput(name="lake", policy=policy, account_bpa=_bpa_off())
    assert evaluate_bucket(b).classification is Classification.PUBLIC


def test_policy_with_condition_is_conditional():
    policy = {
        "Statement": [
            {
                "Sid": "Ip",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}},
            }
        ]
    }
    b = BucketInput(name="cdn", policy=policy, account_bpa=_bpa_off())
    f = evaluate_bucket(b)
    assert f.classification is Classification.CONDITIONAL
    assert any(r.setting == "Policy:Condition" for r in f.reasons)


def test_public_policy_restricted_by_bpa_is_conditional():
    policy = {
        "Statement": [
            {"Sid": "S", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
        ]
    }
    b = BucketInput(
        name="lake",
        policy=policy,
        bucket_bpa=BlockPublicAccess(True, True, True, True),
        account_bpa=_bpa_off(),
    )
    f = evaluate_bucket(b)
    assert f.classification is Classification.CONDITIONAL
    assert any(r.setting == "RestrictPublicBuckets" for r in f.reasons)


def test_account_bpa_overrides_bucket():
    # Bucket has no BPA of its own, but the account restricts everything.
    policy = {
        "Statement": [
            {"Sid": "S", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}
        ]
    }
    b = BucketInput(
        name="lake",
        policy=policy,
        account_bpa=BlockPublicAccess(True, True, True, True),
    )
    assert evaluate_bucket(b).classification is Classification.CONDITIONAL


def test_private_bucket():
    b = BucketInput(name="secret", account_bpa=BlockPublicAccess(True, True, True, True))
    f = evaluate_bucket(b)
    assert f.classification is Classification.PRIVATE
    assert not f.reasons
    assert not f.remediation


def test_non_public_principal_ignored():
    policy = {
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                "Action": "s3:GetObject",
            }
        ]
    }
    b = BucketInput(name="shared", policy=policy, account_bpa=_bpa_off())
    assert evaluate_bucket(b).classification is Classification.PRIVATE


def test_deny_statement_not_public():
    policy = {
        "Statement": [
            {"Effect": "Deny", "Principal": "*", "Action": "s3:GetObject"}
        ]
    }
    b = BucketInput(name="deny", policy=policy, account_bpa=_bpa_off())
    assert evaluate_bucket(b).classification is Classification.PRIVATE
