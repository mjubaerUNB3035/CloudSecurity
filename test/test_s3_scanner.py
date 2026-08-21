import json

from scanner.s3_scanner import (
    analyze_bucket_policy,
    check_encryption,
    check_versioning,
    check_logging,
    check_lifecycle,
    check_object_lock,
    check_https_only,
    check_mfa_delete,
    get_s3_controls,
)


# =========================================================
# S3.2 / S3.3 - Bucket Policy Tests
# =========================================================

def test_public_read_policy():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::test-bucket/*",
            }
        ],
    }

    public_read, public_write = analyze_bucket_policy(
        json.dumps(policy)
    )

    assert public_read is True
    assert public_write is False


def test_public_write_policy():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::test-bucket/*",
            }
        ],
    }

    public_read, public_write = analyze_bucket_policy(
        json.dumps(policy)
    )

    assert public_read is False
    assert public_write is True


def test_public_read_and_write_policy():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                ],
                "Resource": "arn:aws:s3:::test-bucket/*",
            }
        ],
    }

    public_read, public_write = analyze_bucket_policy(
        json.dumps(policy)
    )

    assert public_read is True
    assert public_write is True


def test_private_policy():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789012:root"
                },
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::test-bucket/*",
            }
        ],
    }

    public_read, public_write = analyze_bucket_policy(
        json.dumps(policy)
    )

    assert public_read is False
    assert public_write is False


# =========================================================
# Fake S3 Client
# =========================================================

class FakeS3:

    def __init__(
        self,
        encryption_response=None,
        versioning_response=None,
        logging_response=None,
        lifecycle_response=None,
        object_lock_response=None,
        policy_response=None,
        versioning_error=None,
        logging_error=None,
        lifecycle_error=None,
        object_lock_error=None,
        policy_error=None,
    ):
        self.encryption_response = encryption_response
        self.versioning_response = versioning_response
        self.logging_response = logging_response
        self.lifecycle_response = lifecycle_response
        self.object_lock_response = object_lock_response
        self.policy_response = policy_response

        self.versioning_error = versioning_error
        self.logging_error = logging_error
        self.lifecycle_error = lifecycle_error
        self.object_lock_error = object_lock_error
        self.policy_error = policy_error

    def get_bucket_encryption(self, Bucket):
        return self.encryption_response

    def get_bucket_versioning(self, Bucket):
        if self.versioning_error:
            raise self.versioning_error

        return self.versioning_response

    def get_bucket_logging(self, Bucket):
        if self.logging_error:
            raise self.logging_error

        return self.logging_response

    def get_bucket_lifecycle_configuration(self, Bucket):
        if self.lifecycle_error:
            raise self.lifecycle_error

        return self.lifecycle_response

    def get_object_lock_configuration(self, Bucket):
        if self.object_lock_error:
            raise self.object_lock_error

        return self.object_lock_response

    def get_bucket_policy(self, Bucket):
        if self.policy_error:
            raise self.policy_error

        return self.policy_response


# =========================================================
# S3.4 - Encryption Tests
# =========================================================

def test_encryption_sse_s3():
    s3 = FakeS3(
        encryption_response={
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }
        }
    )

    result = check_encryption(
        s3,
        "test-bucket"
    )

    assert result["status"] == "PASSED"
    assert result["control_id"] == "S3.4"
    assert "SSE-S3" in result["evidence"][1]


def test_encryption_sse_kms():
    s3 = FakeS3(
        encryption_response={
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "test-key-id",
                        }
                    }
                ]
            }
        }
    )

    result = check_encryption(
        s3,
        "test-bucket"
    )

    assert result["status"] == "PASSED"
    assert "SSE-KMS" in result["evidence"][1]
    assert "KMS key: test-key-id" in result["evidence"]


def test_encryption_no_rules():
    s3 = FakeS3(
        encryption_response={
            "ServerSideEncryptionConfiguration": {
                "Rules": []
            }
        }
    )

    result = check_encryption(
        s3,
        "test-bucket"
    )

    assert result["status"] == "FAILED"
    assert result["control_id"] == "S3.4"


def test_encryption_missing_algorithm():
    s3 = FakeS3(
        encryption_response={
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {}
                    }
                ]
            }
        }
    )

    result = check_encryption(
        s3,
        "test-bucket"
    )

    assert result["status"] == "FAILED"
    assert result["control_id"] == "S3.4"


# =========================================================
# S3.5 - Versioning Tests
# =========================================================

def test_versioning_enabled():
    s3 = FakeS3(
        versioning_response={
            "Status": "Enabled"
        }
    )

    result = check_versioning(
        s3,
        "test-bucket"
    )

    assert result["status"] == "PASSED"
    assert result["control_id"] == "S3.5"


def test_versioning_suspended():
    s3 = FakeS3(
        versioning_response={
            "Status": "Suspended"
        }
    )

    result = check_versioning(
        s3,
        "test-bucket"
    )

    assert result["status"] == "FAILED"
    assert result["control_id"] == "S3.5"


def test_versioning_not_configured():
    s3 = FakeS3(
        versioning_response={}
    )

    result = check_versioning(
        s3,
        "test-bucket"
    )

    assert result["status"] == "FAILED"
    assert "Not configured" in result["evidence"][1]


# =========================================================
# S3.6 - Logging Tests
# =========================================================

def test_logging_enabled():
    s3 = FakeS3(
        logging_response={
            "LoggingEnabled": {
                "TargetBucket": "security-logs",
                "TargetPrefix": "s3/"
            }
        }
    )

    result = check_logging(
        s3,
        "test-bucket"
    )

    assert result["status"] == "PASSED"
    assert result["control_id"] == "S3.6"


def test_logging_disabled():
    s3 = FakeS3(
        logging_response={}
    )

    result = check_logging(
        s3,
        "test-bucket"
    )

    assert result["status"] == "FAILED"
    assert result["control_id"] == "S3.6"


# =========================================================
# S3.7 - Lifecycle Tests
# =========================================================

def test_lifecycle_with_rules():
    s3 = FakeS3(
        lifecycle_response={
            "Rules": [
                {
                    "ID": "DeleteOldObjects",
                    "Status": "Enabled"
                }
            ]
        }
    )

    result = check_lifecycle(
        s3,
        "test-bucket"
    )

    assert result["status"] == "PASSED"
    assert result["control_id"] == "S3.7"


def test_lifecycle_without_rules():
    s3 = FakeS3(
        lifecycle_response={
            "Rules": []
        }
    )

    result = check_lifecycle(
        s3,
        "test-bucket"
    )

    assert result["status"] == "PASSED"
    assert result["control_id"] == "S3.7"


# =========================================================
# S3.8 - Object Lock Tests
# =========================================================

def test_object_lock_enabled():
    s3 = FakeS3(
        object_lock_response={
            "ObjectLockConfiguration": {
                "ObjectLockEnabled": "Enabled"
            }
        }
    )

    result = check_object_lock(
        s3,
        "test-bucket"
    )

    assert result["status"] == "PASSED"
    assert result["control_id"] == "S3.8"


def test_object_lock_not_configured():
    s3 = FakeS3(
        object_lock_response={}
    )

    result = check_object_lock(
        s3,
        "test-bucket"
    )

    assert result["status"] == "PASSED"
    assert result["control_id"] == "S3.8"


# =========================================================
# S3.9 - HTTPS-only Policy Tests
# =========================================================

def test_https_only_policy():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    "arn:aws:s3:::test-bucket",
                    "arn:aws:s3:::test-bucket/*",
                ],
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "false"
                    }
                },
            }
        ],
    }

    s3 = FakeS3(
        policy_response={
            "Policy": json.dumps(policy)
        }
    )

    result = check_https_only(
        s3,
        "test-bucket"
    )

    assert result["status"] == "PASSED"
    assert result["control_id"] == "S3.9"


def test_https_only_policy_missing():
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::test-bucket/*",
            }
        ],
    }

    s3 = FakeS3(
        policy_response={
            "Policy": json.dumps(policy)
        }
    )

    result = check_https_only(
        s3,
        "test-bucket"
    )

    assert result["status"] == "FAILED"
    assert result["control_id"] == "S3.9"


# =========================================================
# S3.10 - MFA Delete Tests
# =========================================================

def test_mfa_delete_enabled():
    s3 = FakeS3(
        versioning_response={
            "Status": "Enabled",
            "MFADelete": "Enabled"
        }
    )

    result = check_mfa_delete(
        s3,
        "test-bucket"
    )

    assert result["status"] == "PASSED"
    assert result["control_id"] == "S3.10"


def test_mfa_delete_disabled():
    s3 = FakeS3(
        versioning_response={
            "Status": "Enabled",
            "MFADelete": "Disabled"
        }
    )

    result = check_mfa_delete(
        s3,
        "test-bucket"
    )

    assert result["status"] == "FAILED"
    assert result["control_id"] == "S3.10"


# =========================================================
# Control Registry Test
# =========================================================

def test_s3_control_registry():
    controls = get_s3_controls()

    assert len(controls) == 10

    control_names = [
        control.__name__
        for control in controls
    ]

    assert "check_block_public_access" in control_names
    assert "check_public_read" in control_names
    assert "check_public_write" in control_names
    assert "check_encryption" in control_names
    assert "check_versioning" in control_names
    assert "check_logging" in control_names
    assert "check_lifecycle" in control_names
    assert "check_object_lock" in control_names
    assert "check_https_only" in control_names
    assert "check_mfa_delete" in control_names