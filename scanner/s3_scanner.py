import boto3
import json
from botocore.exceptions import ClientError


def check_block_public_access(s3, bucket_name):
    control_id = "S3.1"
    title = "S3 buckets should have block public access enabled"

    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]

        passed = (
            config.get("BlockPublicAcls", False)
            and config.get("IgnorePublicAcls", False)
            and config.get("BlockPublicPolicy", False)
            and config.get("RestrictPublicBuckets", False)
        )

        evidence = [
            f"BlockPublicAcls={config.get('BlockPublicAcls', False)}",
            f"IgnorePublicAcls={config.get('IgnorePublicAcls', False)}",
            f"BlockPublicPolicy={config.get('BlockPublicPolicy', False)}",
            f"RestrictPublicBuckets={config.get('RestrictPublicBuckets', False)}",
        ]

        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "PASSED" if passed else "FAILED",
            "severity": "MEDIUM",
            "evidence": evidence,
        }

    except ClientError as e:
        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "ERROR",
            "severity": "MEDIUM",
            "evidence": [str(e)],
        }


def get_bucket_policy(s3, bucket_name):
    try:
        response = s3.get_bucket_policy(Bucket=bucket_name)
        return response["Policy"]

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code in [
            "NoSuchBucketPolicy",
            "NoSuchBucketPolicyException",
        ]:
            return None

        raise


def analyze_bucket_policy(policy):
    import json

    policy_data = json.loads(policy)

    public_read = False
    public_write = False

    read_actions = {
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectAcl",
    }

    write_actions = {
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
    }

    statements = policy_data.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        effect = statement.get("Effect")
        principal = statement.get("Principal")
        actions = statement.get("Action", [])

        if isinstance(actions, str):
            actions = [actions]

        is_public = principal == "*"

        if not is_public:
            continue

        if effect != "Allow":
            continue

        for action in actions:
            if action in read_actions or action == "s3:*":
                public_read = True

            if action in write_actions or action == "s3:*":
                public_write = True

    return public_read, public_write


def check_public_read(s3, bucket_name):
    control_id = "S3.2"
    title = "S3 buckets should not allow public read access"

    try:
        policy = get_bucket_policy(s3, bucket_name)

        if policy is None:
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "PASSED",
                "severity": "HIGH",
                "evidence": [
                    "No bucket policy exists.",
                    "No public read access through a bucket policy.",
                ],
            }

        public_read, public_write = analyze_bucket_policy(policy)

        if public_read:
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "FAILED",
                "severity": "HIGH",
                "evidence": [
                    "Bucket policy allows public read access.",
                    "Principal: *",
                    "A public read action was detected.",
                ],
            }

        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "PASSED",
            "severity": "HIGH",
            "evidence": [
                "Bucket policy exists.",
                "No public read access detected.",
            ],
        }

    except ClientError as e:
        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "ERROR",
            "severity": "HIGH",
            "evidence": [str(e)],
        }


def check_public_write(s3, bucket_name):
    control_id = "S3.3"
    title = "S3 buckets should not allow public write access"

    try:
        policy = get_bucket_policy(s3, bucket_name)

        if policy is None:
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "PASSED",
                "severity": "CRITICAL",
                "evidence": [
                    "No bucket policy exists.",
                    "No public write access through a bucket policy.",
                ],
            }

        public_read, public_write = analyze_bucket_policy(policy)

        if public_write:
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "FAILED",
                "severity": "CRITICAL",
                "evidence": [
                    "Bucket policy allows public write access.",
                    "Principal: *",
                    "A public write action was detected.",
                ],
            }

        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "PASSED",
            "severity": "CRITICAL",
            "evidence": [
                "Bucket policy exists.",
                "No public write access detected.",
            ],
        }

    except ClientError as e:
        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "ERROR",
            "severity": "CRITICAL",
            "evidence": [str(e)],
        }


def check_encryption(s3, bucket_name):
    control_id = "S3.4"
    title = "S3 buckets should have server-side encryption enabled"

    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)

        rules = response["ServerSideEncryptionConfiguration"]["Rules"]

        if not rules:
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "FAILED",
                "severity": "HIGH",
                "evidence": [
                    "Server-side encryption configuration exists but contains no rules.",
                ],
            }

        encryption = rules[0]["ApplyServerSideEncryptionByDefault"]

        encryption_type = encryption.get("SSEAlgorithm")

        if not encryption_type:
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "FAILED",
                "severity": "HIGH",
                "evidence": [
                    "Encryption configuration exists but no encryption algorithm was found.",
                ],
            }

        encryption_name = {
            "AES256": "SSE-S3",
            "aws:kms": "SSE-KMS",
            "aws:kms:dsse": "DSSE-KMS",
        }.get(encryption_type, encryption_type)

        evidence = [
            "Default server-side encryption is configured.",
            f"Encryption method: {encryption_name}",
            f"Encryption algorithm: {encryption_type}",
        ]

        if encryption_type in ["aws:kms", "aws:kms:dsse"]:
            kms_key = encryption.get("KMSMasterKeyID")

            if kms_key:
                evidence.append(f"KMS key: {kms_key}")
            else:
                evidence.append("No specific KMS key was returned.")

        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "PASSED",
            "severity": "HIGH",
            "evidence": evidence,
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "PASSED",
                "severity": "HIGH",
                "evidence": [
                    "No explicit default encryption configuration was returned.",
                    "S3 applies server-side encryption by default.",
                ],
            }

        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "ERROR",
            "severity": "HIGH",
            "evidence": [str(e)],
        }

def check_versioning(s3, bucket_name):
    control_id = "S3.5"
    title = "S3 buckets should have versioning enabled"

    try:
        response = s3.get_bucket_versioning(
            Bucket=bucket_name
        )

        status = response.get("Status")

        if status == "Enabled":
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "PASSED",
                "severity": "MEDIUM",
                "evidence": [
                    "Bucket versioning is enabled.",
                    "Versioning status: Enabled",
                ],
            }

        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "FAILED",
            "severity": "MEDIUM",
            "evidence": [
                "Bucket versioning is not enabled.",
                f"Versioning status: {status or 'Not configured'}",
            ],
        }

    except ClientError as e:
        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "ERROR",
            "severity": "MEDIUM",
            "evidence": [str(e)],
        }
def check_logging(s3, bucket_name):
    control_id = "S3.6"
    title = "S3 buckets should have access logging enabled"

    try:
        response = s3.get_bucket_logging(
            Bucket=bucket_name
        )

        logging_enabled = bool(
            response.get("LoggingEnabled")
        )

        if logging_enabled:
            target_bucket = response["LoggingEnabled"].get(
                "TargetBucket"
            )

            target_prefix = response["LoggingEnabled"].get(
                "TargetPrefix"
            )

            evidence = [
                "S3 access logging is enabled.",
                f"Target bucket: {target_bucket}",
            ]

            if target_prefix:
                evidence.append(
                    f"Target prefix: {target_prefix}"
                )

            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "PASSED",
                "severity": "MEDIUM",
                "evidence": evidence,
            }

        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "FAILED",
            "severity": "MEDIUM",
            "evidence": [
                "S3 access logging is not enabled."
            ],
        }

    except ClientError as e:
        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "ERROR",
            "severity": "MEDIUM",
            "evidence": [str(e)],
        }

def check_lifecycle(s3, bucket_name):
    control_id = "S3.7"
    title = "S3 buckets should have lifecycle configuration reviewed"

    try:
        response = s3.get_bucket_lifecycle_configuration(
            Bucket=bucket_name
        )

        rules = response.get("Rules", [])

        if not rules:
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "PASSED",
                "severity": "LOW",
                "evidence": [
                    "Lifecycle configuration exists but contains no rules."
                ],
            }

        enabled_rules = [
            rule
            for rule in rules
            if rule.get("Status") == "Enabled"
        ]

        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "PASSED",
            "severity": "LOW",
            "evidence": [
                f"Lifecycle rules configured: {len(rules)}",
                f"Enabled lifecycle rules: {len(enabled_rules)}",
            ],
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code in [
            "NoSuchLifecycleConfiguration",
            "NoSuchLifecycleConfigurationException",
        ]:
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "PASSED",
                "severity": "LOW",
                "evidence": [
                    "No lifecycle configuration is configured."
                ],
            }

        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "ERROR",
            "severity": "LOW",
            "evidence": [str(e)],
        }

def check_object_lock(s3, bucket_name):
    control_id = "S3.8"
    title = "S3 buckets should have object lock reviewed"

    try:
        response = s3.get_object_lock_configuration(
            Bucket=bucket_name
        )

        configuration = response.get(
            "ObjectLockConfiguration"
        )

        if not configuration:
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "PASSED",
                "severity": "LOW",
                "evidence": [
                    "Object Lock is not configured."
                ],
            }

        status = configuration.get("ObjectLockEnabled")

        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "PASSED",
            "severity": "LOW",
            "evidence": [
                "Object Lock configuration exists.",
                f"Object Lock status: {status}",
            ],
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code in [
            "ObjectLockConfigurationNotFoundError",
            "NoSuchObjectLockConfiguration",
        ]:
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "PASSED",
                "severity": "LOW",
                "evidence": [
                    "Object Lock is not configured."
                ],
            }

        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "ERROR",
            "severity": "LOW",
            "evidence": [str(e)],
        }

def check_https_only(s3, bucket_name):
    control_id = "S3.9"
    title = "S3 buckets should require secure transport"

    try:
        policy = get_bucket_policy(s3, bucket_name)

        if policy is None:
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "FAILED",
                "severity": "HIGH",
                "evidence": [
                    "No bucket policy exists.",
                    "No explicit HTTPS-only policy was detected.",
                ],
            }

        policy_data = json.loads(policy)

        statements = policy_data.get("Statement", [])

        if isinstance(statements, dict):
            statements = [statements]

        https_protection_found = False

        for statement in statements:
            if statement.get("Effect") != "Deny":
                continue

            condition = statement.get("Condition", {})

            bool_condition = condition.get("Bool", {})

            secure_transport = bool_condition.get(
                "aws:SecureTransport"
            )

            if str(secure_transport).lower() == "false":
                https_protection_found = True
                break

        if https_protection_found:
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "PASSED",
                "severity": "HIGH",
                "evidence": [
                    "Bucket policy explicitly denies insecure transport.",
                    "aws:SecureTransport=false condition detected.",
                ],
            }

        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "FAILED",
            "severity": "HIGH",
            "evidence": [
                "Bucket policy exists.",
                "No explicit HTTPS-only deny statement was detected.",
            ],
        }

    except ClientError as e:
        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "ERROR",
            "severity": "HIGH",
            "evidence": [str(e)],
        }

    except json.JSONDecodeError as e:
        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "ERROR",
            "severity": "HIGH",
            "evidence": [
                f"Unable to parse bucket policy JSON: {str(e)}"
            ],
        }

def check_mfa_delete(s3, bucket_name):
    control_id = "S3.10"
    title = "S3 buckets should have MFA Delete reviewed"

    try:
        response = s3.get_bucket_versioning(
            Bucket=bucket_name
        )

        mfa_delete = response.get("MFADelete")

        if mfa_delete == "Enabled":
            return {
                "control_id": control_id,
                "title": title,
                "resource": bucket_name,
                "status": "PASSED",
                "severity": "MEDIUM",
                "evidence": [
                    "MFA Delete is enabled.",
                    "MFA Delete status: Enabled",
                ],
            }

        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "FAILED",
            "severity": "MEDIUM",
            "evidence": [
                "MFA Delete is not enabled.",
                f"MFA Delete status: {mfa_delete or 'Not configured'}",
            ],
        }

    except ClientError as e:
        return {
            "control_id": control_id,
            "title": title,
            "resource": bucket_name,
            "status": "ERROR",
            "severity": "MEDIUM",
            "evidence": [str(e)],
        }

def print_result(result):
    print("\n" + "-" * 70)
    print(f"Control ID : {result['control_id']}")
    print(f"Title      : {result['title']}")
    print(f"Resource   : {result['resource']}")
    print(f"Status     : {result['status']}")
    print(f"Severity   : {result['severity']}")
    print("Evidence:")

    for item in result["evidence"]:
        print(f"  - {item}")


def get_s3_controls():
    return [
        check_block_public_access,
        check_public_read,
        check_public_write,
        check_encryption,
        check_versioning,
        check_logging,
        check_lifecycle,
        check_object_lock,
        check_https_only,
        check_mfa_delete,
    ]


def scan_s3():
    s3 = boto3.client("s3")

    print("Starting AWS S3 security scan...\n")

    response = s3.list_buckets()
    buckets = response.get("Buckets", [])

    print(f"Found {len(buckets)} S3 bucket(s).")

    for bucket in buckets:
        bucket_name = bucket["Name"]

        print(f"\nChecking bucket: {bucket_name}")

        results = []

        for control in get_s3_controls():
            result = control(s3, bucket_name)
            results.append(result)

        for result in results:
            print_result(result)


if __name__ == "__main__":
    scan_s3()

