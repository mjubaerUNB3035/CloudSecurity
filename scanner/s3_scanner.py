import json

import boto3
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
            "NoSuchBucketPolicyException"
        ]:
            return None

        raise


def analyze_bucket_policy(policy):
    """
    Analyze an S3 bucket policy for public read and write access.

    Returns:
        tuple: (public_read, public_write)
    """

    policy_data = json.loads(policy)

    public_read = False
    public_write = False

    read_actions = {
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:ListBucket",
        "s3:*"
    }

    write_actions = {
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:*"
    }

    for statement in policy_data.get("Statement", []):

        # Only analyze statements that grant permissions
        if statement.get("Effect") != "Allow":
            continue

        principal = statement.get("Principal")

        # Detect public access
        is_public = (
            principal == "*"
            or (
                isinstance(principal, dict)
                and principal.get("AWS") == "*"
            )
        )

        if not is_public:
            continue

        actions = statement.get("Action", [])

        # Action can be a string or a list
        if isinstance(actions, str):
            actions = [actions]

        for action in actions:

            if action in read_actions:
                public_read = True

            if action in write_actions:
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
                    "No public read access through a bucket policy."
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
                    "A public read action was detected."
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
                "No public read access detected."
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
                    "No public write access through a bucket policy."
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
                    "A public write action was detected."
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
                "No public write access detected."
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


def scan_s3():
    s3 = boto3.client("s3")

    print("Starting AWS S3 security scan...\n")

    response = s3.list_buckets()
    buckets = response.get("Buckets", [])

    print(f"Found {len(buckets)} S3 bucket(s).")

    for bucket in buckets:
        bucket_name = bucket["Name"]

        print(f"\nChecking bucket: {bucket_name}")

        results = [
            check_block_public_access(s3, bucket_name),
            check_public_read(s3, bucket_name),
            check_public_write(s3, bucket_name),
        ]

        for result in results:
            print_result(result)


if __name__ == "__main__":
    scan_s3()
