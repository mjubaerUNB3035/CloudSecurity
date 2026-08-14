import json

from scanner.s3_scanner import analyze_bucket_policy


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