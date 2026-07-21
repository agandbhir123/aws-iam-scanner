import boto3
from botocore.exceptions import NoCredentialsError, ProfileNotFound, ClientError


def get_session(profile=None, region="us-east-1"):
    """
    Create and validate a boto3 session.
    Returns (session, caller_identity_dict) or raises RuntimeError.
    """
    try:
        if profile:
            session = boto3.Session(profile_name=profile, region_name=region)
        else:
            session = boto3.Session(region_name=region)

        # Validate credentials by calling STS
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        return session, identity

    except NoCredentialsError:
        raise RuntimeError(
            "No AWS credentials found. Configure via `aws configure`, "
            "environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY), "
            "or an IAM role."
        )
    except ProfileNotFound:
        raise RuntimeError(
            f"AWS profile '{profile}' not found. "
            "Check your ~/.aws/credentials file."
        )
    except ClientError as e:
        raise RuntimeError(f"AWS authentication error: {e}")
