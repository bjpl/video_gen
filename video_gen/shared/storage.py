"""
Storage abstraction layer for video outputs.

Supports multiple storage backends:
- LocalStorage: Filesystem storage (ephemeral on Railway)
- S3Storage: AWS S3 storage
- CloudflareR2Storage: Cloudflare R2 storage (S3-compatible, cost-effective)
"""

import os
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from abc import ABC, abstractmethod
from datetime import datetime, timedelta


logger = logging.getLogger(__name__)


class StorageBackend(ABC):
    """Abstract base class for storage backends."""

    @abstractmethod
    async def upload_file(
        self,
        local_path: Path,
        remote_key: str,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Upload a file to storage.

        Args:
            local_path: Path to local file
            remote_key: Remote storage key/path
            content_type: MIME type (e.g., 'video/mp4')
            metadata: Additional metadata to store with file

        Returns:
            Public URL to access the file
        """
        pass

    @abstractmethod
    async def delete_file(self, remote_key: str) -> bool:
        """
        Delete a file from storage.

        Args:
            remote_key: Remote storage key/path

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    async def get_url(self, remote_key: str, expires_in: int = 3600) -> str:
        """
        Get a public or signed URL for a file.

        Args:
            remote_key: Remote storage key/path
            expires_in: URL expiration time in seconds (for signed URLs)

        Returns:
            Public or signed URL
        """
        pass

    @abstractmethod
    async def cleanup_old_files(self, max_age_days: int = 7) -> int:
        """
        Delete files older than max_age_days.

        Args:
            max_age_days: Maximum age in days

        Returns:
            Number of files deleted
        """
        pass


class LocalStorage(StorageBackend):
    """Local filesystem storage (current behavior)."""

    def __init__(self, base_path: Path, base_url: Optional[str] = None):
        """
        Initialize local storage.

        Args:
            base_path: Base directory for storage
            base_url: Base URL for accessing files (e.g., 'http://localhost:8000/outputs')
        """
        self.base_path = Path(base_path)
        self.base_url = base_url or ""
        self.base_path.mkdir(parents=True, exist_ok=True)

    async def upload_file(
        self,
        local_path: Path,
        remote_key: str,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Upload file to local storage (just validate it exists).

        Args:
            local_path: Path to local file
            remote_key: Remote storage key/path
            content_type: MIME type (ignored for local storage)
            metadata: Additional metadata (ignored for local storage)

        Returns:
            Local URL path
        """
        # For local storage, file should already be at the correct location
        if not local_path.exists():
            raise FileNotFoundError(f"File not found: {local_path}")

        # Return URL path
        relative_path = local_path.relative_to(self.base_path) if local_path.is_relative_to(self.base_path) else local_path.name
        url = f"{self.base_url}/{relative_path}".replace("\\", "/")
        logger.info(f"Local storage: {local_path} -> {url}")
        return url

    async def delete_file(self, remote_key: str) -> bool:
        """
        Delete file from local storage.

        Args:
            remote_key: File path relative to base_path

        Returns:
            True if successful, False otherwise
        """
        try:
            file_path = self.base_path / remote_key
            if file_path.exists():
                file_path.unlink()
                logger.info(f"Deleted local file: {file_path}")
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete local file {remote_key}: {e}")
            return False

    async def get_url(self, remote_key: str, expires_in: int = 3600) -> str:
        """
        Get URL for local file.

        Args:
            remote_key: File path relative to base_path
            expires_in: Ignored for local storage

        Returns:
            Local URL path
        """
        url = f"{self.base_url}/{remote_key}".replace("\\", "/")
        return url

    async def cleanup_old_files(self, max_age_days: int = 7) -> int:
        """
        Delete local files older than max_age_days.

        Args:
            max_age_days: Maximum age in days

        Returns:
            Number of files deleted
        """
        deleted_count = 0
        cutoff_time = datetime.now().timestamp() - (max_age_days * 86400)

        try:
            for file_path in self.base_path.rglob("*"):
                if file_path.is_file() and file_path.stat().st_mtime < cutoff_time:
                    try:
                        file_path.unlink()
                        deleted_count += 1
                        logger.debug(f"Deleted old file: {file_path}")
                    except Exception as e:
                        logger.warning(f"Failed to delete {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")

        logger.info(f"Cleaned up {deleted_count} old files")
        return deleted_count


class S3Storage(StorageBackend):
    """AWS S3 storage backend."""

    def __init__(
        self,
        bucket_name: str,
        region: str = "us-east-1",
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        endpoint_url: Optional[str] = None
    ):
        """
        Initialize S3 storage.

        Args:
            bucket_name: S3 bucket name
            region: AWS region
            access_key: AWS access key (or use env AWS_ACCESS_KEY_ID)
            secret_key: AWS secret key (or use env AWS_SECRET_ACCESS_KEY)
            endpoint_url: Custom endpoint URL (for S3-compatible services)
        """
        try:
            import boto3
            from botocore.exceptions import ClientError
            self.ClientError = ClientError
        except ImportError:
            raise ImportError(
                "boto3 is required for S3 storage. Install with: pip install boto3"
            )

        self.bucket_name = bucket_name
        self.region = region

        # Initialize S3 client
        session_kwargs = {}
        if access_key and secret_key:
            session_kwargs["aws_access_key_id"] = access_key
            session_kwargs["aws_secret_access_key"] = secret_key

        client_kwargs = {"region_name": region}
        if endpoint_url:
            client_kwargs["endpoint_url"] = endpoint_url

        self.s3_client = boto3.client("s3", **session_kwargs, **client_kwargs)
        self.s3_resource = boto3.resource("s3", **session_kwargs, **client_kwargs)

        logger.info(f"Initialized S3 storage: bucket={bucket_name}, region={region}")

    async def upload_file(
        self,
        local_path: Path,
        remote_key: str,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Upload file to S3.

        Args:
            local_path: Path to local file
            remote_key: S3 object key
            content_type: MIME type
            metadata: Additional metadata

        Returns:
            Public S3 URL
        """
        if not local_path.exists():
            raise FileNotFoundError(f"File not found: {local_path}")

        try:
            extra_args = {}

            # Set content type
            if content_type:
                extra_args["ContentType"] = content_type
            elif str(local_path).endswith(".mp4"):
                extra_args["ContentType"] = "video/mp4"
            elif str(local_path).endswith(".jpg") or str(local_path).endswith(".jpeg"):
                extra_args["ContentType"] = "image/jpeg"
            elif str(local_path).endswith(".json"):
                extra_args["ContentType"] = "application/json"

            # Set metadata
            if metadata:
                extra_args["Metadata"] = metadata

            # Make publicly readable
            extra_args["ACL"] = "public-read"

            # Upload file
            self.s3_client.upload_file(
                str(local_path),
                self.bucket_name,
                remote_key,
                ExtraArgs=extra_args
            )

            # Generate public URL
            url = f"https://{self.bucket_name}.s3.{self.region}.amazonaws.com/{remote_key}"
            logger.info(f"Uploaded to S3: {local_path} -> {url}")
            return url

        except self.ClientError as e:
            logger.error(f"S3 upload failed: {e}")
            raise

    async def delete_file(self, remote_key: str) -> bool:
        """
        Delete file from S3.

        Args:
            remote_key: S3 object key

        Returns:
            True if successful, False otherwise
        """
        try:
            self.s3_client.delete_object(Bucket=self.bucket_name, Key=remote_key)
            logger.info(f"Deleted S3 object: {remote_key}")
            return True
        except self.ClientError as e:
            logger.error(f"Failed to delete S3 object {remote_key}: {e}")
            return False

    async def get_url(self, remote_key: str, expires_in: int = 3600) -> str:
        """
        Get signed URL for S3 object.

        Args:
            remote_key: S3 object key
            expires_in: URL expiration time in seconds

        Returns:
            Signed S3 URL
        """
        try:
            url = self.s3_client.generate_presigned_url(
                "get_object",
                Params={"Bucket": self.bucket_name, "Key": remote_key},
                ExpiresIn=expires_in
            )
            return url
        except self.ClientError as e:
            logger.error(f"Failed to generate presigned URL for {remote_key}: {e}")
            # Return public URL as fallback
            return f"https://{self.bucket_name}.s3.{self.region}.amazonaws.com/{remote_key}"

    async def cleanup_old_files(self, max_age_days: int = 7) -> int:
        """
        Delete S3 objects older than max_age_days.

        Args:
            max_age_days: Maximum age in days

        Returns:
            Number of objects deleted
        """
        deleted_count = 0
        cutoff_date = datetime.now() - timedelta(days=max_age_days)

        try:
            bucket = self.s3_resource.Bucket(self.bucket_name)
            for obj in bucket.objects.all():
                if obj.last_modified.replace(tzinfo=None) < cutoff_date:
                    try:
                        obj.delete()
                        deleted_count += 1
                        logger.debug(f"Deleted old S3 object: {obj.key}")
                    except self.ClientError as e:
                        logger.warning(f"Failed to delete {obj.key}: {e}")
        except self.ClientError as e:
            logger.error(f"Error during S3 cleanup: {e}")

        logger.info(f"Cleaned up {deleted_count} old S3 objects")
        return deleted_count


class CloudflareR2Storage(S3Storage):
    """
    Cloudflare R2 storage backend.

    R2 is S3-compatible but with different endpoint URL format.
    Cheaper than S3: No egress fees, $0.015/GB storage.
    """

    def __init__(
        self,
        bucket_name: str,
        account_id: str,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        public_domain: Optional[str] = None
    ):
        """
        Initialize Cloudflare R2 storage.

        Args:
            bucket_name: R2 bucket name
            account_id: Cloudflare account ID
            access_key: R2 access key (or use env AWS_ACCESS_KEY_ID)
            secret_key: R2 secret key (or use env AWS_SECRET_ACCESS_KEY)
            public_domain: Custom domain for public URLs (optional)
        """
        # R2 uses S3-compatible API with custom endpoint
        endpoint_url = f"https://{account_id}.r2.cloudflarestorage.com"

        # Initialize using S3Storage parent class
        super().__init__(
            bucket_name=bucket_name,
            region="auto",  # R2 handles region automatically
            access_key=access_key,
            secret_key=secret_key,
            endpoint_url=endpoint_url
        )

        self.account_id = account_id
        self.public_domain = public_domain
        logger.info(f"Initialized Cloudflare R2 storage: bucket={bucket_name}, account={account_id}")

    async def upload_file(
        self,
        local_path: Path,
        remote_key: str,
        content_type: Optional[str] = None,
        metadata: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Upload file to R2.

        Args:
            local_path: Path to local file
            remote_key: R2 object key
            content_type: MIME type
            metadata: Additional metadata

        Returns:
            Public R2 URL
        """
        # Upload using parent S3 method
        await super().upload_file(local_path, remote_key, content_type, metadata)

        # Generate public URL
        if self.public_domain:
            url = f"https://{self.public_domain}/{remote_key}"
        else:
            # Use R2.dev subdomain (must enable in R2 settings)
            url = f"https://pub-{self.account_id}.r2.dev/{remote_key}"

        logger.info(f"Uploaded to R2: {local_path} -> {url}")
        return url

    async def get_url(self, remote_key: str, expires_in: int = 3600) -> str:
        """
        Get URL for R2 object.

        Args:
            remote_key: R2 object key
            expires_in: URL expiration time in seconds

        Returns:
            Public R2 URL or signed URL
        """
        if self.public_domain:
            # Use custom domain (public access)
            return f"https://{self.public_domain}/{remote_key}"
        else:
            # Use R2.dev subdomain or generate presigned URL
            return f"https://pub-{self.account_id}.r2.dev/{remote_key}"


def create_storage(
    backend: Optional[str] = None,
    **kwargs
) -> StorageBackend:
    """
    Factory function to create storage backend.

    Args:
        backend: Storage backend type ('local', 's3', 'r2')
                 If None, reads from STORAGE_BACKEND env var (default: 'local')
        **kwargs: Additional arguments for storage backend

    Returns:
        Storage backend instance

    Environment Variables:
        STORAGE_BACKEND: local|s3|r2 (default: local)

        For S3:
        - AWS_ACCESS_KEY_ID
        - AWS_SECRET_ACCESS_KEY
        - AWS_BUCKET_NAME
        - AWS_REGION (default: us-east-1)

        For R2:
        - AWS_ACCESS_KEY_ID (R2 access key)
        - AWS_SECRET_ACCESS_KEY (R2 secret key)
        - AWS_BUCKET_NAME (R2 bucket name)
        - R2_ACCOUNT_ID (Cloudflare account ID)
        - R2_PUBLIC_DOMAIN (optional custom domain)
    """
    backend = backend or os.getenv("STORAGE_BACKEND", "local").lower()

    if backend == "local":
        base_path = kwargs.get("base_path") or Path(os.getenv("OUTPUT_DIR", "outputs"))
        base_url = kwargs.get("base_url") or os.getenv("OUTPUT_BASE_URL", "")
        return LocalStorage(base_path=base_path, base_url=base_url)

    elif backend == "s3":
        bucket_name = kwargs.get("bucket_name") or os.getenv("AWS_BUCKET_NAME")
        if not bucket_name:
            raise ValueError("S3 storage requires AWS_BUCKET_NAME")

        return S3Storage(
            bucket_name=bucket_name,
            region=kwargs.get("region") or os.getenv("AWS_REGION", "us-east-1"),
            access_key=kwargs.get("access_key") or os.getenv("AWS_ACCESS_KEY_ID"),
            secret_key=kwargs.get("secret_key") or os.getenv("AWS_SECRET_ACCESS_KEY"),
            endpoint_url=kwargs.get("endpoint_url")
        )

    elif backend == "r2":
        bucket_name = kwargs.get("bucket_name") or os.getenv("AWS_BUCKET_NAME")
        account_id = kwargs.get("account_id") or os.getenv("R2_ACCOUNT_ID")

        if not bucket_name:
            raise ValueError("R2 storage requires AWS_BUCKET_NAME")
        if not account_id:
            raise ValueError("R2 storage requires R2_ACCOUNT_ID")

        return CloudflareR2Storage(
            bucket_name=bucket_name,
            account_id=account_id,
            access_key=kwargs.get("access_key") or os.getenv("AWS_ACCESS_KEY_ID"),
            secret_key=kwargs.get("secret_key") or os.getenv("AWS_SECRET_ACCESS_KEY"),
            public_domain=kwargs.get("public_domain") or os.getenv("R2_PUBLIC_DOMAIN")
        )

    else:
        raise ValueError(f"Unknown storage backend: {backend}")
