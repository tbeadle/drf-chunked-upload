from datetime import timedelta

from django.conf import settings

_PREFIX = "ADRF_CHUNKED_UPLOAD"

# How long after creation the upload will expire
DEFAULT_EXPIRATION_DELTA = timedelta(days=1)
EXPIRATION_DELTA = getattr(
    settings, f"{_PREFIX}_EXPIRATION_DELTA", DEFAULT_EXPIRATION_DELTA
)

# Path where uploading files will be stored until completion
DEFAULT_UPLOAD_PATH = "chunked_uploads/%Y/%m/%d"
UPLOAD_PATH = getattr(settings, f"{_PREFIX}_PATH", DEFAULT_UPLOAD_PATH)

# Checksum type to use when verifying files
DEFAULT_CHECKSUM_TYPE = "sha256"
CHECKSUM_TYPE = getattr(settings, f"{_PREFIX}_CHECKSUM", DEFAULT_CHECKSUM_TYPE)

# File extensions for upload files
COMPLETE_EXT = getattr(settings, f"{_PREFIX}_COMPLETE_EXT", ".done")
INCOMPLETE_EXT = getattr(settings, f"{_PREFIX}_INCOMPLETE_EXT", ".part")

# Storage system
STORAGE = getattr(settings, f"{_PREFIX}_STORAGE_CLASS", lambda: None)()

# Boolean that defines if the ChunkedUpload model is abstract or not
ABSTRACT_MODEL = getattr(settings, f"{_PREFIX}_ABSTRACT_MODEL", False)

# Boolean that defines if users beside the creator can access an upload record
USER_RESTRICTED = getattr(settings, f"{_PREFIX}_USER_RESTRICTED", True)

# Max amount of data (in bytes) that can be uploaded. `None` means no limit
DEFAULT_MAX_BYTES = None
MAX_BYTES = getattr(settings, f"{_PREFIX}_MAX_BYTES", DEFAULT_MAX_BYTES)
