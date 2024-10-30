import time
import os.path
import hashlib
from typing import Optional
import uuid
from datetime import datetime

import aiofiles
import aiofiles.os
from django.core.files.uploadedfile import UploadedFile
from django.db import models
from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.utils import timezone

from adrf_chunked_upload import settings as _settings


AUTH_USER_MODEL = getattr(settings, "AUTH_USER_MODEL", "auth.User")


def generate_filename(instance, filename):
    upload_dir = getattr(instance, "upload_dir", _settings.UPLOAD_PATH)
    filename = os.path.join(upload_dir, str(instance.id) + _settings.INCOMPLETE_EXT)
    return time.strftime(filename)


class AbstractChunkedUpload(models.Model):
    """Inherit from this model if you are implementing your own."""

    class Meta:
        abstract = True

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    file = models.FileField(
        max_length=255,
        upload_to=generate_filename,
        storage=_settings.STORAGE,
    )
    filename = models.CharField(max_length=255)
    offset = models.BigIntegerField(default=0)
    created_at = models.DateTimeField(
        auto_now_add=True,
        editable=False,
    )
    completed_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    @property
    def expires_at(self) -> Optional[datetime]:
        return (
            None if self.is_complete else self.created_at + _settings.EXPIRATION_DELTA
        )

    @property
    def expired(self) -> bool:
        return not self.is_complete and self.expires_at <= timezone.now()

    @property
    def is_complete(self) -> bool:
        return self.completed_at is not None

    @staticmethod
    async def calculate_checksum(filelike):
        h = hashlib.new(_settings.CHECKSUM_TYPE)
        async with aiofiles.open(filelike, mode="rb") as fil:
            while True:
                chunk = await fil.read(64 * 2**10)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    async def checksum(self, rehash=False):
        if getattr(self, "_checksum", None) is None or rehash is True:
            self._checksum = await self.calculate_checksum(self.file.path)
        return self._checksum

    async def adelete_file(self):
        if self.file:
            storage, path = self.file.storage, self.file.path
            if isinstance(storage, FileSystemStorage):
                try:
                    await aiofiles.os.unlink(path)
                except FileNotFoundError:  # pragma: no cover
                    pass
            else:
                storage.delete(path)  # pragma: no cover
        self.file = None

    async def adelete(self, delete_file=True, *args, **kwargs):
        await super().adelete(*args, **kwargs)
        if delete_file:
            await self.adelete_file()

    def __repr__(self):
        return "<{} - upload_id: {} - bytes: {} - complete: {}>".format(
            self.filename,
            self.id,
            self.offset,
            self.is_complete,
        )

    async def append_chunk(self, chunk: UploadedFile):
        if self.file is None:
            raise AssertionError(  # pragma: no cover
                "append_chunk() can only be called after saving an initial file"
            )
        async with aiofiles.open(self.file.path, mode="ab") as fil:
            for subchunk in chunk.chunks():
                await fil.write(subchunk)
        self.offset += chunk.size
        # clear any cached checksum
        self._checksum = None
        await self.asave()

    async def completed(self, completed_at=None, ext=_settings.COMPLETE_EXT):
        if completed_at is None:
            completed_at = timezone.now()

        if ext != _settings.INCOMPLETE_EXT:
            original_path = self.file.path
            self.file.name = os.path.splitext(self.file.name)[0] + ext
        self.completed_at = completed_at
        await self.asave()
        if ext != _settings.INCOMPLETE_EXT:
            await aiofiles.os.rename(
                original_path,
                os.path.splitext(self.file.path)[0] + ext,
            )


class ChunkedUpload(AbstractChunkedUpload):
    """Concrete model if you are not implementing your own."""

    user = models.ForeignKey(
        AUTH_USER_MODEL,
        related_name="%(class)s",
        editable=False,
        on_delete=models.CASCADE,
    )

    class Meta:
        abstract = _settings.ABSTRACT_MODEL
