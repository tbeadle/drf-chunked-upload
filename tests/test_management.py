import asyncio
import io
import pytest
import importlib

from pathlib import Path
from datetime import timedelta

from asgiref.sync import sync_to_async
from django.contrib.auth.models import User
from django.core.files.uploadedfile import UploadedFile
from django.utils import timezone

from adrf_chunked_upload import settings as _settings
from adrf_chunked_upload.management.commands.delete_expired_uploads import (
    Command as DeleteExpiredUploads,
)
from adrf_chunked_upload.models import ChunkedUpload


try:
    from random import randbytes
except ImportError:
    import random

    def randbytes(n):
        """Generate n random bytes."""
        return random.getrandbits(n * 8).to_bytes(n, "little")


@pytest.fixture(autouse=True)
def use_tmp_upload_dir(tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    settings.ADRF_CHUNKED_UPLOAD_PATH = ""
    importlib.reload(_settings)


@pytest.fixture
def short_expirations(settings):
    settings.ADRF_CHUNKED_UPLOAD_EXPIRATION_DELTA = timedelta(microseconds=1)
    importlib.reload(_settings)


@pytest.fixture()
async def user1(db):
    obj = await sync_to_async(User.objects.create_user)(
        username="testuser1", password="12345"
    )
    try:
        yield obj
    finally:
        await obj.adelete()


@pytest.fixture()
async def user1_uploads(user1):
    uploads = []
    for i in range(4):
        f = UploadedFile(file=io.BytesIO(randbytes(100)), name=f"file{i}")
        cu = ChunkedUpload(user=user1, file=f, filename=f"fakefile_{i}")
        await cu.asave()
        uploads.append(cu)

    uploads[-1].completed_at = timezone.now()
    await uploads[-1].asave()

    try:
        yield uploads
    finally:
        await ChunkedUpload.objects.all().adelete()


@pytest.mark.django_db
@pytest.mark.usefixtures("short_expirations")
async def test_delete_expired_uploads(settings, user1_uploads):
    # sleep to make sure uploads expire
    await asyncio.sleep(0.01)

    # make sure we have the number of expected files
    path = Path(settings.MEDIA_ROOT)
    upload_files = sorted([ul.file.name for ul in user1_uploads])
    assert sorted([f.name for f in path.iterdir()]) == upload_files

    assert len(list(filter(lambda ul: ul.expired, user1_uploads))) == 3

    # call managment command to clean up expired upload files and records
    await DeleteExpiredUploads().ahandle(
        {
            "models": (
                "adrf_chunked_upload.ChunkedUpload",
                "auth.User",
                "not_a.real_model",
            )
        }
    )

    # we should only have the completed file
    assert sorted([f.name for f in path.iterdir()]) == [user1_uploads[-1].file.name]

    # make sure expired records are gone but we still have the completed one
    for ul in user1_uploads:
        if ul.expired:
            with pytest.raises(ChunkedUpload.DoesNotExist):
                await ChunkedUpload.objects.aget(pk=ul.id)
        else:
            try:
                await ChunkedUpload.objects.aget(pk=ul.id)
            except ChunkedUpload.DoesNotExist as e:
                assert False, f"Missing chunked upload records per exception '{e}'"


@pytest.mark.django_db
@pytest.mark.usefixtures("short_expirations")
async def test_delete_expired_uploads_two_stage(settings, user1_uploads):
    # sleep to make sure uploads expire
    await asyncio.sleep(0.01)

    # make sure we have the number of expected files
    path = Path(settings.MEDIA_ROOT)
    upload_files = sorted([ul.file.name for ul in user1_uploads])
    assert sorted([f.name for f in path.iterdir()]) == upload_files

    assert len(list(filter(lambda ul: ul.expired, user1_uploads))) == 3

    # call managment command to clean up expired upload files but leave records
    await DeleteExpiredUploads().ahandle({"delete_record": False})

    # we should only have the completed file
    assert sorted([f.name for f in path.iterdir()]) == [user1_uploads[-1].file.name]

    # ensure the records all exist
    for ul in user1_uploads:
        try:
            await ChunkedUpload.objects.aget(pk=ul.id)
        except ChunkedUpload.DoesNotExist as e:
            assert False, f"Missing chunked upload records per exception '{e}'"

    # call managment command to clean up expired upload records
    await DeleteExpiredUploads().ahandle({})

    # make sure expired records are gone but we still have the completed one
    for ul in user1_uploads:
        if ul.expired:
            with pytest.raises(ChunkedUpload.DoesNotExist):
                await ChunkedUpload.objects.aget(pk=ul.id)
        else:
            try:
                await ChunkedUpload.objects.aget(pk=ul.id)
            except ChunkedUpload.DoesNotExist as e:
                assert False, f"Missing chunked upload records per exception '{e}'"
