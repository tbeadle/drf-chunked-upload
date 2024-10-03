import io
import hashlib
import pytest
import importlib
from datetime import timedelta
from random import randbytes
from typing import Optional

from asgiref.sync import sync_to_async
from django.contrib.auth.models import User, AnonymousUser
from django.http.response import Http404
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIRequestFactory
from rest_framework import exceptions

from adrf_chunked_upload import settings as _settings
from adrf_chunked_upload.views import ChunkedUploadDetailView, ChunkedUploadListView
from adrf_chunked_upload.models import ChunkedUpload


factory = APIRequestFactory()


class Chunk:
    def __init__(self, offset, total_size, data):
        self.offset = offset
        self.total_size = total_size
        self.data = data
        self.end = self.offset + len(self.data) - 1


class Chunks:
    def __init__(self, chunk_size=10000, count=10):
        self.chunk_size = chunk_size
        self.count = count
        self.total_size = self.chunk_size * self.count
        self.data = randbytes(self.total_size)
        self.sha256 = get_sha256(self.data)

    def __getitem__(self, idx):
        start = idx * self.chunk_size
        return Chunk(
            start,
            self.total_size,
            self.data[start : start + self.chunk_size],
        )

    def __iter__(self):
        for idx in range(self.count):
            yield self[idx]


class NamedBytesIO(io.BytesIO):
    """This can be used to simulate file uploads because it will include
    the 'name' attribute as the 'filename' part of the content-disposition
    header in multipart POST requests.
    """

    def __init__(self, name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = name


def get_sha256(data):
    return hashlib.sha256(data).hexdigest()


def build_request(
    chunk: Optional[Chunk],
    user: User,
    do_post=False,
    content_range=None,
    checksum=None,
    extra_fields=None,
):
    if content_range is None and chunk is not None and not do_post:
        content_range = f"bytes {chunk.offset}-{chunk.end}/{chunk.total_size}"

    request_dict = {}
    if chunk:
        request_dict["file"] = NamedBytesIO("afile", chunk.data)

    if extra_fields:
        for k, v in extra_fields.items():
            request_dict[k] = v

    if do_post:
        if checksum:
            request_dict["sha256"] = checksum
        mkrequest = factory.post
    else:
        mkrequest = factory.put

    kwargs = {
        "format": "multipart",
    }
    if content_range is not None:
        kwargs["HTTP_CONTENT_RANGE"] = content_range
    req = mkrequest("/", request_dict, **kwargs)
    req.user = user
    return req


@pytest.fixture(autouse=True)
def use_tmp_upload_dir(tmp_path, settings):
    settings.MEDIA_ROOT = str(tmp_path)
    # need to reload just to make sure any settings
    # changed by the last test  have been reset
    importlib.reload(_settings)


@pytest.fixture
def no_restrict_users(settings):
    settings.ADRF_CHUNKED_UPLOAD_USER_RESTRICTED = False
    importlib.reload(_settings)


@pytest.fixture()
async def user1():
    obj = await sync_to_async(User.objects.create_user)(
        username="testuser1", password="12345"
    )
    try:
        yield obj
    finally:
        await obj.adelete()


@pytest.fixture()
async def user2():
    obj = await sync_to_async(User.objects.create_user)(
        username="testuser2", password="12345"
    )
    try:
        yield obj
    finally:
        await obj.adelete()


@pytest.fixture
def detail_view():
    return ChunkedUploadDetailView.as_view()


@pytest.fixture
def list_view():
    return ChunkedUploadListView.as_view()


@pytest.fixture()
async def user1_uploads(user1):
    uploads = [
        ChunkedUpload(user=user1, filename="fakefile"),
        ChunkedUpload(user=user1, filename="fakefile", completed_at=timezone.now()),
    ]
    for upload in uploads:
        await upload.asave()
    try:
        yield uploads
    finally:
        for upload in uploads:
            await upload.adelete()


@pytest.fixture()
async def user2_uploads(user2):
    uploads = [
        ChunkedUpload(user=user2, filename="fakefile"),
        ChunkedUpload(user=user2, filename="fakefile"),
    ]
    for upload in uploads:
        await upload.asave()
    try:
        yield uploads
    finally:
        for upload in uploads:
            await upload.adelete()


@pytest.mark.django_db
async def test_print_chunked_upload(user1_uploads):
    assert (
        user1_uploads[0].__repr__()
        == f"<fakefile - upload_id: {user1_uploads[0].id} - bytes: 0 - complete: False>"
    )
    assert (
        user1_uploads[1].__repr__()
        == f"<fakefile - upload_id: {user1_uploads[1].id} - bytes: 0 - complete: True>"
    )


@pytest.mark.django_db
async def test_chunked_upload(detail_view, list_view, user1, freezer):
    """Validate that uploading a file in chunks works as expected."""
    freezer.move_to("2024-10-02")
    chunks = Chunks()
    pk = None
    view = list_view
    for chunk in chunks:
        request = build_request(chunk, user1)
        response = await view(request, pk=pk)
        assert response.status_code == status.HTTP_200_OK
        obj = await ChunkedUpload.objects.afirst()
        assert response.data == {
            "id": str(obj.pk),
            "url": f"http://testserver/{obj.pk}/",
            "completed_at": None,
            "created_at": "2024-10-02T00:00:00Z",
            "expires_at": "2024-10-03T00:00:00Z",
            "filename": "afile",
            "offset": chunk.end + 1,
            "user": user1.pk,
        }
        pk = str(obj.pk)
        view = detail_view
    request = factory.post(
        "/",
        {"sha256": chunks.sha256},
        format="multipart",
    )
    request.user = user1
    freezer.move_to("2024-10-02 12:00:00Z")
    response = await view(request, pk=pk)
    assert response.status_code == status.HTTP_200_OK
    assert response.data == {
        "id": str(obj.pk),
        "url": f"http://testserver/{obj.pk}/",
        "filename": "afile",
        "offset": chunks.total_size,
        "created_at": "2024-10-02T00:00:00Z",
        "completed_at": "2024-10-02T12:00:00Z",
        "user": user1.pk,
        "expires_at": None,
    }


@pytest.mark.django_db
async def test_chunked_upload_wrong_order(detail_view, list_view, user1, freezer):
    """Validate that sending a chunk out of order (in other words, the
    Content-Range header is for a byte range different than what is expected)
    results in an HTTP 400.
    """
    chunks = Chunks(chunk_size=10, count=5)
    pk = None
    chunk = chunks[0]
    request = build_request(chunk, user1)
    freezer.move_to("2024-10-02")
    response = await list_view(request)
    assert response.status_code == status.HTTP_200_OK
    obj = await ChunkedUpload.objects.afirst()
    assert response.data == {
        "id": str(obj.pk),
        "url": f"http://testserver/{obj.pk}/",
        "completed_at": None,
        "created_at": "2024-10-02T00:00:00Z",
        "expires_at": "2024-10-03T00:00:00Z",
        "filename": "afile",
        "offset": chunk.end + 1,
        "user": user1.pk,
    }
    pk = str(obj.pk)

    chunk = chunks[2]
    request = build_request(chunk, user1)
    response = await detail_view(request, pk=pk)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "content-range" in response.data["detail"]


@pytest.mark.django_db
async def test_complete_upload_no_checksum(list_view, user1):
    """Send a complete upload, but do not include the checksum."""
    request = factory.post(
        "/",
        {"file": NamedBytesIO("afile", b"abcdef")},
        format="multipart",
    )
    request.user = user1
    response = await list_view(request)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "sha256" in response.data


@pytest.mark.django_db
async def test_chunked_upload_no_checksum(detail_view, list_view, user1):
    """Send the first (and only) chunk. Then send the POST to complete
    the upload, but with no checksum included.
    """
    chunks = Chunks(count=1)
    chunk = chunks[0]
    request = build_request(chunk, user1)
    response = await list_view(request)
    assert response.status_code == status.HTTP_200_OK

    request = factory.post(
        f"/{response.data['id']}/",
        {},
        format="multipart",
    )
    request.user = user1
    response = await detail_view(request, pk=response.data["id"])
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "sha256" in response.data


@pytest.mark.django_db
async def test_wrong_user(detail_view, user1_uploads, user2):
    chunks = Chunks()
    pk = user1_uploads[0].id
    request = build_request(chunks[3], user2)
    response = await detail_view(request, pk=str(pk))
    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
async def test_resume_expired(detail_view, user1, user1_uploads, freezer):
    chunks = Chunks()
    pk = user1_uploads[0].id
    freezer.move_to(user1_uploads[0].expires_at + timedelta(milliseconds=1))
    request = build_request(chunks[0], user1)
    response = await detail_view(request, pk=str(pk))
    assert response.status_code == status.HTTP_410_GONE


@pytest.mark.django_db
async def test_resume_completed(detail_view, user1, user1_uploads):
    chunks = Chunks()
    pk = user1_uploads[1].id
    request = build_request(chunks[5], user1)
    response = await detail_view(request, pk=str(pk))
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data["detail"] == "Upload has already been marked as 'complete'"


bad_content_ranges = [
    ("bytes nonsense", "Invalid Content-Range header"),
    ("bytes 0-100000/5", "End of chunk exceeds reported total (5 bytes)"),
    (
        "bytes 0-9999/999999999999999999999",
        "Size of file (999999999999999999999) exceeds the limit (1000000 bytes)",
    ),
    (
        "bytes 0-1/100000",
        "Chunk size doesn't match headers: chunk size is 10000 but 2 reported",
    ),
]


@pytest.mark.django_db
@pytest.mark.parametrize("cr", bad_content_ranges)
async def test_bad_content_range(cr, list_view, user1):
    chunks = Chunks()
    request = build_request(chunks[0], user1, content_range=cr[0])
    response = await list_view(request)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert str(response.data[0]) == cr[1]


@pytest.mark.django_db
async def test_complete_upload(list_view, user1, freezer):
    chunks = Chunks(chunk_size=100000, count=1)
    freezer.move_to("2024-10-02")
    request = build_request(chunks[0], user1, checksum=chunks.sha256, do_post=True)
    response = await list_view(request)
    assert response.status_code == status.HTTP_200_OK
    obj = await ChunkedUpload.objects.afirst()
    assert response.data == {
        "id": str(obj.pk),
        "url": f"http://testserver/{obj.pk}/",
        "filename": "afile",
        "offset": chunks.total_size,
        "created_at": "2024-10-02T00:00:00Z",
        "completed_at": "2024-10-02T00:00:00Z",
        "user": user1.pk,
        "expires_at": None,
    }


@pytest.mark.django_db
async def test_bad_checksum(list_view, user1):
    chunks = Chunks(chunk_size=100000, count=1)
    request = build_request(chunks[0], user1, do_post=True, checksum="a" * 64)
    response = await list_view(request)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data["checksum"] == "checksum does not match"


@pytest.mark.django_db
@pytest.mark.parametrize("do_post", (True, False))
async def test_list_view_no_chunk(list_view, user1, do_post):
    request = build_request(None, user1, do_post=do_post, checksum="a" * 64)
    response = await list_view(request)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "file" in response.data


@pytest.mark.django_db
async def test_detail_view_no_chunk(detail_view, list_view, user1):
    chunks = Chunks()
    request = build_request(chunks[0], user1)
    response = await list_view(request)
    assert response.status_code == status.HTTP_200_OK
    request = build_request(None, user1)
    response = await detail_view(request, pk=response.data["id"])
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "file" in response.data


@pytest.mark.django_db
async def test_list_uploads(list_view, user1, user1_uploads):
    request = factory.get("/")
    request.user = user1
    response = await list_view(request)
    assert response.status_code == status.HTTP_200_OK
    user1_upload_pks = sorted([str(ul.pk) for ul in user1_uploads])
    resp_upload_pks = sorted([ul["id"] for ul in response.data])
    assert user1_upload_pks == resp_upload_pks


@pytest.mark.django_db
async def test_get_upload(detail_view, user1, user1_uploads):
    pk = str(user1_uploads[0].pk)
    request = factory.get(f"/{pk}/")
    request.user = user1
    response = await detail_view(request, pk=pk)
    assert response.status_code == status.HTTP_200_OK
    assert response.data["id"] == pk


@pytest.mark.django_db
async def test_get_upload_wrong_user(detail_view, user2, user1_uploads):
    pk = str(user1_uploads[0].pk)
    request = factory.get(f"/{pk}/")
    request.user = user2
    response = await detail_view(request, pk=pk)
    assert response.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.django_db
async def test_list_uploads_no_user_restricted(list_view):
    request = factory.get("/")
    response = await list_view(request)
    assert response.status_code == status.HTTP_200_OK
    assert response.data == []


@pytest.mark.django_db
async def test_anonymous_upload(list_view):
    chunks = Chunks(chunk_size=100000, count=1)
    request = build_request(
        chunks[0], AnonymousUser, checksum=chunks.sha256, do_post=True
    )
    response = await list_view(request)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "logged in user is required" in response.data["user"]


@pytest.mark.django_db
@pytest.mark.usefixtures("no_restrict_users")
async def test_list_uploads_no_user_not_restricted(
    list_view, user1_uploads, user2_uploads
):
    request = factory.get("/")
    response = await list_view(request)
    assert response.status_code == status.HTTP_200_OK
    uploads = user1_uploads + user2_uploads
    upload_pks = sorted([str(ul.pk) for ul in uploads])
    resp_upload_pks = sorted([ul["id"] for ul in response.data])
    assert upload_pks == resp_upload_pks
