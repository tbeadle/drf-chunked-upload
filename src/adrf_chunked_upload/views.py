import re
from typing import Optional, Type

from adrf.generics import ListAPIView, RetrieveAPIView
from adrf import serializers as adrf_serializers
from rest_framework.response import Response
from rest_framework import exceptions, status

from . import settings as _settings
from .exceptions import ChunkedUploadError
from .models import ChunkedUpload
from .serializers import (
    ChunkedUploadSerializer,
    CompleteUploadSerializer,
    FinishUploadSerializer,
    UploadResponseSerializer,
)


class ChunkedUploadMixin:
    model = ChunkedUpload
    user_field_name = "user"  # the field name that point towards the AUTH_USER in ChunkedUpload class or its subclasses

    chunked_upload_serializer_class = ChunkedUploadSerializer
    complete_upload_serializer_class = CompleteUploadSerializer
    finish_upload_serializer_class = FinishUploadSerializer
    response_serializer_class = UploadResponseSerializer

    # I wouldn't recommend turning off the checksum check,
    # unless it is signifcantly impacting performance.
    # Proceed at your own risk.
    do_checksum_check = True

    content_range_pattern = re.compile(
        r"^bytes (?P<start>\d+)-(?P<end>\d+)/(?P<total>\d+)$"
    )
    max_bytes = _settings.MAX_BYTES  # Max amount of data that can be uploaded

    async def checksum_check(self, chunked_upload: ChunkedUpload, checksum: str):
        """
        Verify if checksum sent by client matches generated checksum.
        """
        if await chunked_upload.checksum() != checksum:
            raise exceptions.ValidationError(
                {_settings.CHECKSUM_TYPE: "checksum does not match"}
            )

    def get_max_bytes(self):
        """
        Used to limit the max amount of data that can be uploaded. `None` means
        no limit.
        You can override this to have a custom `max_bytes`, e.g. based on
        logged user.
        """
        return self.max_bytes

    def get_queryset(self):
        """
        Get (and filter) ChunkedUpload queryset.
        By default, user can only continue uploading his/her own uploads.
        """
        if _settings.USER_RESTRICTED and hasattr(self.model, self.user_field_name):
            if hasattr(self.request, "user") and self.request.user.is_authenticated:
                queryset = self.model.objects.filter(
                    **{self.user_field_name: self.request.user}
                )
            else:
                queryset = self.model.objects.none()
        else:
            queryset = self.model.objects.all()

        return queryset

    async def finalize_upload(
        self, chunked_upload: ChunkedUpload, checksum: Optional[str]
    ) -> Optional[Response]:
        if self.do_checksum_check and checksum is not None:
            await self.checksum_check(chunked_upload, checksum)

        await chunked_upload.completed()

        return await self.on_completion(chunked_upload, checksum)

    def get_chunk(self):
        chunk = self.serializer.validated_data["file"]
        filename = getattr(chunk, "name", "")
        if not filename:
            raise exceptions.ValidationError(
                "No chunk filename was passed in the Content-Disposition"
            )

        content_range: Optional[str] = None
        if self.request.method == "POST":
            if "HTTP_CONTENT_RANGE" in self.request.META:
                raise exceptions.ValidationError(
                    "A Content-Range header should not be supplied in POST requests",
                )
        elif self.request.method == "PUT":
            content_range = self.request.META.get("HTTP_CONTENT_RANGE")
        else:
            raise AssertionError(
                "get_chunk should not be called for requests other than PUT or POST"
            )

        if content_range is None:
            start = 0
            total = chunk.size
            end = total - 1
        else:
            match = self.content_range_pattern.match(content_range)
            if not match:
                raise exceptions.ValidationError("Invalid Content-Range header")

            start = int(match.group("start"))
            end = int(match.group("end"))
            total = int(match.group("total"))

            if end >= total:
                raise exceptions.ValidationError(
                    f"End of chunk exceeds reported total ({total} bytes)",
                )

            chunk_size = end - start + 1
            if chunk.size != chunk_size:
                raise exceptions.ValidationError(
                    f"Chunk size doesn't match headers: chunk size is {chunk.size} but {chunk_size} reported",
                )

        max_bytes = self.get_max_bytes()
        if max_bytes is not None and total > max_bytes:
            raise exceptions.ValidationError(
                f"Size of file ({total}) exceeds the limit ({max_bytes} bytes)",
            )

        return {
            "file": chunk,
            "filename": filename,
            "offset": end + 1,
        }, start

    async def get_response(self, chunked_upload: model):
        return Response(
            await self.get_response_serializer_class()(
                chunked_upload,
                context=self.get_serializer_context(),
            ).adata,
            status=status.HTTP_200_OK,
        )

    def get_response_serializer_class(self):
        return self.response_serializer_class

    async def on_completion(
        self, chunked_upload: model, checksum: Optional[str]
    ) -> Optional[Response]:
        """
        This may be overridden in child classes to do more validation or operations
        to run when upload is complete.
        It may return either a Response object or None to have get_response() used.
        """
        return None


class ChunkedUploadDetailView(ChunkedUploadMixin, RetrieveAPIView):
    async def aget_object(self):
        """Check if chunked upload has already expired."""
        chunked_upload = await super().aget_object()
        if chunked_upload.expired:
            raise ChunkedUploadError(
                "Upload has expired",
                status_code=status.HTTP_410_GONE,
            )
        return chunked_upload

    def assert_upload_is_incomplete(self, chunked_upload: ChunkedUploadMixin.model):
        if chunked_upload.is_complete:
            raise ChunkedUploadError(
                "Upload has already been marked as 'complete'",
            )

    def get_serializer_class(self) -> Type[adrf_serializers.Serializer]:
        if self.request.method in ("GET", "HEAD"):
            return self.response_serializer_class
        if self.request.method == "PUT":
            return self.chunked_upload_serializer_class
        if self.request.method == "POST":
            return self.finish_upload_serializer_class
        raise exceptions.MethodNotAllowed

    async def post(self, request, pk, *args, **kwargs) -> Response:
        """Finish a chunked upload."""
        chunked_upload = await self.aget_object()
        self.assert_upload_is_incomplete(chunked_upload)
        self.serializer = self.get_serializer(data=request.data)
        self.serializer.is_valid(raise_exception=True)
        response = await self.finalize_upload(
            chunked_upload, self.serializer.validated_data.get(_settings.CHECKSUM_TYPE)
        )
        if response is None:
            response = await self.get_response(chunked_upload)
        return response

    async def put(self, request, pk, *args, **kwargs) -> Response:
        """Upload another chunk of a sample."""
        chunked_upload = await self.aget_object()
        self.assert_upload_is_incomplete(chunked_upload)
        await self.update_chunked_upload_from_request(request, chunked_upload)
        return await self.get_response(chunked_upload)

    async def update_chunked_upload_from_request(
        self, request, instance: ChunkedUploadMixin.model
    ):
        self.serializer = self.get_serializer(data=request.data)
        self.serializer.is_valid(raise_exception=True)
        data, start = self.get_chunk()
        if instance.offset != start:
            raise ChunkedUploadError(
                f"Start of content-range ({start}) does not match expected value ({instance.offset})",
            )
        await instance.append_chunk(data["file"])


class ChunkedUploadListView(ChunkedUploadMixin, ListAPIView):
    async def create_chunked_upload_from_request(self, request):
        self.serializer = self.get_serializer(data=request.data)
        self.serializer.is_valid(raise_exception=True)
        data, _ = self.get_chunk()
        return await self.model.objects.acreate(user=self.get_user(), **data)

    def get_serializer_class(self) -> Type[adrf_serializers.Serializer]:
        if self.request.method in ("GET", "HEAD"):
            return self.response_serializer_class
        if self.request.method == "PUT":
            return self.chunked_upload_serializer_class
        if self.request.method == "POST":
            return self.complete_upload_serializer_class
        raise exceptions.MethodNotAllowed

    def get_user(self):
        try:
            user = self.request.user
        except AttributeError:
            raise AssertionError("A request context is required.")
        if not user.is_authenticated:
            raise exceptions.ValidationError({"user": "A logged in user is required."})
        return user

    async def post(self, request, *args, **kwargs) -> Response:
        """Upload an entire file."""
        chunked_upload = await self.create_chunked_upload_from_request(request)
        response = await self.finalize_upload(
            chunked_upload, self.serializer.validated_data.get(_settings.CHECKSUM_TYPE)
        )
        if response is None:
            response = await self.get_response(chunked_upload)
        return response

    async def put(self, request, *args, **kwargs) -> Response:
        """Start a chunked upload."""
        chunked_upload = await self.create_chunked_upload_from_request(request)
        return await self.get_response(chunked_upload)
