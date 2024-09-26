import re
from typing import Optional, cast

from adrf.mixins import ListModelMixin, RetrieveModelMixin
from adrf.viewsets import GenericViewSet
from django.shortcuts import aget_object_or_404
from django.utils.decorators import method_decorator
from django.views.decorators.cache import cache_page
from rest_framework.response import Response
from rest_framework import status

from . import settings as _settings
from .models import ChunkedUpload
from .serializers import ChunkedUploadSerializer
from .exceptions import ChunkedUploadError


class ChunkedUploadViewSet(ListModelMixin, RetrieveModelMixin, GenericViewSet):
    """
    Uploads large files in multiple chunks. Also, has the ability to resume
    if the upload is interrupted. PUT without upload ID to create an upload
    and POST to complete the upload. POST with a complete file to upload a
    whole file in one go. Method `on_completion` is a placeholder to
    define what to do when upload is complete.
    """

    # Has to be a ChunkedUpload subclass
    model = ChunkedUpload
    user_field_name = "user"  # the field name that point towards the AUTH_USER in ChunkedUpload class or its subclasses
    serializer_class = ChunkedUploadSerializer

    # I wouldn't recommend turning off the checksum check,
    # unless it is signifcantly impacting performance.
    # Proceed at your own risk.
    do_checksum_check = True

    field_name = "file"
    content_range_pattern = re.compile(
        r"^bytes (?P<start>\d+)-(?P<end>\d+)/(?P<total>\d+)$"
    )
    max_bytes = _settings.MAX_BYTES  # Max amount of data that can be uploaded

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

    async def get(self, request, *args, **kwargs):
        """
        Handle GET requests.
        """
        try:
            return await self._get(request, *args, **kwargs)
        except ChunkedUploadError as error:
            return Response(error.data, status=error.status_code)

    @method_decorator(cache_page(0))
    async def _get(self, request, pk=None, *args, **kwargs):
        if pk:
            return await self.aretrieve(request, pk=pk, *args, **kwargs)
        else:
            return await self.alist(request, *args, **kwargs)

    async def post(self, request, *args, **kwargs):
        """
        Handle POST requests.
        """
        try:
            return await self._post(request, *args, **kwargs)
        except ChunkedUploadError as error:
            return Response(error.data, status=error.status_code)

    async def _post(self, request, pk=None, *args, **kwargs) -> Response:
        chunked_upload: Optional[ChunkedUpload] = None
        if pk:
            upload_id = pk
        else:
            chunked_upload = await self._put_chunk(request, *args, whole=True, **kwargs)
            upload_id = chunked_upload.id

        checksum = request.data.get(_settings.CHECKSUM_TYPE)

        if self.do_checksum_check and not checksum:
            raise ChunkedUploadError(
                status=status.HTTP_400_BAD_REQUEST,
                detail="Checksum of type '{}' is required".format(
                    _settings.CHECKSUM_TYPE
                ),
            )

        if not chunked_upload:
            chunked_upload = cast(
                ChunkedUpload,
                await aget_object_or_404(self.get_queryset(), pk=upload_id),
            )

        self.is_valid_chunked_upload(chunked_upload)

        if self.do_checksum_check:
            await self.checksum_check(chunked_upload, checksum)

        await chunked_upload.completed()

        return await self.on_completion(chunked_upload, request)

    async def put(self, request, *args, **kwargs):
        """
        Handle PUT requests.
        """
        try:
            return await self._put(request, *args, **kwargs)
        except ChunkedUploadError as error:
            return Response(error.data, status=error.status_code)

    async def _put(self, request, *args, **kwargs):
        chunked_upload = await self._put_chunk(request, *args, **kwargs)
        return Response(
            self.serializer_class(chunked_upload, context={"request": request}).data,
            status=status.HTTP_200_OK,
        )

    async def on_completion(self, chunked_upload: ChunkedUpload, request) -> Response:
        """
        Validation or operations to run when upload is complete.
        Returns an HTTP response.
        """
        return Response(
            await self.serializer_class(
                chunked_upload, context={"request": request}
            ).adata,
            status=status.HTTP_200_OK,
        )

    def get_max_bytes(self, request):
        """
        Used to limit the max amount of data that can be uploaded. `None` means
        no limit.
        You can override this to have a custom `max_bytes`, e.g. based on
        logged user.
        """

        return self.max_bytes

    def is_valid_chunked_upload(self, chunked_upload: ChunkedUpload):
        """
        Check if chunked upload has already expired or is already complete.
        """
        if chunked_upload.expired:
            raise ChunkedUploadError(
                status=status.HTTP_410_GONE, detail="Upload has expired"
            )
        error_msg = 'Upload has already been marked as "%s"'
        if chunked_upload.status == chunked_upload.StatusChoices.COMPLETE:
            raise ChunkedUploadError(
                status=status.HTTP_400_BAD_REQUEST, detail=error_msg % "complete"
            )

    async def _put_chunk(
        self, request, pk=None, whole=False, *args, **kwargs
    ) -> ChunkedUpload:
        try:
            chunk = request.data[self.field_name]
        except KeyError:
            raise ChunkedUploadError(
                status=status.HTTP_400_BAD_REQUEST, detail="No chunk file was submitted"
            )

        if whole:
            start = 0
            total = chunk.size
            end = total - 1
        else:
            content_range = request.META.get("HTTP_CONTENT_RANGE", "")
            match = self.content_range_pattern.match(content_range)
            if not match:
                raise ChunkedUploadError(
                    status=status.HTTP_400_BAD_REQUEST,
                    detail="Error in request headers",
                )

            start = int(match.group("start"))
            end = int(match.group("end"))
            total = int(match.group("total"))

        chunk_size = end - start + 1
        max_bytes = self.get_max_bytes(request)

        if end > total:
            raise ChunkedUploadError(
                status=status.HTTP_400_BAD_REQUEST,
                detail="End of chunk exceeds reported total (%s bytes)" % total,
            )

        if max_bytes is not None and total > max_bytes:
            raise ChunkedUploadError(
                status=status.HTTP_400_BAD_REQUEST,
                detail="Size of file exceeds the limit (%s bytes)" % max_bytes,
            )

        if chunk.size != chunk_size:
            raise ChunkedUploadError(
                status=status.HTTP_400_BAD_REQUEST,
                detail="File size doesn't match headers: file size is {} but {} reported".format(
                    chunk.size,
                    chunk_size,
                ),
            )

        if pk:
            upload_id = pk
            chunked_upload = cast(
                ChunkedUpload,
                await aget_object_or_404(self.get_queryset(), pk=upload_id),
            )
            self.is_valid_chunked_upload(chunked_upload)
            if chunked_upload.offset != start:
                raise ChunkedUploadError(
                    status=status.HTTP_400_BAD_REQUEST,
                    detail="Offsets do not match",
                    expected_offset=chunked_upload.offset,
                    provided_offset=start,
                )

            await chunked_upload.append_chunk(chunk, chunk_size=chunk_size)
        else:
            kwargs = {"offset": chunk.size}

            if hasattr(self.model, self.user_field_name):
                if hasattr(request, "user") and request.user.is_authenticated:
                    kwargs[self.user_field_name] = request.user
                elif self.model._meta.get_field(self.user_field_name).null:
                    kwargs[self.user_field_name] = None
                else:
                    raise ChunkedUploadError(
                        status=status.HTTP_400_BAD_REQUEST,
                        detail="Upload requires user authentication but user cannot be determined",
                    )

            serializer = self.serializer_class(data=request.data)
            if not serializer.is_valid():
                raise ChunkedUploadError(
                    status=status.HTTP_400_BAD_REQUEST, detail=chunked_upload.errors
                )

            chunked_upload = cast(ChunkedUpload, await serializer.asave(**kwargs))

        return chunked_upload

    async def checksum_check(self, chunked_upload: ChunkedUpload, checksum: str):
        """
        Verify if checksum sent by client matches generated checksum.
        """
        if await chunked_upload.checksum() != checksum:
            raise ChunkedUploadError(
                status=status.HTTP_400_BAD_REQUEST, detail="checksum does not match"
            )
