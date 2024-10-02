from adrf import serializers as adrf_serializers
from rest_framework import fields, serializers


from . import settings as _settings
from .models import ChunkedUpload


class UploadResponseSerializer(adrf_serializers.ModelSerializer):
    expires_at = serializers.DateTimeField()

    class Meta:
        model = ChunkedUpload
        fields = [
            "id",
            "url",
            "filename",
            "offset",
            "created_at",
            "completed_at",
            "user",
            "expires_at",
        ]


class ChunkedUploadSerializer(adrf_serializers.ModelSerializer):
    class Meta:
        model = ChunkedUpload
        fields = [
            "file",
        ]


class ChecksumFieldMixin:
    def get_fields(self):
        retval = super().get_fields()
        retval[_settings.CHECKSUM_TYPE] = fields.CharField(
            required=True, allow_blank=False
        )
        return retval


class CompleteUploadSerializer(ChecksumFieldMixin, ChunkedUploadSerializer):
    pass


class FinishUploadSerializer(ChecksumFieldMixin, adrf_serializers.Serializer):
    pass
