from adrf import serializers as adrf_serializers

# from rest_framework.reverse import reverse
# from rest_framework.serializers import SerializerMethodField

from . import settings as _settings
from .models import ChunkedUpload


class ChunkedUploadSerializer(adrf_serializers.ModelSerializer):
    # viewname = f"{_settings.URL_BASENAME}-detail"
    # url = SerializerMethodField()

    # def get_url(self, obj):
    #     return reverse(
    #         self.viewname, kwargs={"pk": obj.id}, request=self.context["request"]
    #     )

    class Meta:
        model = ChunkedUpload
        fields = "__all__"
        read_only_fields = ("status", "completed_at")
        extra_kwargs = {
            "file": {"write_only": not _settings.INCLUDE_FILE_URL_IN_RESPONSE}
        }
