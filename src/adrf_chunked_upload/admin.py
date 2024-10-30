from django.contrib import admin

from adrf_chunked_upload.models import ChunkedUpload
from adrf_chunked_upload import settings as _settings

if not _settings.ABSTRACT_MODEL:  # If the model exists

    class ChunkedUploadAdmin(admin.ModelAdmin):
        list_display = ("id", "filename", "user", "created_at")
        search_fields = ("filename",)
        list_filter = ()

    admin.site.register(ChunkedUpload, ChunkedUploadAdmin)
