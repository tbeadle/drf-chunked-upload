DEBUG = True

SECRET_KEY = "migration key"

INSTALLED_APPS = (
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
    "adrf",
    "adrf_chunked_upload",
)

ADRF_CHUNKED_UPLOAD_ABSTRACT_MODEL = False
