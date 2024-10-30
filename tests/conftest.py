from django.conf import settings


def pytest_configure():
    settings.configure(
        DEBUG=True,
        DEBUG_PROPAGATE_EXCEPTIONS=True,
        DATABASES={
            "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"},
        },
        SITE_ID=1,
        SECRET_KEY="secret key",
        STATIC_URL="/static/",
        ROOT_URLCONF="adrf_chunked_upload.urls",
        MIDDLEWARE=(
            "django.middleware.common.CommonMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "django.contrib.messages.middleware.MessageMiddleware",
        ),
        INSTALLED_APPS=(
            "django.contrib.admin",
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "django.contrib.sessions",
            "django.contrib.sites",
            "rest_framework",
            "adrf_chunked_upload",
        ),
        DATETIME_FORMAT="Y-m-d H:i:s",
        TIME_ZONE="UTC",
        # our settings
        ADRF_CHUNKED_UPLOAD_MAX_BYTES=1000000,
    )
