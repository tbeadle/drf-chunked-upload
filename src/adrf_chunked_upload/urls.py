from rest_framework.urls import path

from . import views

urlpatterns = [
    path(
        "<uuid:pk>/",
        views.ChunkedUploadDetailView.as_view(),
        name="chunkedupload-detail",
    ),
    path(
        "",
        views.ChunkedUploadListView.as_view(),
        name="chunkedupload-list",
    ),
]
