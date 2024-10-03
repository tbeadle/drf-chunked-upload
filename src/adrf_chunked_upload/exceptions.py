"""
Exceptions raised by django-chunked-upload.
"""

from rest_framework import exceptions, status


class ChunkedUploadError(exceptions.APIException):
    """
    Exception raised if errors in the request/process.
    """

    def __init__(self, detail, code=None, status_code=status.HTTP_400_BAD_REQUEST):
        super().__init__(detail=detail, code=code)
        self.status_code = status_code
