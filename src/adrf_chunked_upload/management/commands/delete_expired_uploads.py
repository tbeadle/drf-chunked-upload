import asyncio
import django.apps
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.utils.translation import gettext as _

from adrf_chunked_upload import settings as _settings
from adrf_chunked_upload.models import AbstractChunkedUpload


PROMPT_MSG = _("Do you want to delete {obj}?")
VALID_RESP = {"yes": True, "y": True, "ye": True, "no": False, "n": False}


class Command(BaseCommand):

    # Has to be an AbstractChunkedUpload subclass
    base_model = AbstractChunkedUpload

    help = "Deletes incomplete chunked uploads that have expired."

    def add_arguments(self, parser):
        parser.add_argument(
            "models",
            metavar="app.model",
            nargs="*",
            help="Any app.model classes you want to clean up. "
            "Default is all AbstractChunkedUpload subclasses within a project.",
        )
        parser.add_argument(
            "-i",
            "--interactive",
            action="store_true",
            dest="interactive",
            default=False,
            help="Prompt for confirmation before each deletion.",
        )
        parser.add_argument(
            "-k",
            "--keep-record",
            action="store_false",
            dest="delete_record",
            default=True,
            help="Don't delete upload records, just uploaded files on disk.",
        )

    def handle(self, *args, **options):
        asyncio.run(self.ahandle(options))

    async def ahandle(self, options):
        filter_models = options.get("models", None)
        interactive = options.get("interactive", False)
        delete_record = options.get("delete_record", True)

        upload_models = self.get_models(filter_models=filter_models)

        for model in upload_models:
            await self.process_model(
                model, interactive=interactive, delete_record=delete_record
            )

    def _get_filter_model(self, model):
        model_app, model_name = model.split(".")
        try:
            model_cls = django.apps.apps.get_app_config(model_app).get_model(model_name)
        except LookupError as e:
            print("WARNING: {}".format(e))
        else:
            if issubclass(model_cls, self.base_model):
                return model_cls
            print(
                "WARNING: Model {} is not a subclass of AbstractChunkedUpload and will be skipped.".format(
                    model
                )
            )
            return None

    def get_models(self, filter_models=None):
        upload_models = []

        if filter_models:
            # the models were specified and
            # we want to process only them
            for model in filter_models:
                model = self._get_filter_model(model)
                if model:
                    upload_models.append(model)
        else:
            # no models were specified and we want
            # to find all AbstractChunkedUpload classes
            upload_models = [
                m
                for m in django.apps.apps.get_models()
                if issubclass(m, self.base_model)
            ]

        return upload_models

    async def process_model(self, model, interactive=False, delete_record=True):
        print(
            "Processing uploads for model {}.{}...".format(
                model._meta.app_label,
                model.__name__,
            )
        )

        chunked_uploads = model.objects.filter(
            created_at__lt=(timezone.now() - _settings.EXPIRATION_DELTA),
            completed_at=None,
        )

        async for chunked_upload in chunked_uploads:
            if interactive and not self.get_confirmation(chunked_upload):
                continue

            # Deleting objects individually to call delete method explicitly
            if delete_record:
                await chunked_upload.adelete()
            else:
                await chunked_upload.adelete_file()
                await chunked_upload.asave()

        print(
            "{} upload{}s were deleted.".format(
                len(chunked_uploads),
                (" file" if not delete_record else ""),
            )
        )

    def get_confirmation(self, chunked_upload):
        prompt = PROMPT_MSG.format(obj=chunked_upload) + " (y/n): "

        while True not in ("y", "n"):
            answer = VALID_RESP.get(input(prompt).lower(), None)
            if answer is not None:
                return answer
