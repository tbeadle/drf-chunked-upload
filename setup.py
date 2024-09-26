#!/usr/bin/env python
import os
from setuptools import setup, find_packages

ROOT = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
    readme = f.read()

version = os.environ.get("DCU_VERSION", "0.0.0")


setup(
    name="adrf-chunked-upload",
    packages=find_packages("src"),
    package_dir={"": "src"},
    version=version,
    description=(
        "Upload large files to Django REST Framework in multiple chunks,"
        " with the ability to resume if the upload is interrupted. Use async Django."
    ),
    long_description=readme,
    long_description_content_type="text/markdown",
    author="Tommy Beadle",
    author_email="tbeadle@gmail.com",
    url="https://github.com/tbeadle/adrf-chunked-upload",
    install_requires=[
        "Django>=4.1",
        "djangorestframework>=3.14.0",
        "adrf>=0.1.7",
        "aiofiles>=24.1.0",
    ],
    python_requires=">3.8",
    license="MIT-Zero",
)
