#!/usr/bin/env python3 

from setuptools import setup, find_packages

setup(
    name="odoh-sdk",
    version="1.0",
    packages=find_packages(),
    include_package_data=True,
    license="MIT",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    entry_points={
        "console_scripts": [
            "odoh_sdk = odoh_sdk.query_cli:main",
        ],
    },
    install_requires=[],
    python_requires=">=3.6",
)