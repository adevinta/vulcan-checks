#!/usr/bin/env python3

from setuptools import setup, find_packages
setup(
    name='httpobs',
    packages=find_packages(),
    include_package_data=True,
    scripts=['httpobs/scripts/httpobs-local-scan'],
)
