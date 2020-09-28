#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  VULNERS OPENSOURCE
#  __________________
#
#  Vulners Project [https://vulners.com]
#  All Rights Reserved.
#
__author__ = "Kir Ermakov <isox@vulners.com>"

import re
from setuptools import setup

version = re.search(r'__version__\s*=\s*"(.+)"', open('mikrot8over/mikrot8over.py', 'rt').read()).group(1)


long_description = '''
mikrot8over
=========

Command line Mikrotik exploitation tool.
It's using Mikrotik exploit from Vault 7 CIA Leaks automation tool
Takeovers up to RouterOS 6.38.4.
'''

setup(
    name='mikrot8over',
    packages=['mikrot8over'],
    version=version,
    description='Command line Mikrotik exploitation tool for RouterOS up to 6.38.4',
    long_description=long_description,
    long_description_content_type="text/plain",
    license='MIT',
    url='https://github.com/vulnersCom/mikrot8over',
    author='Kir Ermakov',
    author_email='isox@vulners.com',
    maintainer="Kir Ermakov",
    entry_points={
        'console_scripts': [
            'mikrot8over = mikrot8over.mikrot8over:main',
        ]
    },
    install_requires = [
            'six',
            'texttable',
            'tqdm',
            'futures',
            'ipcalc',
        ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Topic :: Security",
    ]
)
