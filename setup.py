import sys
from setuptools import setup

assert sys.version_info.major == 3 and sys.version_info.minor >= 7, \
    "The CybORG repo is designed to work with Python 3.7 and greater." \
    + "Please install it before proceeding."

with open('Requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name="CybORG",
    version="0.1",
    install_requires=requirements,
    description="A Cyber Security Research Environment",
)
