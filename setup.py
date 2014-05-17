#!/usr/bin/env python
import sys
from setuptools import setup

extra_options = dict(
    name="Loxodo",
    version="1.1",
    description="CLI and web password manager. With v3 passwordsafe compatible DB.",
    license = 'GPLv2',
    author_email = 'haaaad@gmail.com',
    author = "Christoph Sommer & Adam Hamsik ",
    url = 'https://github.com/haad/loxodo',
    include_package_data=True,
    app = ['loxodo.py', 'web-loxodo.py'],
    scripts = ['loxodo.py', 'web-loxodo.py'],
    packages = ['Loxodo', 'Loxodo/db', 'Loxodo/twofish', 'Loxodo/frontends', 'Loxodo/frontends/cmdline', 'Loxodo/frontends/web']
)
setup(**extra_options)


