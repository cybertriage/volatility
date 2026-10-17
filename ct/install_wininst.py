#!/usr/bin/env python
"""Installs a pure-Python bdist_wininst installer into this Python's site-packages.

Usage: install_wininst.py <installer.exe>

A bdist_wininst installer is a zip after an exe stub. Its PURELIB folder holds the
files for site-packages, including the egg-info that pip and pkg_resources
recognise as the installed distribution. The workflow uses it for distorm3,
whose PyPI Windows installer carries the built distorm3.dll; pip cannot install
it, and `wheel convert` rejects its egg-info file name.
"""

from __future__ import print_function

import os
import sys
import zipfile
from distutils.sysconfig import get_python_lib

PREFIX = "PURELIB/"


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    site_packages = get_python_lib()
    installer = zipfile.ZipFile(sys.argv[1])
    try:
        others = [name for name in installer.namelist() if not name.startswith(PREFIX)]
        if others:
            print("not a pure-Python installer, it also has {0}".format(others))
            return 1
        for info in installer.infolist():
            if info.filename.endswith("/"):
                continue
            target = os.path.join(site_packages, *info.filename[len(PREFIX):].split("/"))
            if not os.path.isdir(os.path.dirname(target)):
                os.makedirs(os.path.dirname(target))
            with open(target, "wb") as file_object:
                file_object.write(installer.read(info))
            print("installed {0}".format(target))
    finally:
        installer.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
