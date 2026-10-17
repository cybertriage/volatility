#!/usr/bin/env python
"""Builds plugins.zip, the community Volatility plugins Cyber Triage passes with --plugins.

Usage: make_plugins_zip.py <plugins.zip>

Lays it out like the plugins.zip Cyber Triage shipped before this fork built it:
a top-level plugins/ folder holding autoruns.py, shimcachemem.py and __init__.py,
from ct/smoke_plugins. Timestamps and attributes are fixed, so every build of the
same files writes the same bytes.
"""

from __future__ import print_function

import os
import sys
import zipfile

SOURCE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "smoke_plugins")

# In the order of the plugins.zip Cyber Triage shipped.
FILES = ("autoruns.py", "shimcachemem.py", "__init__.py")

# The earliest time a zip can hold.
TIMESTAMP = (1980, 1, 1, 0, 0, 0)

UNIX = 3
MSDOS_DIRECTORY = 0x10


def entry(name, mode):
    info = zipfile.ZipInfo(name, TIMESTAMP)
    info.create_system = UNIX
    info.external_attr = mode << 16
    return info


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    archive = zipfile.ZipFile(sys.argv[1], "w")
    try:
        folder = entry("plugins/", 0o40755)
        folder.external_attr |= MSDOS_DIRECTORY
        archive.writestr(folder, b"")
        for name in FILES:
            info = entry("plugins/" + name, 0o100644)
            info.compress_type = zipfile.ZIP_DEFLATED
            with open(os.path.join(SOURCE, name), "rb") as file_object:
                archive.writestr(info, file_object.read())
    finally:
        archive.close()
    print("wrote {0}".format(sys.argv[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
