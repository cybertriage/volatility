#!/usr/bin/env python
"""Smoke test for the Cyber Triage build of Volatility 2.

Usage: smoke_test.py <volatility.exe or volatility> <plugins.zip>

Run it with the Python 2.7 that has PyInstaller installed, on the platform the
executable was built for, with the plugins.zip the release carries.

Needs no memory image. Before pinning a new release in Cyber Triage, run it on
a memory image against the release it replaces; see ct/README.md.
"""

from __future__ import print_function

import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import zipfile

from PyInstaller.archive.readers import CArchiveReader

CT = os.path.dirname(os.path.abspath(__file__))

# The Volatility plugins Cyber Triage runs, in cybertriage_volatility.
PLUGINS = (
    "imageinfo", "kdbgscan", "pslist", "dlllist", "dlldump", "cmdline", "connscan", "sockscan",
    "netscan", "malfind", "modules", "moddump", "procdump", "svcscan", "getsids", "userassist",
    "yarascan",
)

# The community plugins Cyber Triage passes in plugins.zip, with --plugins.
COMMUNITY_PLUGINS = ("autoruns", "shimcachemem")

# The layout and files of the plugins.zip Cyber Triage shipped before this fork built it.
PLUGINS_ZIP_LAYOUT = ["plugins/", "plugins/autoruns.py", "plugins/shimcachemem.py", "plugins/__init__.py"]
PLUGINS_ZIP_SHA256 = {
    "plugins/autoruns.py": "a94d3b798e830919aefd54d10b74568cda1dba97760d74e42021e690e54a53e8",
    "plugins/shimcachemem.py": "8560472529be1d2af6076d280a9ce3855998608753bab3ace02de2a2f9e61b38",
    "plugins/__init__.py": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}

# Bundled by PyInstaller, so the executable needs nothing installed on the machine.
if sys.platform == "win32":
    BUNDLED = ("python27.dll", "msvcr90.dll", "distorm3.dll", "yara.pyd")
else:
    # Everything but glibc, which every mainstream Linux has.
    BUNDLED = ("libpython2.7.so", "libdistorm3.so", "yara.so")

# The Linux executable must run on glibc 2.28 (RHEL 8, Debian 10), the oldest of any Linux still in support.
OLDEST_GLIBC = (2, 28)

TYPECODE_BINARY = "b"


def run(arguments, timeout=600):
    """Runs a command and returns its exit code and combined output."""
    process = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    timer = threading.Timer(timeout, process.kill)
    timer.start()
    try:
        output = process.communicate()[0]
    finally:
        timer.cancel()
    # Python 2 on Windows writes \r\n to a pipe.
    return process.returncode, output.decode("utf-8", "replace").replace("\r\n", "\n")


def listed_plugins(output):
    """Returns the plugin names in the Plugins section of --info output."""
    lines = output.split("\n")
    names = set()
    section = None
    for index, line in enumerate(lines):
        if line and index + 1 < len(lines) and lines[index + 1] == "-" * len(line):
            section = line
        elif section == "Plugins":
            match = re.match(r"(\w+)\s+- ", line)
            if match:
                names.add(match.group(1))
    return names


def import_failures(output):
    return re.findall(r"^\*\*\* Failed to import .*$", output, re.MULTILINE)


def glibc_needed(path):
    """Returns the newest glibc symbol version an ELF file needs, or None."""
    exit_code, output = run(["objdump", "-p", path])
    if exit_code != 0:
        raise RuntimeError("objdump -p {0} exited with {1}: {2}".format(path, exit_code, output))
    versions = re.findall(r"\bGLIBC_(\d+(?:\.\d+)+)", output)
    return max([tuple(int(part) for part in version.split(".")) for version in versions] or [None])


def glibc_needed_by(exe, archive):
    """Returns the newest glibc version the executable and each binary it bundles need."""
    needed = {os.path.basename(exe): glibc_needed(exe)}
    directory = tempfile.mkdtemp()
    try:
        path = os.path.join(directory, "binary")
        for index, entry in enumerate(archive.toc.data):
            name, typecode = entry[5], entry[4]
            if typecode == TYPECODE_BINARY:
                with open(path, "wb") as file_object:
                    file_object.write(archive.extract(index)[1])
                needed[name] = glibc_needed(path)
    finally:
        shutil.rmtree(directory)
    return needed


def dotted(version):
    return ".".join(str(part) for part in version) if version else "none"


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2

    exe = os.path.abspath(sys.argv[1])
    plugins_zip = os.path.abspath(sys.argv[2])
    failures = []

    zip_file = zipfile.ZipFile(plugins_zip)
    try:
        layout = zip_file.namelist()
        changed = sorted(name for name, digest in PLUGINS_ZIP_SHA256.items()
                         if name not in layout or hashlib.sha256(zip_file.read(name)).hexdigest() != digest)
    finally:
        zip_file.close()
    print("plugins.zip: {0}, changed {1}".format(layout, changed))
    if layout != PLUGINS_ZIP_LAYOUT or changed:
        failures.append("plugins.zip holds {0} with {1} changed, expected {2} as shipped".format(
            layout, changed, PLUGINS_ZIP_LAYOUT))

    exit_code, output = run([exe, "--info"])
    listed = listed_plugins(output)
    missing = [name for name in PLUGINS if name not in listed]
    failed = import_failures(output)
    print("--info: exit code {0}, {1} plugins, missing {2}, import failures {3}".format(
        exit_code, len(listed), missing, failed))
    if exit_code != 0 or missing or failed:
        failures.append("--info exited with {0}, does not list {1} or failed imports {2}".format(exit_code, missing, failed))

    directory = tempfile.mkdtemp()
    try:
        # As Cyber Triage passes plugins.zip, in AutorunsCommand and ShimcachememCommand.
        exit_code, output = run([exe, "--plugins=" + plugins_zip, "--info"])
        listed = listed_plugins(output)
        missing = [name for name in COMMUNITY_PLUGINS if name not in listed]
        failed = import_failures(output)
        print("--plugins=plugins.zip --info: exit code {0}, missing {1}, import failures {2}".format(
            exit_code, missing, failed))
        if exit_code != 0 or missing or failed:
            failures.append("--plugins=plugins.zip --info exited with {0}, does not list {1} or failed imports {2}".format(
                exit_code, missing, failed))

        # Volatility wants an image to run a plugin, though ctselftest never reads it.
        image = os.path.join(directory, "zeros.raw")
        with open(image, "wb") as file_object:
            file_object.write(b"\0" * 4096)
        exit_code, output = run([exe, "--plugins=" + os.path.join(CT, "selftest"), "-f", image, "ctselftest"])
        results = re.findall(r"^(.+): (ok|FAIL) \((.*)\)$", output, re.MULTILINE)
        print("ctselftest: exit code {0}".format(exit_code))
        for name, status, detail in results:
            print("  {0}: {1} ({2})".format(name, status, detail))
        bad = [name for name, status, _ in results if status != "ok"]
        if exit_code != 0 or len(results) != 16 or bad:
            failures.append("ctselftest exited with {0}, gave {1} of 16 results, failed {2}: {3}".format(
                exit_code, len(results), bad, output[-2000:]))
    finally:
        shutil.rmtree(directory)

    archive = CArchiveReader(exe)
    names = [entry[5].lower() for entry in archive.toc.data]
    missing = [name for name in BUNDLED if not any(name in entry for entry in names)]
    print("archive: {0} entries, missing {1}".format(len(names), missing))
    if missing:
        failures.append("the executable does not bundle {0}".format(missing))

    if sys.platform.startswith("linux"):
        needed = glibc_needed_by(exe, archive)
        newest = max([version for version in needed.values() if version] or [None])
        too_new = sorted(
            "{0} ({1})".format(name, dotted(version)) for name, version in needed.items() if version and version > OLDEST_GLIBC
        )
        print("glibc: newest needed {0}, allowed {1}, too new {2}".format(dotted(newest), dotted(OLDEST_GLIBC), too_new))
        if newest is None:
            failures.append("objdump found no glibc versions, so the glibc check did not run")
        elif too_new:
            failures.append("these need a glibc newer than {0}: {1}".format(dotted(OLDEST_GLIBC), too_new))

    for failure in failures:
        print("FAIL: {0}".format(failure))
    if not failures:
        print("PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
