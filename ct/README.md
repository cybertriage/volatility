# Volatility 2 for Cyber Triage

This fork builds the Volatility 2 executables, for Windows and Linux, that
Cyber Triage runs through `cybertriage_volatility` to analyze memory images.

Work happens on `master`. Upstream is
[volatilityfoundation/volatility](https://github.com/volatilityfoundation/volatility),
archived in 2025. Cyber Triage has shipped a build of upstream commit `a438e76`
(Volatility 2.6.1) as `volatility-a438e76.exe`. The only upstream commit after
it, `328a178`, adds an archival notice to `README.txt`, so the Volatility code
here is `a438e76` plus the one change below.

## What differs from upstream

- **`malfind -W` also filters JSON output.** Upstream applies `-W`
  (`--refined`: only regions that start with an MZ header or `PUSH EBP; MOV EBP,
  ESP`) to text output only. Cyber Triage runs `malfind -W --output=json`, and
  the `volatility-a438e76.exe` it shipped carried this change to
  `volatility/plugins/malware/malfind.py`, recovered from that exe. Without it,
  `malfind` reports every region the VAD filter matches.
- **Adds `.github/workflows/ct_release.yml`**, which builds the executables
  from upstream's `pyinstaller.spec` and `pyinstaller/` hooks.
- **Removes `pyinstaller/hook-distorm3.py` and `pyinstaller/hook-openpyxl.py`.**
  PyInstaller 3.6 ships its own hooks for both, which bundle the same files, and
  fails with an `AssertionError` when a hook directory has a second hook for the
  same module.
- **Pins packages** in `ct/requirements.txt` (bundled) and
  `ct/requirements-build.txt` and `ct/requirements-bootstrap.txt` (build tools).
- **Adds `ct/smoke_test.py`**, run by the workflow, and the two directories it
  uses: `ct/selftest/` and `ct/smoke_plugins/`, and `ct/install_wininst.py`
  (see below).

## Getting the executables

Do not build locally. Download a release from this repository's Releases page.
Each release has:

| File | Contents |
|---|---|
| `volatility-<tag>-windows-x64.zip` | `volatility-a438e76.exe`, a PyInstaller one-file build |
| `volatility-<tag>-linux-x86_64.tar.gz` | `volatility`, a PyInstaller one-file build |
| `SHA256SUMS` | SHA-256 of both archives |

Both archives also carry upstream's `LICENSE.txt`, `LEGAL.txt`, `AUTHORS.txt`,
`CREDITS.txt` and `README.txt`, the three requirements files, and a
`SOURCE.txt` naming the exact source commit and build.

The Windows exe keeps the name `volatility-a438e76.exe`, after the upstream
commit, because the Cyber Triage installer and `WindowsToolLayout` run it by
that name. It bundles Python 2.7.18 and its Visual C++ 2008 runtime, so it
needs nothing installed.

The Linux executable bundles Python 2.7.18 and everything else except glibc. It
is built on Debian 10, so it runs on x86-64 Linux with glibc 2.28 or later:
RHEL 8 and its rebuilds, Debian 10, and every newer distro. It does not run on
distros that use musl instead of glibc, such as Alpine. The smoke test fails
the build if anything in it needs a newer glibc.

Every push to `master` builds the same archives and keeps them as workflow
artifacts for the run. Only a tag publishes a release.

## What the executables bundle

| Package | Version | Used by |
|---|---|---|
| Python | 2.7.18 | everything |
| distorm3 | 3.3.4 | `malfind`, `apihooks` and other disassembling plugins |
| yara-python | 3.11.0 | `yarascan` |
| pycryptodome | 3.21.0 | `hashdump`, `lsadump`, `cachedump` |

distorm3 3.3.4 and yara-python 3.11.0 are the versions in the
`volatility-a438e76.exe` Cyber Triage shipped before this fork built it. On
Windows, its `distorm3.dll`, `yara.pyd`, `python27.dll` (bar the Visual C++
runtime version in its manifest) and Python extension modules are byte-for-byte
the ones in these builds, and its Volatility bytecode matches module for
module. That exe bundled pycrypto 2.6.1, which has no wheels and is
unmaintained. pycryptodome provides the same `Crypto` package for the ciphers
and hashes Volatility uses.

## How the build works around Python 2.7

Python 2.7 and its last tool releases are long past end of life, so the
workflow does the following:

- **Python on Windows.** `actions/setup-python` no longer offers 2.7. The
  workflow installs python.org's `python-2.7.18.amd64.msi`, pinned by SHA-256,
  with `ALLUSERS=1`, so its Visual C++ 2008 runtime lands in WinSxS, where
  PyInstaller finds it to bundle.
- **Python on Linux.** The build runs in the official `python:2.7.18-buster`
  image, pinned by digest. Debian moved buster to `archive.debian.org`, so the
  workflow points apt there before installing anything.
- **Last releases for Python 2.7.** PyInstaller 3.6, pip 20.3.4, setuptools
  44.1.1 and wheel 0.37.1 are the last releases that support Python 2.7, and
  pycryptodome 3.21.0 is the last with Python 2.7 wheels for both Windows x64
  and Linux x86-64. pip installs with `--no-build-isolation`, so source
  packages build with the pinned setuptools and wheel, not the latest.
- **distorm3 on Windows.** distorm3 3.3.4 has no wheel, and its source package
  needs Visual C++ 2008 to build, which Microsoft no longer distributes. Its
  PyPI Windows installer (`distorm3-3.3.4.win-amd64.exe`, pinned by SHA-256)
  carries the built `distorm3.dll`. pip cannot install it, and `wheel convert`
  rejects its egg-info file name, so `ct/install_wininst.py` copies its files
  into site-packages, where pip then finds distorm3 3.3.4 installed. On Linux,
  pip builds it from source.
- **yara-python on Linux.** yara-python has no Python 2.7 wheel for Linux, so
  pip builds 3.11.0 from source, with `--enable-dotnet` and `--enable-cuckoo`
  and against the image's OpenSSL, so it has the modules the Windows wheel has:
  `pe`, `elf`, `math`, `hash`, `dotnet`, `cuckoo` and `time`. `cuckoo` needs
  jansson, which the workflow installs from Debian.
- **No UPX.** Upstream's spec asks for UPX, but PyInstaller uses it only when
  `upx` is installed, and neither runner has it. The build log says
  `UPX is not available`.

## The smoke test

`ct/smoke_test.py` needs no memory image. It checks that:

- `--info` lists the plugins Cyber Triage runs, including `yarascan`,
  `imageinfo` and `pslist`, and that no plugin fails to import.
- `--plugins=plugins.zip` loads `autoruns` and `shimcachemem`. It zips
  `ct/smoke_plugins/` the way Cyber Triage's `plugins.zip` is laid out.
- The `ctselftest` plugin in `ct/selftest/` passes. Inside the exe, it checks
  the bundled distorm3, yara (with each of its modules) and Crypto against
  known answers, since Volatility only loads them when a plugin needs them.
- The exe bundles Python, its C runtime, distorm3 and yara, and, on Linux,
  needs no glibc newer than 2.28.

## Making a release

1. Make sure the `ct_release` workflow passes on `master`.
2. Run both executables on a Windows memory image with the plugins Cyber Triage
   uses, at least `imageinfo`, `pslist`, `connscan` or `netscan`, `dlllist`,
   `malfind` and `yarascan`, and compare their output with the release they
   replace.
3. Tag the commit `ct-<yyyymmdd>.<n>`, for example `ct-20261016.1`.
4. Push the tag. The workflow publishes the release.

Never move or reuse a tag. Cyber Triage pins a release by its SHA-256.

## Antivirus

Volatility writes out malware it finds in memory images (`procdump`,
`dlldump`, `moddump`). A new, unsigned build has no reputation with Microsoft
Defender: in testing, Defender's machine-learning detection quarantined one as
`Trojan:Win32/Bearfoos.B!ml` seconds after it dumped Duqu from a sample image.
The Cyber Triage signed installer build signs `volatility-a438e76.exe`, as it
signs `BitsParser.exe`.

## Updating a dependency

Change its pin in the requirements file that has it in its own commit, then
release.

## `ct/smoke_plugins`

Unmodified copies of the two community plugins in Cyber Triage's
`plugins.zip`, for the smoke test only. Cyber Triage ships its own
`plugins.zip`; the releases do not carry them.

| File | Source | Licence |
|---|---|---|
| `autoruns.py` | [tomchop/volatility-autoruns](https://github.com/tomchop/volatility-autoruns) at `4dd2b5cf` | GPL-2.0 |
| `shimcachemem.py` | [mandiant/Volatility-Plugins](https://github.com/mandiant/Volatility-Plugins), `shimcachemem/` at `ae8f9126` | GPL-2.0-or-later, in its header |

## Licence

GPL-2.0-or-later, the same as upstream; see `LICENSE.txt` and `LEGAL.txt`. The
executables also bundle Python (PSF License), distorm3 (BSD), yara-python
(Apache-2.0) and pycryptodome (BSD-2-Clause and public domain). The source for
every release is this repository at the commit named in its `SOURCE.txt`.
