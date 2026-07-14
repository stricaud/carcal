#!/usr/bin/env python3
"""wheel.py — wrap a bundle from packaging/build.sh into a platform wheel.

    python3 packaging/wheel.py [--bundle dist/carcal-<plat>] [--plat TAG]

carcal is a C program with no Python in it; PyPI is used purely as a binary
channel (as ruff, cmake and ninja do), so the wheel is a zip of the bundle plus
a console_scripts shim. There is no compilation here and no setuptools: a wheel
is a zip with two metadata files, and hand-writing it keeps the platform tag
under our control — the one thing setuptools makes awkward for a package that
carries a binary but builds no extension module.

The bundles are already relocatable ($ORIGIN/../lib on Linux,
@executable_path/../lib on macOS, DLLs beside the exe on Windows), which is what
makes this a repack rather than a port.
"""
import argparse
import base64
import hashlib
import os
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"

SUMMARY = "carcal — a terminal packet analyzer (a tiny Wireshark for the TUI)"
HOMEPAGE = "https://github.com/stricaud/carcal"


def version() -> str:
    """Same convention as windows-installer.sh: CARCAL_VERSION wins, because CI
    checks out shallow and `git describe` then finds no tags."""
    v = os.environ.get("CARCAL_VERSION", "")
    if not v:
        try:
            v = subprocess.run(
                ["git", "-C", str(ROOT), "describe", "--tags", "--abbrev=0"],
                capture_output=True, text=True, check=True).stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            v = ""
    v = v.lstrip("v")
    return v if re.fullmatch(r"\d+(\.\d+)*", v or "") else "0.0.0"


def macos_minos(bundle: Path) -> str:
    """Lowest macOS this bundle actually runs on: the *highest* LC_BUILD_VERSION
    minos across the binary and every dylib we ship.

    Read from the Mach-O headers rather than hardcoded, and maxed over the whole
    bundle rather than taken from bin/carcal alone, because the floor is set by
    whichever piece demands the most — in practice the Homebrew bottles, which
    are built for the runner's OS. A wheel tagged below its true floor installs
    happily and then dies at exec with a dyld error.
    """
    floor = (0, 0)
    for f in [bundle / "bin" / "carcal", *sorted((bundle / "lib").glob("*.dylib"))]:
        if not f.exists():
            continue
        try:
            out = subprocess.run(["otool", "-l", str(f)],
                                 capture_output=True, text=True, check=True).stdout
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue
        for m in re.finditer(r"^\s*minos\s+(\d+)(?:\.(\d+))?", out, re.M):
            floor = max(floor, (int(m.group(1)), int(m.group(2) or 0)))
    if floor == (0, 0):
        import platform
        parts = (platform.mac_ver()[0] or "11.0").split(".")
        floor = (int(parts[0]), int(parts[1]) if len(parts) > 1 else 0)
    return f"{floor[0]}_{floor[1]}"


def glibc_ver() -> str:
    """manylinux floor, from the glibc we linked against on this runner."""
    try:
        v = os.confstr("CS_GNU_LIBC_VERSION") or ""       # "glibc 2.35"
        maj, _, minor = v.split()[-1].partition(".")
        return f"{maj}_{minor}"
    except (ValueError, OSError):
        return "2_28"


def detect_plat(bundle: Path) -> str:
    name = bundle.name
    arch = name.rsplit("-", 1)[-1]
    if "-windows-" in name:
        return {"x86_64": "win_amd64", "i686": "win32"}.get(arch, "win_amd64")
    if "-macos-" in name:
        return f"macosx_{macos_minos(bundle)}_{arch}"
    if "-linux-" in name:
        return f"manylinux_{glibc_ver()}_{arch}"
    raise SystemExit(f"cannot infer a platform tag from {name!r}; pass --plat")


def latest_bundle() -> Path:
    # Matched by name, not just "any directory": dist/ also holds pkgroot/ and
    # pkgscripts/ from the .pkg build, and picking one of those would produce a
    # wheel that installs nothing.
    cands = [p for p in DIST.glob("carcal-*")
             if p.is_dir() and re.fullmatch(r"carcal-(linux|macos|windows)-\w+", p.name)]
    if not cands:
        raise SystemExit("no bundle in dist/ — run packaging/build.sh first")
    return max(cands, key=lambda p: p.stat().st_mtime)


# The shim. It replaces the bundle's shell launcher, and does the same job more
# reliably: Python always knows where it was installed, so it can point carcal at
# the protos/ and grammars/ that shipped with it (see protos_dir() in
# src/main.c — outside Windows, carcal has no exe-relative fallback and would
# otherwise read the compile-time default, a CI path that means nothing here).
MAIN_PY = '''\
"""Entry point for the `carcal` console script."""
import os
import sys
from pathlib import Path

_BUNDLE = Path(__file__).resolve().parent / "_bundle"


def _layout():
    """(executable, protos, grammars) — the Windows bundle is flat, the others
    are bin/ + lib/ + share/."""
    win = _BUNDLE / "carcal.exe"
    if win.exists():
        return win, _BUNDLE / "protos", _BUNDLE / "grammars"
    share = _BUNDLE / "share" / "carcal"
    return _BUNDLE / "bin" / "carcal", share / "protos", share / "grammars"


def main() -> int:
    exe, protos, grammars = _layout()
    if not exe.exists():
        sys.exit(f"carcal: bundled binary is missing from {_BUNDLE} "
                 f"(broken install — try reinstalling)")

    env = dict(os.environ)
    # setdefault, not assignment: an explicit CARCAL_PROTOS_DIR is how a user
    # points carcal at their own .posa decoders, and it must still win.
    env.setdefault("CARCAL_PROTOS_DIR", str(protos))
    env.setdefault("CARCAL_GRAMMARS_DIR", str(grammars))

    argv = [str(exe), *sys.argv[1:]]
    if os.name == "nt":
        # execve on Windows returns control to the shell immediately, which
        # would hand a live TUI a prompt it is fighting for; spawn and wait.
        import subprocess
        return subprocess.run(argv, env=env).returncode
    os.execve(exe, argv, env)   # no return


if __name__ == "__main__":
    sys.exit(main())
'''

INIT_PY = '"""carcal — a terminal packet analyzer. See `carcal --help`."""\n'


def readme() -> str:
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    # The README leads with a screenshot committed to the repo; a relative image
    # link renders as a broken image on PyPI, so point it at the raw file.
    return text.replace(
        "](carcalui.png)",
        "](https://raw.githubusercontent.com/stricaud/carcal/main/carcalui.png)")


def build(bundle: Path, plat: str, ver: str) -> Path:
    dist_info = f"carcal-{ver}.dist-info"
    records: list[tuple[str, str, int]] = []
    out = DIST / f"carcal-{ver}-py3-none-{plat}.whl"

    def add(zf: zipfile.ZipFile, arcname: str, data: bytes, mode: int = 0o644):
        info = zipfile.ZipInfo(arcname, date_time=(1980, 1, 1, 0, 0, 0))
        # S_IFREG matters: pip only carries the exec bit across an install for
        # entries whose external_attr passes stat.S_ISREG, so permission bits
        # alone leave bin/carcal non-executable and the install dead on arrival.
        info.external_attr = ((stat.S_IFREG | mode) & 0xFFFF) << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, data)
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
        records.append((arcname, f"sha256={digest.decode()}", len(data)))

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        add(zf, "carcal/__init__.py", INIT_PY.encode())
        add(zf, "carcal/__main__.py", MAIN_PY.encode())

        # The bundle, verbatim — minus the shell launcher at its root, which the
        # console script replaces. Source modes are preserved: lose the exec bit
        # on bin/carcal and the wheel installs fine and then cannot run.
        for path in sorted(bundle.rglob("*")):
            if path.is_dir() or path.is_symlink():
                continue
            rel = path.relative_to(bundle)
            if rel.as_posix() in ("carcal", "README.txt"):
                continue
            mode = path.stat().st_mode & 0o777
            add(zf, f"carcal/_bundle/{rel.as_posix()}", path.read_bytes(), mode)

        metadata = "\n".join([
            "Metadata-Version: 2.1",
            "Name: carcal",
            f"Version: {ver}",
            f"Summary: {SUMMARY}",
            f"Home-page: {HOMEPAGE}",
            "License: MIT",
            "Classifier: Development Status :: 4 - Beta",
            "Classifier: Environment :: Console :: Curses",
            "Classifier: License :: OSI Approved :: MIT License",
            "Classifier: Programming Language :: C",
            "Classifier: Topic :: System :: Networking :: Monitoring",
            "Requires-Python: >=3.8",
            "Description-Content-Type: text/markdown",
            "",
            readme(),
        ])
        add(zf, f"{dist_info}/METADATA", metadata.encode())
        add(zf, f"{dist_info}/WHEEL", "\n".join([
            "Wheel-Version: 1.0",
            "Generator: carcal packaging/wheel.py",
            # false — the payload is a native binary, so it must land in platlib
            # and the wheel must never be treated as cross-platform.
            "Root-Is-Purelib: false",
            f"Tag: py3-none-{plat}",
            "",
        ]).encode())
        add(zf, f"{dist_info}/entry_points.txt",
            "[console_scripts]\ncarcal = carcal.__main__:main\n".encode())
        add(zf, f"{dist_info}/licenses/LICENSE",
            (ROOT / "LICENSE").read_bytes())

        lines = [f"{n},{h},{s}" for n, h, s in records]
        lines.append(f"{dist_info}/RECORD,,")           # RECORD cannot hash itself
        info = zipfile.ZipInfo(f"{dist_info}/RECORD", date_time=(1980, 1, 1, 0, 0, 0))
        info.external_attr = 0o644 << 16
        zf.writestr(info, "\n".join(lines) + "\n")

    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--bundle", type=Path,
                    help="dist/carcal-<plat>/ (default: most recent)")
    ap.add_argument("--plat", help="wheel platform tag (default: inferred)")
    args = ap.parse_args()

    bundle = args.bundle or latest_bundle()
    if not bundle.is_dir():
        raise SystemExit(f"not a bundle directory: {bundle}")
    plat = args.plat or detect_plat(bundle)
    ver = version()

    out = build(bundle, plat, ver)
    print(f"==> {out}")
    if ver == "0.0.0":
        print("    (version 0.0.0 — set CARCAL_VERSION or tag the repo)",
              file=sys.stderr)


if __name__ == "__main__":
    main()
