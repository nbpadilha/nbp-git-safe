# SPDX-License-Identifier: MIT
"""Package gate for CI and for releases: inspects the built wheel and sdist in a directory.

Checks the metadata (name, version equal to ``__version__``, licence, classifiers, project URLs,
README as the description, ``requires-python``), that the wheel carries the package and the entry
point, and that neither file carries anything that must not be published (internal plan, upstream
test suite, CI files, lockfile, caches, key or environment files). Prints file names and findings
only.

Run from the repository root after ``uv build``: ``python scripts/check_package.py [dist]``.
"""

from __future__ import annotations

import email
import re
import sys
import tarfile
import zipfile
from email.message import Message
from pathlib import Path

NAME = "nbp-git-safe"
FORBIDDEN = re.compile(
    r"(^|/)(PLAN-SPEC\.md|uv\.lock|\.github|\.claude|\.venv|__pycache__|upstream-tests|"
    r"upstream-transcrypt-CHANGELOG\.md|\.env[^/]*|[^/]*\.pem|[^/]*\.key|sa[^/]*\.json|"
    r"\.coverage[^/]*)(/|$)|\.py[co]$"
)
REQUIRED_SDIST = ("pyproject.toml", "README.md", "LICENSE", "NOTICE", "src/nbp_git_safe/cli.py")
REQUIRED_WHEEL = ("nbp_git_safe/__init__.py", "nbp_git_safe/cli.py", "nbp_git_safe/crypto.py")
EXPECTED_URLS = {"Homepage", "Repository", "Issues", "Changelog", "Security"}


def _metadata(text: str) -> Message:
    return email.message_from_string(text)


def check_metadata(meta: Message, version: str, readme: str) -> list[str]:
    problems: list[str] = []
    if meta["Name"] != NAME:
        problems.append(f"Name is {meta['Name']!r}")
    if meta["Version"] != version:
        problems.append(f"Version is {meta['Version']!r}, __version__ is {version!r}")
    if meta["License-Expression"] != "MIT":
        problems.append("License-Expression is not MIT")
    if not (meta["Summary"] or "").strip():
        problems.append("empty Summary")
    if meta["Requires-Python"] != ">=3.11":
        problems.append(f"Requires-Python is {meta['Requires-Python']!r}")
    if meta["Description-Content-Type"] != "text/markdown":
        problems.append("the description is not text/markdown")
    body = meta.get_payload()
    body = body if isinstance(body, str) else ""
    if body.replace("\r\n", "\n").strip() != readme.replace("\r\n", "\n").strip():
        problems.append("the long description is not README.md")
    classifiers = meta.get_all("Classifier") or []
    for needed in (
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security :: Cryptography",
        "Operating System :: Microsoft :: Windows",
    ):
        if needed not in classifiers:
            problems.append(f"missing classifier {needed!r}")
    if any(c.startswith("License ::") for c in classifiers):
        problems.append("a 'License ::' classifier next to License-Expression (deprecated)")
    urls = {u.split(",", 1)[0].strip() for u in (meta.get_all("Project-URL") or [])}
    if not urls >= EXPECTED_URLS:
        problems.append(f"missing Project-URL entries: {sorted(EXPECTED_URLS - urls)}")
    if not meta["Keywords"]:
        problems.append("no keywords")
    requires = meta.get_all("Requires-Dist") or []
    if [r for r in requires if not re.fullmatch(r"[A-Za-z0-9_.-]+==[0-9][^;\s]*", r)]:
        problems.append("a runtime dependency is not pinned with ==")
    return problems


def check_wheel(path: Path, version: str, readme: str) -> list[str]:
    problems: list[str] = []
    with zipfile.ZipFile(path) as wheel:
        names = wheel.namelist()
        for name in names:
            if FORBIDDEN.search(name):
                problems.append(f"{path.name}: must not be published: {name}")
        for needed in REQUIRED_WHEEL:
            if needed not in names:
                problems.append(f"{path.name}: missing {needed}")
        dist_info = f"nbp_git_safe-{version}.dist-info"
        meta_name = f"{dist_info}/METADATA"
        if meta_name not in names:
            return [*problems, f"{path.name}: no {meta_name}"]
        problems += [
            f"{path.name}: {p}"
            for p in check_metadata(
                _metadata(wheel.read(meta_name).decode("utf-8")), version, readme
            )
        ]
        entry = wheel.read(f"{dist_info}/entry_points.txt").decode("utf-8")
        if "nbp-git-safe = nbp_git_safe.cli:console" not in entry:
            problems.append(f"{path.name}: the console entry point is missing")
        for licence in ("LICENSE", "NOTICE"):
            if f"{dist_info}/licenses/{licence}" not in names:
                problems.append(f"{path.name}: {licence} is not in the wheel")
        if any(not n.startswith(("nbp_git_safe/", dist_info + "/")) for n in names):
            problems.append(f"{path.name}: files outside the package and its dist-info")
    return problems


def check_sdist(path: Path, version: str, readme: str) -> list[str]:
    problems: list[str] = []
    prefix = f"nbp_git_safe-{version}/"
    with tarfile.open(path) as sdist:
        names = sdist.getnames()
        for name in names:
            if not name.startswith(prefix):
                problems.append(f"{path.name}: {name} is outside {prefix}")
            elif FORBIDDEN.search(name[len(prefix) :]):
                problems.append(f"{path.name}: must not be published: {name}")
        for needed in REQUIRED_SDIST:
            if prefix + needed not in names:
                problems.append(f"{path.name}: missing {needed}")
        member = sdist.extractfile(prefix + "PKG-INFO")
        if member is None:
            return [*problems, f"{path.name}: no PKG-INFO"]
        meta = _metadata(member.read().decode("utf-8"))
        problems += [f"{path.name}: {p}" for p in check_metadata(meta, version, readme)]
    return problems


def main(argv: list[str]) -> int:
    root = Path.cwd()
    dist = Path(argv[0]) if argv else root / "dist"
    sys.path.insert(0, str(root / "src"))
    from nbp_git_safe import __version__

    readme = (root / "README.md").read_text(encoding="utf-8")
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    problems: list[str] = []
    if len(wheels) != 1 or len(sdists) != 1:
        problems.append(f"expected exactly one wheel and one sdist in {dist}")
    else:
        problems += check_wheel(wheels[0], __version__, readme)
        problems += check_sdist(sdists[0], __version__, readme)
    for problem in problems:
        print(f"check_package: {problem}")
    if problems:
        return 1
    print(f"check_package: ok ({wheels[0].name}, {sdists[0].name})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
