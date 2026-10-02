# SPDX-License-Identifier: MIT
"""Command-line entry point (minimal in phase 1: prints the version)."""

from __future__ import annotations

from nbp_git_safe import __version__


def main() -> int:
    print(f"nbp-git-safe {__version__}")
    return 0
