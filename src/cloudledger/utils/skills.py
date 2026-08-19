"""
Locate the skills package shipped with CloudLedger.

Installed distributions carry the skills inside the package as
``cloudledger/skills`` (a hatchling force-include of the repository's
``skills/`` directory). Editable and source-checkout runs fall back to the
repository-root directory, which remains the single source of truth.

Uses Australian English in all documentation and comments.
"""

from importlib.resources import files
from pathlib import Path


def packaged_skills_dir() -> Path:
    """Return the directory holding the shipped skill folders.

    Raises FileNotFoundError if neither the packaged copy nor the
    repository-root copy exists.
    """
    packaged = Path(str(files("cloudledger") / "skills"))
    if packaged.is_dir():
        return packaged
    repo_root = Path(__file__).resolve().parents[3] / "skills"
    if repo_root.is_dir():
        return repo_root
    raise FileNotFoundError(
        "The CloudLedger skills directory was not found in the installed "
        "package or the source tree."
    )
