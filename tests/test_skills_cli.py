"""
Tests for the skills export CLI: the `skills` command group and the
packaged-skills resolver that backs it.

Uses Australian English in all documentation and comments.
"""

import zipfile
from pathlib import Path

from click.testing import CliRunner

from cloudledger.scanner.cli import cli
from cloudledger.utils.skills import packaged_skills_dir

REPO_SKILLS = Path(__file__).resolve().parents[1] / "skills"


def _skill_names() -> list[str]:
    """The skill folder names shipped in the repository."""
    return sorted(p.name for p in REPO_SKILLS.iterdir() if p.is_dir())


def test_packaged_skills_dir_holds_every_shipped_skill():
    root = packaged_skills_dir()
    for name in _skill_names():
        assert (root / name / "SKILL.md").is_file()


def test_export_writes_one_zip_per_skill(tmp_path):
    result = CliRunner().invoke(cli, ["skills", "export", "--output", str(tmp_path)])
    assert result.exit_code == 0, result.output
    produced = sorted(p.name for p in tmp_path.glob("*.zip"))
    assert produced == [f"{name}.zip" for name in _skill_names()]


def test_zip_holds_the_skill_folder_as_its_root(tmp_path):
    CliRunner().invoke(cli, ["skills", "export", "--output", str(tmp_path)])
    with zipfile.ZipFile(tmp_path / "security-assessment.zip") as archive:
        names = archive.namelist()
    assert "security-assessment/SKILL.md" in names
    assert "security-assessment/references/scoring-rubric.md" in names
    assert "security-assessment/references/challenge-guide.md" in names
    assert all(n.startswith("security-assessment/") for n in names)


def test_zip_contents_match_the_source_files(tmp_path):
    CliRunner().invoke(cli, ["skills", "export", "--output", str(tmp_path)])
    with zipfile.ZipFile(tmp_path / "security-assessment.zip") as archive:
        packed = archive.read("security-assessment/SKILL.md")
    source = (REPO_SKILLS / "security-assessment" / "SKILL.md").read_bytes()
    assert packed == source


def test_export_never_produces_an_archive_for_the_directory_readme(tmp_path):
    result = CliRunner().invoke(cli, ["skills", "export", "--output", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert not (tmp_path / "README.zip").exists()


def test_export_skips_existing_archives_without_force(tmp_path):
    marker = tmp_path / "security-assessment.zip"
    marker.write_bytes(b"pre-existing")
    result = CliRunner().invoke(cli, ["skills", "export", "--output", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert marker.read_bytes() == b"pre-existing"
    assert "skipped" in result.output.lower()


def test_export_force_overwrites_existing_archives(tmp_path):
    marker = tmp_path / "security-assessment.zip"
    marker.write_bytes(b"pre-existing")
    result = CliRunner().invoke(
        cli, ["skills", "export", "--output", str(tmp_path), "--force"]
    )
    assert result.exit_code == 0, result.output
    assert zipfile.is_zipfile(marker)
