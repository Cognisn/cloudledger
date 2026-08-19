"""
CLI command group for the shipped MCP-client skills.

``cloudledger skills export`` packages each skill folder into its own ZIP
archive, in the shape MCP clients such as claude.ai and Claude Desktop expect
for skill uploads: the skill folder itself is the archive root.

Uses Australian English in all documentation and comments.
"""

import zipfile
from pathlib import Path

import click

from ..utils.skills import packaged_skills_dir


@click.group(name="skills")
def skills_group():
    """Package the bundled MCP-client skills for installation."""


@skills_group.command(name="export")
@click.option(
    "--output",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path.cwd,
    help="Directory to write the skill archives into (default: current directory).",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite archives that already exist in the output directory.",
)
def export_skills(output: Path, force: bool):
    """Write one ZIP archive per bundled skill, ready to install on an MCP client."""
    skills_root = packaged_skills_dir()
    output.mkdir(parents=True, exist_ok=True)

    written, skipped = [], []
    for skill_dir in sorted(p for p in skills_root.iterdir() if p.is_dir()):
        archive_path = output / f"{skill_dir.name}.zip"
        if archive_path.exists() and not force:
            skipped.append(archive_path)
            continue
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
            for source in sorted(skill_dir.rglob("*")):
                if source.is_file():
                    archive.write(
                        source, f"{skill_dir.name}/{source.relative_to(skill_dir)}"
                    )
        written.append(archive_path)

    for path in written:
        click.echo(f"Wrote {path}")
    for path in skipped:
        click.echo(f"Skipped {path} (already exists; use --force to overwrite)")
    if written:
        click.echo(
            f"{len(written)} skill archive(s) ready to install on your MCP client."
        )
