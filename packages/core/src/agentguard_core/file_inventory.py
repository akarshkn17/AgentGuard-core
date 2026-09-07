from __future__ import annotations

import os
import subprocess
from collections.abc import Iterator
from pathlib import Path

DEFAULT_IGNORED_DIRECTORIES = frozenset(
    {".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__", ".agentguard"}
)


def _is_ignored(path: Path, root: Path, ignored: frozenset[str]) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return True
    return any(part.lower() in ignored for part in relative.parts[:-1])


def _git_files(root: Path, ignored: frozenset[str]) -> list[Path] | None:
    try:
        output = subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        ).stdout
    except (FileNotFoundError, OSError, subprocess.CalledProcessError):
        return None

    paths: list[Path] = []
    for raw in output.split(b"\0"):
        if not raw:
            continue
        path = root / os.fsdecode(raw)
        if path.is_file() and not _is_ignored(path, root, ignored):
            paths.append(path)
    return sorted(set(paths), key=lambda item: item.as_posix().lower())


def _walk_files(root: Path, ignored: frozenset[str]) -> Iterator[Path]:
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.lower(), reverse=True)
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.lower() not in ignored:
                        pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=True):
                    yield Path(entry.path)
            except OSError:
                continue


def discover_repository_files(
    root: Path,
    ignored_directories: frozenset[str] = DEFAULT_IGNORED_DIRECTORIES,
) -> list[Path]:
    """Return one deterministic, SCM-aware file inventory for a scan."""
    resolved = root.resolve()
    ignored = frozenset(item.lower() for item in ignored_directories)
    git_paths = _git_files(resolved, ignored)
    if git_paths is not None:
        return git_paths
    return sorted(_walk_files(resolved, ignored), key=lambda item: item.as_posix().lower())
