from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict, deque
from pathlib import Path
from typing import Any
from urllib.parse import quote

import tomllib
import yaml

from .bom_models import PackageEntity
from .file_inventory import discover_repository_files
from .models import Relationship


def normalize_package_name(name: str, ecosystem: str) -> str:
    value = name.strip().lower()
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", value)
    return value


def _exact_version(value: str) -> str:
    candidate = value.strip().strip('"\'')
    if candidate.startswith("=="):
        candidate = candidate[2:].strip()
    if not candidate or candidate.lower() in {"*", "latest", "declared"}:
        return ""
    if candidate.startswith(("^", "~", ">", "<", "!", "=", "git+", "http:", "https:", "file:", "workspace:")):
        return ""
    if any(token in candidate for token in (" || ", " ", ",", "*")):
        return ""
    return candidate


class PackageInventory:
    """Offline Python and JavaScript package/lockfile inventory."""

    def __init__(self, root: Path, repository_paths: list[Path] | None = None):
        self.root = root.resolve()
        self.repository_paths = tuple(repository_paths if repository_paths is not None else discover_repository_files(self.root))
        self.paths_by_name: dict[str, list[Path]] = defaultdict(list)
        for path in self.repository_paths:
            self.paths_by_name[path.name].append(path)
        self.direct: set[tuple[str, str]] = set()
        self.requests: dict[tuple[str, str], str] = {}
        self.manifest_origins: dict[tuple[str, str], list[str]] = defaultdict(list)
        self.evidence: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        self.lock_records: list[tuple[str, str, str, list[str], str, list[str]]] = []

    def _relative(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix()

    def _paths(self, names: set[str], patterns: tuple[str, ...] = ()) -> list[Path]:
        matches = [path for name in names for path in self.paths_by_name.get(name, ())]
        if patterns:
            matches.extend(
                path for path in self.repository_paths if any(path.match(pattern) for pattern in patterns)
            )
        return sorted(set(matches))

    @staticmethod
    def _line(path: Path, needle: str) -> int:
        try:
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if needle.lower() in line.lower():
                    return number
        except OSError:
            pass
        return 1

    def _add_request(self, ecosystem: str, name: str, requested: str, path: Path) -> None:
        normalized = normalize_package_name(name, ecosystem)
        if not normalized:
            return
        key = (ecosystem, normalized)
        origin = self._relative(path)
        self.direct.add(key)
        self.requests[key] = requested.strip()
        if origin not in self.manifest_origins[key]:
            self.manifest_origins[key].append(origin)
        item = {"file": origin, "line": self._line(path, name), "detail": f"direct dependency {name} {requested}".strip()}
        if item not in self.evidence[key]:
            self.evidence[key].append(item)

    def _read_python_manifests(self) -> None:
        for path in self._paths(set(), ("requirements*.txt",)):
            for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
                value = line.split("#", 1)[0].strip()
                if not value or value.startswith(("-", "git+", "http://", "https://")):
                    continue
                value = value.split(";", 1)[0].strip()
                match = re.match(r"([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)", value)
                if match:
                    self._add_request("PyPI", match.group(1), match.group(2), path)

        for path in self._paths({"pyproject.toml"}):
            try:
                data = tomllib.loads(path.read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError):
                continue
            project = data.get("project", {})
            dependency_groups = [project.get("dependencies", [])]
            dependency_groups.extend((project.get("optional-dependencies", {}) or {}).values())
            for dependencies in dependency_groups:
                for dependency in dependencies or []:
                    specification = str(dependency).split(";", 1)[0].strip()
                    match = re.match(r"\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*(.*)", specification)
                    if match:
                        self._add_request("PyPI", match.group(1), match.group(2), path)
            poetry = ((data.get("tool") or {}).get("poetry") or {})
            poetry_groups = [poetry.get("dependencies", {})]
            poetry_groups.extend(
                group.get("dependencies", {})
                for group in (poetry.get("group", {}) or {}).values()
                if isinstance(group, dict)
            )
            for dependencies in poetry_groups:
                for name, constraint in (dependencies or {}).items():
                    if str(name).lower() == "python":
                        continue
                    requested = constraint.get("version", "") if isinstance(constraint, dict) else str(constraint)
                    self._add_request("PyPI", str(name), str(requested), path)

    def _read_javascript_manifests(self) -> None:
        for path in self._paths({"package.json"}):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                for name, requested in (data.get(section) or {}).items():
                    self._add_request("npm", str(name), str(requested), path)

    def _add_lock(self, ecosystem: str, name: str, version: str, dependencies: list[str], path: Path, licenses: list[str] | None = None) -> None:
        exact = _exact_version(str(version))
        normalized = normalize_package_name(name, ecosystem)
        if exact and normalized:
            self.lock_records.append((ecosystem, str(name), exact, dependencies, self._relative(path), list(licenses or [])))

    def _read_python_locks(self) -> None:
        for path in self._paths({"poetry.lock", "uv.lock"}):
            try:
                data = tomllib.loads(path.read_text(encoding="utf-8"))
            except (OSError, tomllib.TOMLDecodeError):
                continue
            for package in data.get("package", []) or []:
                if not isinstance(package, dict):
                    continue
                dependencies = package.get("dependencies") or {}
                if isinstance(dependencies, dict):
                    dependency_names = [str(name) for name in dependencies]
                else:
                    dependency_names = [str(item.get("name")) for item in dependencies if isinstance(item, dict) and item.get("name")]
                license_value = package.get("license")
                licenses = [str(license_value)] if license_value else []
                self._add_lock("PyPI", str(package.get("name", "")), str(package.get("version", "")), dependency_names, path, licenses)

        for path in self._paths({"Pipfile.lock"}):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for section in ("default", "develop"):
                for name, record in (data.get(section) or {}).items():
                    version = record.get("version", "") if isinstance(record, dict) else str(record)
                    self._add_request("PyPI", str(name), str(version), path)
                    self._add_lock("PyPI", str(name), str(version), [], path)

    def _read_package_lock(self, path: Path) -> None:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        packages = data.get("packages")
        if isinstance(packages, dict):
            root = packages.get("") or {}
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                for name, requested in (root.get(section) or {}).items():
                    self._add_request("npm", str(name), str(requested), path.parent / "package.json" if (path.parent / "package.json").exists() else path)
            for location, record in packages.items():
                if not location or not isinstance(record, dict):
                    continue
                name = str(record.get("name") or location.rsplit("node_modules/", 1)[-1])
                dependencies = [str(item) for item in (record.get("dependencies") or {})]
                license_value = record.get("license")
                licenses = [str(license_value)] if license_value else []
                self._add_lock("npm", name, str(record.get("version", "")), dependencies, path, licenses)
            return

        def walk(records: dict[str, Any]) -> None:
            for name, record in records.items():
                if not isinstance(record, dict):
                    continue
                dependencies = [str(item) for item in (record.get("requires") or record.get("dependencies") or {})]
                self._add_lock("npm", str(name), str(record.get("version", "")), dependencies, path)
                nested = record.get("dependencies")
                if isinstance(nested, dict):
                    walk(nested)

        walk(data.get("dependencies") or {})

    def _read_yarn_lock(self, path: Path) -> None:
        current_names: list[str] = []
        version = ""
        dependencies: list[str] = []

        def flush() -> None:
            for name in current_names:
                self._add_lock("npm", name, version, dependencies, path)

        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line and not line.startswith((" ", "\t", "#")) and line.rstrip().endswith(":"):
                flush()
                selectors = [item.strip().strip('"\'') for item in line[:-1].split(",")]
                current_names = []
                for selector in selectors:
                    match = re.match(r"(@[^/]+/[^@]+|[^@]+)@", selector)
                    if match and match.group(1) not in current_names:
                        current_names.append(match.group(1))
                version, dependencies = "", []
            else:
                match = re.match(r"\s+version\s+[\"']?([^\"']+)", line)
                if match:
                    version = match.group(1)
                dependency = re.match(r"\s{4}(@?[^\s]+)\s+", line)
                if dependency and dependency.group(1) not in {"version", "resolved", "integrity"}:
                    dependencies.append(dependency.group(1))
        flush()

    @staticmethod
    def _pnpm_key(value: str) -> tuple[str, str]:
        key = value.lstrip("/").split("(", 1)[0]
        if key.startswith("@"):
            separator = key.rfind("@")
        else:
            separator = key.find("@")
        return (key[:separator], key[separator + 1 :]) if separator > 0 else ("", "")

    def _read_pnpm_lock(self, path: Path) -> None:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            return
        for importer in (data.get("importers") or {}).values():
            if not isinstance(importer, dict):
                continue
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                for name, record in (importer.get(section) or {}).items():
                    requested = record.get("specifier", "") if isinstance(record, dict) else str(record)
                    self._add_request("npm", str(name), str(requested), path)
        records = data.get("packages") or data.get("snapshots") or {}
        for key, record in records.items():
            name, version = self._pnpm_key(str(key))
            if not name or not isinstance(record, dict):
                continue
            dependencies = [str(item) for item in (record.get("dependencies") or {})]
            self._add_lock("npm", name, version, dependencies, path)

    def _read_javascript_locks(self) -> None:
        for path in self._paths({"package-lock.json", "npm-shrinkwrap.json"}):
            self._read_package_lock(path)
        for path in self._paths({"yarn.lock"}):
            self._read_yarn_lock(path)
        for path in self._paths({"pnpm-lock.yaml", "pnpm-lock.yml"}):
            self._read_pnpm_lock(path)

    @staticmethod
    def _package_id(ecosystem: str, normalized_name: str, version: str) -> str:
        material = f"{ecosystem.lower()}|{normalized_name}|{version or 'unresolved'}"
        return f"PKG-{hashlib.sha256(material.encode()).hexdigest()[:20].upper()}"

    @staticmethod
    def _purl(ecosystem: str, normalized_name: str, version: str) -> str:
        if not version:
            return ""
        purl_type = "pypi" if ecosystem == "PyPI" else "npm"
        return f"pkg:{purl_type}/{quote(normalized_name, safe='/')}@{quote(version, safe='.+-_')}"

    def discover(self) -> tuple[list[PackageEntity], list[Relationship]]:
        self._read_python_manifests()
        self._read_javascript_manifests()
        self._read_python_locks()
        self._read_javascript_locks()

        packages: dict[tuple[str, str, str], PackageEntity] = {}
        locked_names: set[tuple[str, str]] = set()
        dependency_names: dict[str, list[str]] = {}
        for ecosystem, name, version, dependencies, origin, licenses in self.lock_records:
            normalized = normalize_package_name(name, ecosystem)
            locked_names.add((ecosystem, normalized))
            package_id = self._package_id(ecosystem, normalized, version)
            key = (ecosystem, normalized, version)
            package = packages.get(key)
            if package is None:
                direct = (ecosystem, normalized) in self.direct
                evidence = list(self.evidence.get((ecosystem, normalized), []))
                evidence.append({"file": origin, "line": 1, "detail": f"resolved {name} {version}"})
                package = PackageEntity(
                    package_id,
                    name,
                    normalized,
                    ecosystem,
                    version,
                    self._purl(ecosystem, normalized, version),
                    "direct" if direct else "transitive",
                    list(self.manifest_origins.get((ecosystem, normalized), [])),
                    [origin],
                    [],
                    licenses,
                    evidence,
                    self.requests.get((ecosystem, normalized), ""),
                    True,
                )
                packages[key] = package
            elif origin not in package.lockfile_origins:
                package.lockfile_origins.append(origin)
            dependency_names[package_id] = dependencies

        for (ecosystem, normalized), requested in self.requests.items():
            if (ecosystem, normalized) in locked_names:
                continue
            exact = _exact_version(requested)
            version = exact or requested or "unknown"
            package_id = self._package_id(ecosystem, normalized, version)
            packages[(ecosystem, normalized, version)] = PackageEntity(
                package_id,
                normalized,
                normalized,
                ecosystem,
                version,
                self._purl(ecosystem, normalized, exact),
                "direct",
                list(self.manifest_origins[(ecosystem, normalized)]),
                [],
                [package_id],
                [],
                list(self.evidence[(ecosystem, normalized)]),
                requested,
                bool(exact),
            )

        by_name: dict[tuple[str, str], list[PackageEntity]] = defaultdict(list)
        for package in packages.values():
            by_name[(package.ecosystem, package.normalized_name)].append(package)
        for values in by_name.values():
            values.sort(key=lambda item: (item.dependency_type != "direct", item.version, item.package_id))

        relationships: list[Relationship] = []
        adjacency: dict[str, list[str]] = defaultdict(list)
        for package in packages.values():
            for dependency_name in dependency_names.get(package.package_id, []):
                normalized = normalize_package_name(dependency_name, package.ecosystem)
                candidates = by_name.get((package.ecosystem, normalized), [])
                if not candidates:
                    continue
                target = candidates[0]
                if target.package_id == package.package_id or target.package_id in adjacency[package.package_id]:
                    continue
                adjacency[package.package_id].append(target.package_id)
                package.dependencies.append(target.package_id)
                origin = package.lockfile_origins[0] if package.lockfile_origins else package.manifest_origins[0]
                evidence = {"file": origin, "line": 1, "detail": f"{package.name} depends on {target.name}"}
                relationships.append(Relationship(
                    package.package_id,
                    "DEPENDS_ON",
                    target.package_id,
                    origin,
                    1,
                    {"resolution": "lockfile", "ecosystem": package.ecosystem},
                    "explicit/direct",
                    "exact",
                    "lockfile-dependency",
                    [evidence],
                ))

        queue = deque((package.package_id, [package.package_id]) for package in packages.values() if package.dependency_type == "direct")
        visited: set[str] = set()
        by_id = {package.package_id: package for package in packages.values()}
        while queue:
            package_id, path = queue.popleft()
            if package_id in visited:
                continue
            visited.add(package_id)
            package = by_id[package_id]
            if not package.dependency_path or len(path) < len(package.dependency_path):
                package.dependency_path = path
            for target_id in adjacency.get(package_id, []):
                queue.append((target_id, [*path, target_id]))

        return sorted(packages.values(), key=lambda item: (item.ecosystem, item.normalized_name, item.version)), relationships
