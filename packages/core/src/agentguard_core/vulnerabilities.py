from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .bom_models import PackageEntity, VulnerabilityRecord

OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class VulnerabilityProvider(ABC):
    """Provider boundary; implementations receive package identity, never source."""

    name = "unknown"

    @abstractmethod
    def query_batch(self, packages: list[PackageEntity]) -> dict[str, list[VulnerabilityRecord]]:
        """Return normalized vulnerabilities keyed by PackageEntity.package_id."""


class OSVVulnerabilityProvider(VulnerabilityProvider):
    name = "OSV"

    def __init__(self, *, endpoint: str = OSV_QUERY_BATCH_URL, timeout_seconds: float = 20.0):
        self.endpoint = endpoint
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _record(package: PackageEntity, value: dict[str, Any], enriched_at: str) -> VulnerabilityRecord:
        canonical = str(value.get("id") or "UNKNOWN")
        vulnerability_id = f"VULN-{hashlib.sha256(f'{canonical}|{package.package_id}'.encode()).hexdigest()[:20].upper()}"
        database_specific = value.get("database_specific") or {}
        severity = str(database_specific.get("severity") or "unknown").lower()
        cvss = [dict(item) for item in value.get("severity") or [] if isinstance(item, dict)]
        aliases = sorted({str(item) for item in value.get("aliases") or [] if item})
        references = sorted({str(item.get("url")) for item in value.get("references") or [] if isinstance(item, dict) and item.get("url")})
        cwe = {str(item) for item in database_specific.get("cwe_ids") or [] if item}
        affected_ranges: list[dict[str, Any]] = []
        fixed_versions: set[str] = set()
        for affected in value.get("affected") or []:
            if not isinstance(affected, dict):
                continue
            ecosystem_specific = affected.get("ecosystem_specific") or {}
            for item in ecosystem_specific.get("database_specific", {}).get("cwe_ids", []) or []:
                cwe.add(str(item))
            for package_range in affected.get("ranges") or []:
                if not isinstance(package_range, dict):
                    continue
                affected_ranges.append({
                    "type": str(package_range.get("type") or ""),
                    "repo": str(package_range.get("repo") or ""),
                    "events": [dict(event) for event in package_range.get("events") or [] if isinstance(event, dict)],
                })
                for event in package_range.get("events") or []:
                    if isinstance(event, dict) and event.get("fixed"):
                        fixed_versions.add(str(event["fixed"]))
        return VulnerabilityRecord(
            vulnerability_id,
            canonical,
            aliases,
            "OSV",
            severity,
            package.package_id,
            "affected",
            "unknown",
            "unknown",
            "present",
            cvss,
            sorted(cwe),
            affected_ranges,
            sorted(fixed_versions),
            references,
            str(value.get("published") or ""),
            str(value.get("modified") or ""),
            enriched_at,
            str(value.get("summary") or ""),
            str(value.get("details") or ""),
            package.version,
        )

    def query_batch(self, packages: list[PackageEntity]) -> dict[str, list[VulnerabilityRecord]]:
        queryable = [package for package in packages if package.purl and package.resolved]
        if not queryable:
            return {}
        payload = {"queries": [{"package": {"purl": package.purl}} for package in queryable]}
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "AgentGuard-Core/0.4"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
            document = json.loads(response.read().decode("utf-8"))
        results = document.get("results") or []
        enriched_at = _now()
        normalized: dict[str, list[VulnerabilityRecord]] = {}
        for index, package in enumerate(queryable):
            entry = results[index] if index < len(results) and isinstance(results[index], dict) else {}
            normalized[package.package_id] = [
                self._record(package, item, enriched_at)
                for item in entry.get("vulns") or []
                if isinstance(item, dict)
            ]
        return normalized


class CachedVulnerabilityProvider(VulnerabilityProvider):
    """Timestamped package-level cache around any provider implementation."""

    def __init__(self, provider: VulnerabilityProvider, cache_path: Path, ttl: timedelta):
        self.provider = provider
        self.cache_path = cache_path
        self.ttl = ttl
        self.name = provider.name

    def _load(self) -> dict[str, Any]:
        try:
            value = json.loads(self.cache_path.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _write(self, value: dict[str, Any]) -> None:
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.cache_path.with_suffix(f"{self.cache_path.suffix}.tmp-{os.getpid()}")
        temporary.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
        temporary.replace(self.cache_path)

    def query_batch(self, packages: list[PackageEntity]) -> dict[str, list[VulnerabilityRecord]]:
        cache = self._load()
        entries = cache.get("entries") if isinstance(cache.get("entries"), dict) else {}
        now = datetime.now(timezone.utc)
        result: dict[str, list[VulnerabilityRecord]] = {}
        misses: list[PackageEntity] = []
        for package in packages:
            key = package.purl
            entry = entries.get(key) if key else None
            try:
                fetched_at = datetime.fromisoformat(str(entry.get("fetched_at"))) if isinstance(entry, dict) else None
                if fetched_at and fetched_at.tzinfo is None:
                    fetched_at = fetched_at.replace(tzinfo=timezone.utc)
            except ValueError:
                fetched_at = None
            if fetched_at and now - fetched_at <= self.ttl:
                result[package.package_id] = [
                    VulnerabilityRecord.from_dict(item)
                    for item in entry.get("vulnerabilities") or []
                    if isinstance(item, dict)
                ]
            else:
                misses.append(package)
        if misses:
            fetched = self.provider.query_batch(misses)
            fetched_at = _now()
            for package in misses:
                records = fetched.get(package.package_id, [])
                result[package.package_id] = records
                if package.purl:
                    entries[package.purl] = {
                        "fetched_at": fetched_at,
                        "provider": self.provider.name,
                        "vulnerabilities": [record.to_dict() for record in records],
                    }
            self._write({"schema": "agentguard-vulnerability-cache/1.0", "entries": entries})
        return result


def enrich_packages(
    packages: list[PackageEntity],
    provider: VulnerabilityProvider,
) -> list[VulnerabilityRecord]:
    queryable = [package for package in packages if package.purl and package.resolved]
    by_package = provider.query_batch(queryable)
    records: list[VulnerabilityRecord] = []
    for package in packages:
        if not package.purl or not package.resolved:
            package.vulnerability_status = "unknown"
            continue
        package_records = by_package.get(package.package_id, [])
        package.vulnerability_status = "affected" if package_records else "not_affected"
        records.extend(package_records)
    return sorted(records, key=lambda item: (item.canonical_id, item.affected_package_id))


NETWORK_ERRORS = (OSError, TimeoutError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError)
