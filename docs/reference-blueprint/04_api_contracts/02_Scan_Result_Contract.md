# Scan Result Contract

## Intent
`ScanResult` is the stable interchange object between scanner execution and every consumer. Core should not persist platform workflow fields into this object.

## Top-level structure

```json
{
  "contract_version": "1.0",
  "scan": {},
  "engines": [],
  "findings": [],
  "inventory": [],
  "relationships": [],
  "artifacts": [],
  "metrics": {},
  "errors": []
}
```

## Compatibility rules
- New optional fields may be added in minor versions.
- Removing/renaming fields requires a major contract version.
- Findings retain a scanner-stable fingerprint independent of SaaS database IDs.
- File locations are repository-relative, not machine absolute paths.
- Engine identity and engine version are mandatory for provenance.
- Partial scans declare completeness explicitly.

Machine-readable schemas are in `schemas/`.
