# ADR-006: Normalize third-party scanners through a generic engine contract

**Status:** Proposed

## Decision
Every external scanner adapter returns `EngineResult` in canonical schemas. UI and lifecycle services operate on canonical data rather than vendor-specific payloads.

## Rationale
Prevents vendor integrations from leaking throughout the product and allows future scanners to be added independently.
