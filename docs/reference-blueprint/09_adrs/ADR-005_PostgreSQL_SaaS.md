# ADR-005: Use PostgreSQL for SaaS metadata and lifecycle

**Status:** Proposed

## Decision
Retain SQLite for local mode but use PostgreSQL for tenant/project/scan/finding/inventory/lifecycle state in SaaS.

## Rationale
PostgreSQL provides concurrency, migrations, indexing, transactions and tenant isolation mechanisms appropriate for the control plane.
