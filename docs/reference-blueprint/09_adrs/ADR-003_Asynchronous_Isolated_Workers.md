# ADR-003: Execute SaaS scans through asynchronous isolated workers

**Status:** Proposed

## Decision
Platform API creates typed scan jobs. Workers consume jobs and execute scanners in ephemeral bounded workspaces.

## Rationale
Customer repositories are untrusted input and long-running scans should not execute in request/response API processes.
