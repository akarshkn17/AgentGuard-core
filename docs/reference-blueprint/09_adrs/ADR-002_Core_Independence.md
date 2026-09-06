# ADR-002: Keep AgentGuard Core independent from SaaS and UI

**Status:** Proposed

## Decision
Core may depend on Contracts and analysis libraries but not web frameworks, Azure SDKs, platform database models or UI code.

## Rationale
Local/offline scanning and CI use are first-class product modes and must remain available without SaaS.
