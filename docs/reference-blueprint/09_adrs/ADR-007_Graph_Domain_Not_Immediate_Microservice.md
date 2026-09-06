# ADR-007: Define graph as a domain boundary before extracting a graph microservice

**Status:** Proposed

## Decision
Define immutable graph contracts and query interfaces now. Initially implement graph persistence/query inside the platform deployment unless load/query evidence requires independent service scaling.

## Rationale
Avoid premature microservices while preserving a future extraction boundary.
