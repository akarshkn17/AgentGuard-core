# ADR-001: Use a monorepo with modular packages and deployables

**Status:** Proposed

## Context
AgentGuard is early enough that splitting repositories would add coordination overhead while the contract boundaries are still evolving.

## Decision
Keep one repository. Separate Core, Contracts, CLI, Platform API, Worker and UI into independently testable/buildable directories.

## Consequences
+ easier atomic refactors during separation
+ shared contract changes visible in one PR
+ simpler developer setup
- CI must selectively build/test affected modules
- CODEOWNERS and dependency rules are required to avoid a new monolith
