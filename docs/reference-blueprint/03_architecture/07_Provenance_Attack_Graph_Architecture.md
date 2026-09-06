# Provenance and Attack Graph Architecture

## Separation of concerns
- Scanner/Inventory extracts source-grounded entities and relationships.
- Graph domain persists immutable snapshot facts.
- Graph analytics derives reachability, blast radius and attack paths.
- UI renders graph/query results through API contracts.

## Raw graph model
Typical asset path:

```text
External Input -> Agent -> MCP Server -> Tool -> API -> Data Store
                        |         |         |
                        v         v         v
                      Model     Identity   Secret/credential context
```

## Finding overlay
A finding may attach to:
- a node (insecure agent/tool/model configuration),
- an edge (unprotected call/capability relationship),
- an evidence path spanning multiple nodes/edges.

## Derived path examples
- externally influenced prompt -> privileged tool -> sensitive datastore
- public MCP endpoint -> overprivileged identity -> production API
- agent -> unapproved model provider -> sensitive prompt/data

## Storage strategy
Start with normalized snapshot tables/adjacency indexes in PostgreSQL if query volume is moderate. Extract to a graph-specific service/store only after demonstrated requirements for traversal performance, independent scale or graph algorithms.

## Important rule
Raw source-evidence relationships are immutable per scan. Derived risk scores/attack paths are recalculable views so algorithms can evolve without rewriting evidence.

See `diagrams/10_provenance_attack_graph.drawio`.
