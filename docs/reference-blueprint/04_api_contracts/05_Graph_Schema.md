# Graph Schema

## Graph node
A graph node references an inventory entity or a derived security object.

Node classes:
- asset
- identity
- data
- finding
- control

## Graph edge
Each edge contains:
- `edge_id`
- `source_id`
- `target_id`
- `relationship_type`
- confidence
- source evidence
- snapshot/scan ID
- attributes

## Security overlay
Derived edge/node metadata can include:
- privilege level
- externally influenced
- data classification
- internet reachable
- vulnerable
- sensitive sink
- trust zone

The raw graph remains immutable per scan snapshot. Attack-path/risk calculations are derived views so algorithms can evolve without rewriting source evidence.
