# Finding Schema

A canonical finding must be able to represent deep dataflow findings, structural/config findings and normalized external-engine findings.

Required fields:
- `fingerprint`
- `engine_id`
- `rule_id`
- `title`
- `severity`
- `analysis_type`
- `location`

Important optional fields:
- confidence
- description
- message
- category
- framework mappings
- CWE
- source/sink
- evidence path
- code snippets
- remediation
- references
- related asset IDs
- vendor/original payload reference

Platform lifecycle status is deliberately not part of the scanner's canonical finding identity. The platform joins a finding fingerprint to lifecycle state.
