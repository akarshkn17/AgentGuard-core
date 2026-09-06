# Container Architecture

This uses the C4 meaning of **container**: an independently running application/process, not only a Docker container.

| Container | Responsibility | Technology direction | Persistent state |
|---|---|---|---|
| Core library | static analysis | Python package | none required |
| CLI | local developer/pipeline interface | Python CLI/standalone binary | local config/cache only |
| Platform API | SaaS control plane | FastAPI or equivalent | PostgreSQL |
| Scan Worker | isolated execution | hardened container/job | ephemeral workspace |
| Web UI | browser app | React/Next.js or equivalent | none; API only |
| Graph module/service | graph queries/derived paths | initially Platform module; extract later | graph snapshot/index |
| Report worker/module | heavy report rendering | library locally; async worker in SaaS | Blob artifacts |
| Plugin adapters | third-party scanner integration | worker-side SDK/plugins | engine artifacts only |

## Primary communication

- CLI -> Core: in-process Python contract.
- CI adapter -> CLI: process invocation or action wrapper.
- UI -> Platform: HTTPS JSON API.
- Platform -> Worker: queue job reference.
- Worker -> Platform: authenticated result ingestion/API or blob + manifest.
- Platform -> PostgreSQL/Blob/graph store: private service connections.

See editable diagram: `diagrams/02_container_architecture.drawio`.
