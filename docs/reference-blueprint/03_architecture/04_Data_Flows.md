# Data Flow Diagrams

## DFD-1 Local scan
1. Developer invokes CLI.
2. CLI builds `ScanRequest`.
3. Core reads repository as untrusted input.
4. Core creates canonical `ScanResult`.
5. Reporting renders local artifacts.
6. Optional platform upload occurs only when explicitly configured.

## DFD-2 CI/CD scan
1. Pipeline checks out source.
2. CI adapter invokes CLI.
3. Core scans local checkout.
4. Policy engine evaluates findings.
5. Pipeline receives exit code and artifacts.
6. Connected mode uploads `ScanResult` to Platform.

## DFD-3 SaaS-managed scan
1. Authorized user/API creates scan.
2. Platform stores job metadata and queues immutable request.
3. Worker receives job.
4. Worker obtains source snapshot in ephemeral workspace.
5. Worker executes Core and configured external engines.
6. Worker normalizes result and uploads artifacts.
7. Platform transactionally ingests scan metadata, occurrences, inventory and relationships.
8. Lifecycle resolver compares completed result with previous complete scan.
9. Graph/report jobs are triggered asynchronously.

## DFD-4 Third-party scanner
1. Platform policy selects engine.
2. Worker/plugin host loads engine adapter.
3. Adapter executes vendor API/CLI according to approved configuration.
4. Adapter returns `EngineResult`.
5. Normalizer maps vendor schema to canonical finding/entity/relationship contracts.
6. UI renders generic result and shows `engine_id` as provenance.

See editable diagram: `diagrams/04_data_flows.drawio`.
