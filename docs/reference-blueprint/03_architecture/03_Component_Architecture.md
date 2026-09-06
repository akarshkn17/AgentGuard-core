# Component Architecture

## Core components
- RepositoryWalker
- RuleStore
- PythonProjectAnalyzer
- TreeSitterAnalyzer
- ConfigAnalyzer
- Taint/Dataflow Engine
- InventoryDiscoverer
- LLMReviewer extension
- FindingNormalizer
- ScanCoordinator

## CLI components
- command router
- config/profile loader
- local result writer
- policy/exit evaluator
- platform client

## Platform components
- AuthN integration
- Authorization service
- Tenant/workspace/project service
- Scan job service
- Result ingestion service
- Finding lifecycle service
- Inventory service
- Dashboard service
- Reporting service
- Integration configuration service
- Audit service

## Worker components
- job consumer
- source snapshot provider
- sandbox/workspace manager
- engine runner
- plugin host
- result normalizer
- artifact uploader

## UI components
- shell/navigation
- dashboard builder
- projects/scans
- findings/evidence
- inventory/BOM
- graph explorer
- reports
- administration

See editable diagram: `diagrams/03_component_architecture.drawio`.
