# Inventory Schema

Canonical `InventoryEntity` is a discovered technical asset, not a platform ownership record.

Required:
- `entity_id`
- `entity_type`
- `name`
- `source_evidence`

Examples of `entity_type`:
- agent
- sub_agent
- orchestrator
- tool
- function_tool
- mcp_server
- mcp_client
- mcp_tool
- mcp_resource
- mcp_prompt
- skill
- plugin
- model
- embedding_model
- model_provider
- retriever
- vector_store
- rag_pipeline
- memory
- checkpoint_store
- prompt
- guardrail
- api_endpoint
- identity
- deployment

The platform may enrich the asset with owner, business service, approval status, tags and custom governance metadata without changing the scanner identity.
