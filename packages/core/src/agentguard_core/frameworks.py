from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SourceDefinition:
    kind: str
    call_patterns: tuple[str, ...]
    framework: str = "generic"


@dataclass(frozen=True, slots=True)
class SinkDefinition:
    kind: str
    call_patterns: tuple[str, ...]
    framework: str = "generic"

SOURCE_CALLS = {
    "llm_output": [
        ".invoke", ".ainvoke", ".generate", ".agenerate", ".generate_content",
        ".chat.completions.create", "Runner.run", "Runner.run_sync", "Runner.run_streamed",
    ],
    "retrieval": ["similarity_search", "similarity_search_with_score", "retriever.invoke", "retriever.ainvoke", "load_documents", "get_relevant_documents"],
    "mcp_result": ["call_tool", "read_resource", "get_prompt"],
    "tool_result": [".run", ".arun", "tool.invoke", "tool.ainvoke"],
}

SOURCE_DEFINITIONS = tuple(
    SourceDefinition(kind, tuple(patterns), "mcp" if kind == "mcp_result" else "generic")
    for kind, patterns in SOURCE_CALLS.items()
)

SINK_CALLS = {
    "shell_execution": ["os.system", "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output", "child_process.exec", "execSync"],
    "dynamic_code": ["eval", "exec", "compile", "__import__", "importlib.import_module"],
    "sql_query": ["execute", "executemany", "raw", "cursor.execute", "session.execute"],
    "network_request": ["requests.get", "requests.post", "requests.request", "httpx.get", "httpx.post", "httpx.request", "client.get", "client.post", "fetch", "axios.get", "axios.post"],
    "file_read": ["open", "Path.read_text", "Path.read_bytes", "read_text", "read_bytes"],
    "file_write": ["Path.write_text", "Path.write_bytes", "write_text", "write_bytes", "unlink", "remove", "rmtree"],
    "model_load": ["from_pretrained", "torch.load", "pickle.load", "pickle.loads", "joblib.load", "dill.load"],
    "logging_sink": ["print", "logging.debug", "logging.info", "logging.warning", "logging.error", "logger.debug", "logger.info", "logger.warning", "logger.error"],
    "memory_write": ["memory.save", "save_context", "put", "checkpoint.put", "store.put"],
    "vector_write": ["add_documents", "add_texts", "upsert", "index", "vectorstore.add"],
    "package_install": ["pip", "npm", "npx", "uv", "poetry"],
}

SINK_DEFINITIONS = tuple(
    SinkDefinition(kind, tuple(patterns)) for kind, patterns in SINK_CALLS.items()
)


def source_labels(call_name: str) -> set[str]:
    return {
        definition.kind
        for definition in SOURCE_DEFINITIONS
        if any(call_name == pattern or call_name.endswith(pattern) for pattern in definition.call_patterns)
    }


def sink_kinds(call_name: str) -> set[str]:
    return {
        definition.kind
        for definition in SINK_DEFINITIONS
        if any(call_name == pattern or call_name.endswith((f".{pattern}", pattern)) for pattern in definition.call_patterns)
    }

STRUCTURAL_CHECKS = {
    "trust_remote_code": {"keywords": {"trust_remote_code": True}},
    "tls_verify_disabled": {"keywords": {"verify": False}},
    "shell_true": {"keywords": {"shell": True}},
    "debug_true": {"keywords": {"debug": True}},
}

AGENT_CONSTRUCTORS = ["Agent", "RealtimeAgent", "create_react_agent", "create_openai_tools_agent", "StateGraph"]
TOOL_DECORATORS = ["tool", "function_tool", "mcp.tool", "server.tool"]
MCP_SERVER_CONSTRUCTORS = ["MCPServer", "FastMCP"]
MCP_RESOURCE_DECORATORS = ["mcp.resource", "server.resource"]
MCP_PROMPT_DECORATORS = ["mcp.prompt", "server.prompt"]
MODEL_CONSTRUCTORS = ["ChatOpenAI", "OpenAI", "AsyncOpenAI", "ChatAnthropic", "Anthropic", "GenerativeModel", "ChatGoogleGenerativeAI", "AzureOpenAI", "ChatBedrock", "Bedrock"]
VECTOR_CONSTRUCTORS = ["Chroma", "FAISS", "Pinecone", "Qdrant", "Weaviate", "Milvus", "PGVector"]
MEMORY_CONSTRUCTORS = ["MemorySaver", "ConversationBufferMemory", "ConversationSummaryMemory", "RedisSaver", "PostgresSaver"]
RETRIEVER_HINTS = ["as_retriever", "Retriever", "retriever"]
VALIDATOR_NAME_HINTS = ("validate", "sanitize", "allowlist", "authorize", "authorise", "check_permission", "check_access", "approve", "guard", "is_allowed")
