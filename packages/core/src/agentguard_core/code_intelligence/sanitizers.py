from __future__ import annotations

import ast
from dataclasses import dataclass

from .index import ProjectFunction
from .models import SanitizerResult, SanitizerState, node_range


INJECTION_LABELS = frozenset({"user_input", "llm_output", "tool_result", "retrieval", "mcp_result"})
INJECTION_SINKS = frozenset({"shell_execution", "dynamic_code", "sql_query", "file_read", "file_write", "network_request"})
NUMERIC_SINKS = frozenset({"shell_execution", "dynamic_code", "sql_query"})


@dataclass(frozen=True, slots=True)
class SanitizerContract:
    contract_id: str
    call_names: tuple[str, ...]
    state: SanitizerState
    protected_labels: frozenset[str]
    applicable_sinks: frozenset[str]
    reason: str


class SanitizerRegistry:
    """Conservative, sink-aware sanitizer classification.

    A sanitizer-looking name is never proof. Built-ins and structurally verified
    local allowlists are the only default paths to PROVEN.
    """

    NAME_HINTS = ("validate", "sanitize", "allowlist", "guard")

    def __init__(self, contracts: tuple[SanitizerContract, ...] | None = None):
        self.contracts = contracts or (
            SanitizerContract(
                "builtin.numeric-conversion",
                ("int", "builtins.int", "float", "builtins.float"),
                SanitizerState.PROVEN,
                INJECTION_LABELS,
                NUMERIC_SINKS,
                "numeric conversion constrains output to a non-injectable scalar",
            ),
            SanitizerContract(
                "builtin.shlex-quote",
                ("shlex.quote",),
                SanitizerState.PARTIAL,
                INJECTION_LABELS,
                frozenset({"shell_execution"}),
                "shell quoting is platform and composition dependent",
            ),
        )

    def evaluate(self, call_name: str, target: ProjectFunction | None = None) -> SanitizerResult:
        for contract in self.contracts:
            if any(call_name == name or call_name.endswith(f".{name}") for name in contract.call_names):
                return SanitizerResult(
                    contract.state,
                    contract.contract_id,
                    contract.protected_labels,
                    contract.applicable_sinks,
                    contract.reason,
                )
        if target is not None:
            structural = self._structural_allowlist(target)
            if structural is not None:
                return structural
        segments = call_name.lower().split(".")
        if any(segment == hint or segment.startswith(f"{hint}_") for segment in segments for hint in self.NAME_HINTS):
            return SanitizerResult(
                SanitizerState.UNVERIFIED,
                "name-only",
                reason="sanitizer-like name has no configured contract or structural proof",
            )
        return SanitizerResult(SanitizerState.ABSENT)

    @staticmethod
    def _structural_allowlist(target: ProjectFunction) -> SanitizerResult | None:
        if isinstance(target.node, ast.Module) or not target.arguments:
            return None
        parameter = next((arg.arg for arg in target.arguments if arg.arg not in {"self", "cls"}), "")
        if not parameter:
            return None
        guarded = False
        for node in ast.walk(target.node):
            if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
                continue
            comparison = node.test
            if not isinstance(comparison.left, ast.Name) or comparison.left.id != parameter:
                continue
            if not any(isinstance(op, ast.NotIn) for op in comparison.ops):
                continue
            if not comparison.comparators or not SanitizerRegistry._is_static_allowlist(comparison.comparators[0], target):
                continue
            rejects = False
            for statement in node.body:
                for child in ast.walk(statement):
                    if isinstance(child, ast.Raise):
                        rejects = True
                    elif isinstance(child, ast.Return) and (
                        child.value is None or isinstance(child.value, ast.Constant)
                    ):
                        rejects = True
            if rejects:
                guarded = True
                break
        returns = [node for node in ast.walk(target.node) if isinstance(node, ast.Return)]
        safe_returns = bool(returns) and all(
            node.value is None
            or isinstance(node.value, ast.Constant)
            or (isinstance(node.value, ast.Name) and node.value.id == parameter)
            for node in returns
        )
        if not guarded or not safe_returns:
            return None
        return SanitizerResult(
            SanitizerState.PROVEN,
            "structural.allowlist-membership",
            INJECTION_LABELS,
            INJECTION_SINKS,
            "function rejects values outside an explicit allowlist before returning the guarded parameter",
            node_range(str(target.module.path), target.node),
        )

    @staticmethod
    def _is_static_allowlist(node: ast.AST, target: ProjectFunction) -> bool:
        def literal_collection(value: ast.AST) -> bool:
            return isinstance(value, (ast.Set, ast.List, ast.Tuple)) and bool(value.elts) and all(
                isinstance(item, ast.Constant) for item in value.elts
            )

        if literal_collection(node):
            return True
        if not isinstance(node, ast.Name):
            return False
        for statement in target.module.tree.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                if any(isinstance(item, ast.Name) and item.id == node.id for item in targets):
                    return literal_collection(statement.value)
        return False
