from __future__ import annotations

import ast
from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

from .code_intelligence import (
    AbstractLocation,
    AbstractLocationKind,
    AbstractStore,
    CodeIntelligenceSession,
    DataFlowEdge,
    ProjectFunction,
    ResolutionConfidence,
    SanitizerRegistry,
    SanitizerState,
    TaintValue,
)
from .code_intelligence.models import node_range
from .frameworks import sink_kinds, source_labels
from .models import EvidenceNode, Finding
from .rules import Rule


class ProjectPythonAnalyzer:
    """AgentGuard's project-wide Python source-to-sink analyzer.

    This is kept deliberately close to the existing AgentGuard scanner logic:
    modules are indexed before analysis so taint can cross imported/local
    functions, while findings retain deterministic linear evidence paths.
    """

    def __init__(
        self,
        root: Path,
        sources: dict[Path, str],
        rules: list[Rule],
        session: CodeIntelligenceSession | None = None,
    ):
        self.root = root.resolve()
        self.rules = rules
        self.session = session or CodeIntelligenceSession(self.root, sources)
        self.index = self.session.index
        self.sanitizers = SanitizerRegistry()
        self.rules_by_id = {rule.id: rule for rule in rules}
        self.flow_rules: dict[tuple[str, str], list[Rule]] = defaultdict(list)
        for rule in rules:
            if rule.analysis.type not in {"taint", "control_flow", "semantic", "secret", "dependency"}:
                continue
            for source in rule.sources:
                for sink in rule.sinks:
                    self.flow_rules[(source, sink)].append(rule)
        self.target_applicability: dict[tuple[str, str], bool] = {}
        self.functions_with_intrinsic_sources = self._index_intrinsic_source_functions()

    @classmethod
    def from_files(
        cls,
        root: Path,
        paths: Iterable[Path],
        rules: list[Rule],
        session: CodeIntelligenceSession | None = None,
    ) -> ProjectPythonAnalyzer:
        if session is not None:
            return cls(root, session.sources, rules, session)
        sources = {
            path.resolve(): path.read_text(encoding="utf-8", errors="ignore")
            for path in paths
        }
        return cls(root, sources, rules)

    @staticmethod
    def _is_source_call(name: str) -> set[str]:
        return source_labels(name)

    @staticmethod
    def _sink_kinds(name: str) -> set[str]:
        return sink_kinds(name)

    @staticmethod
    def _code_line(function: ProjectFunction, line: int) -> str:
        return function.module.line_text(line).strip()

    def _node(self, function: ProjectFunction, kind: str, label: str, node: ast.AST, symbol: str = "") -> EvidenceNode:
        line = getattr(node, "lineno", 1)
        return EvidenceNode(kind, label, str(function.module.path), line, symbol, self._code_line(function, line))

    @staticmethod
    def _literal_segment(node: ast.AST) -> str:
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
            return repr(node.value)
        return "*"

    def _location(
        self,
        expression: ast.AST,
        function: ProjectFunction,
        environment: AbstractStore,
        *,
        parameter: bool = False,
    ) -> AbstractLocation | None:
        owner = function.symbol.symbol_id if function.symbol else function.qualname
        if isinstance(expression, ast.Name):
            return environment.resolve(AbstractStore.local(owner, expression.id, parameter=parameter))
        if isinstance(expression, ast.Attribute):
            base = self._location(expression.value, function, environment)
            if base is None:
                return None
            return environment.resolve(base.child(expression.attr, AbstractLocationKind.ATTRIBUTE))
        if isinstance(expression, ast.Subscript):
            base = self._location(expression.value, function, environment)
            if base is None:
                return None
            return environment.resolve(base.child(self._literal_segment(expression.slice), AbstractLocationKind.CONTAINER))
        return None

    def _eval(
        self,
        expression: ast.AST | None,
        environment: AbstractStore,
        function: ProjectFunction,
        callstack: tuple[str, ...],
        cache: dict[int, TaintValue] | None = None,
    ) -> TaintValue:
        if expression is None:
            return TaintValue()
        if isinstance(expression, ast.Name):
            location = self._location(expression, function, environment)
            return environment.read(location) if location else TaintValue()
        if isinstance(expression, ast.Constant):
            return TaintValue()
        if isinstance(expression, ast.NamedExpr):
            value = self._eval(expression.value, environment, function, callstack, cache)
            self._assign_target(
                expression.target,
                value,
                environment,
                function,
                expression,
                expression.value,
                callstack,
                cache,
            )
            return value
        if isinstance(expression, ast.Attribute):
            name = self.index.canonical(expression, function)
            if name.endswith("os.environ"):
                return TaintValue(
                    {"sensitive_data"},
                    [self._node(function, "source", "environment secrets", expression, name)],
                )
            location = self._location(expression, function, environment)
            precise = environment.read(location) if location else TaintValue()
            return precise if location and environment.contains(location) else precise.merge(
                self._eval(expression.value, environment, function, callstack, cache)
            )
        if isinstance(expression, ast.Subscript):
            name = self.index.canonical(expression.value, function)
            if name.endswith(("request.json", "request.args", "request.form", "request.headers")):
                return TaintValue(
                    {"user_input"},
                    [self._node(function, "source", "user-controlled request data", expression, name)],
                )
            if name.endswith("os.environ"):
                return TaintValue(
                    {"sensitive_data"},
                    [self._node(function, "source", "environment secret", expression, name)],
                )
            location = self._location(expression, function, environment)
            precise = environment.read(location) if location else TaintValue()
            if location and environment.contains(location):
                return precise
            base = self._eval(expression.value, environment, function, callstack, cache)
            key = self._eval(expression.slice, environment, function, callstack, cache)
            return precise.merge(base).merge(key)
        if isinstance(expression, (ast.JoinedStr, ast.BinOp, ast.BoolOp, ast.List, ast.Tuple, ast.Set)):
            if isinstance(expression, ast.JoinedStr):
                children = [item.value for item in expression.values if isinstance(item, ast.FormattedValue)]
            elif isinstance(expression, ast.BinOp):
                children = [expression.left, expression.right]
            elif isinstance(expression, ast.BoolOp):
                children = list(expression.values)
            else:
                children = list(expression.elts)
            value = TaintValue()
            for child in children:
                value = value.merge(self._eval(child, environment, function, callstack, cache))
            return value.through(self._node(function, "propagator", "expression propagation", expression))
        if isinstance(expression, ast.Dict):
            value = TaintValue()
            for child in [*expression.keys, *expression.values]:
                value = value.merge(self._eval(child, environment, function, callstack, cache))
            return value.through(self._node(function, "propagator", "object/dictionary propagation", expression))
        if isinstance(expression, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            value = self._eval(expression.elt, environment, function, callstack, cache)
            for generator in expression.generators:
                value = value.merge(self._eval(generator.iter, environment, function, callstack, cache))
            return value.through(self._node(function, "propagator", "comprehension propagation", expression))
        if isinstance(expression, ast.Call):
            value, _ = self._eval_call(
                expression,
                environment,
                function,
                callstack,
                cache,
                collect_findings=False,
            )
            return value
        if isinstance(expression, ast.IfExp):
            return self._eval(expression.body, environment, function, callstack, cache).merge(
                self._eval(expression.orelse, environment, function, callstack, cache)
            )
        if isinstance(expression, (ast.UnaryOp, ast.Await, ast.Starred)):
            return self._eval(
                expression.operand if isinstance(expression, ast.UnaryOp) else expression.value,
                environment,
                function,
                callstack,
                cache,
            )
        return TaintValue()

    def _eval_call(
        self,
        expression: ast.Call,
        environment: AbstractStore,
        function: ProjectFunction,
        callstack: tuple[str, ...],
        cache: dict[int, TaintValue] | None,
        *,
        collect_findings: bool,
    ) -> tuple[TaintValue, list[Finding]]:
        if cache is not None and id(expression) in cache:
            return cache[id(expression)], []

        name = self.index.canonical(expression.func, function)
        labels = self._is_source_call(name)
        if name in {"input", "builtins.input"}:
            labels.add("user_input")
        if name.endswith(".get_json") or (name.endswith(".json") and "request" in name):
            labels.add("user_input")
        if name in {"os.getenv", "getenv"}:
            labels.add("sensitive_data")

        resolution = self.index.resolution_for(expression, function)
        target = resolution.target
        sanitizer = self.sanitizers.evaluate(name, target)
        findings: list[Finding] = []
        if labels:
            value = TaintValue(
                labels,
                [self._node(function, "source", ",".join(sorted(labels)), expression, name)],
            )
            if (
                collect_findings
                and target
                and target.qualname not in callstack
                and self.session.allow_context(target.qualname, (*callstack, target.qualname))
            ):
                child_environment = self._call_environment(
                    expression, environment, function, target, callstack, cache
                )
                _, findings = self._run_block(
                    target.body,
                    child_environment,
                    target,
                    (*callstack, target.qualname),
                    collect_findings=True,
                )
                environment.merge_from(child_environment)
        else:
            argument_value = TaintValue()
            for argument in expression.args:
                argument_value = argument_value.merge(
                    self._eval(argument, environment, function, callstack, cache)
                )
            for keyword in expression.keywords:
                argument_value = argument_value.merge(
                    self._eval(keyword.value, environment, function, callstack, cache)
                )
            receiver_value = TaintValue()
            receiver_has_tainted_state = False
            if isinstance(expression.func, ast.Attribute):
                receiver_value = self._eval(
                    expression.func.value, environment, function, callstack, cache
                )
                receiver_location = self._location(
                    expression.func.value, function, environment
                )
                if receiver_location is not None:
                    resolved_receiver = environment.resolve(receiver_location)
                    receiver_has_tainted_state = any(
                        value.labels
                        and (resolved := environment.resolve(location)).owner_symbol_id
                        == resolved_receiver.owner_symbol_id
                        and resolved.root == resolved_receiver.root
                        and resolved.path[: len(resolved_receiver.path)]
                        == resolved_receiver.path
                        for location, value in environment.values.items()
                    )

        if not labels and (
            target
            and target.qualname not in callstack
            and (
                argument_value.labels
                or receiver_value.labels
                or receiver_has_tainted_state
                or target.qualname in self.functions_with_intrinsic_sources
            )
            and self.session.allow_context(target.qualname, (*callstack, target.qualname))
        ):
            child_environment = self._call_environment(
                expression, environment, function, target, callstack, cache
            )
            value, findings = self._run_block(
                target.body,
                child_environment,
                target,
                (*callstack, target.qualname),
                collect_findings=collect_findings,
            )
            environment.merge_from(child_environment)
            value = value.through(
                self._node(function, "propagator", f"return from {target.qualname}", expression, name)
            )
        elif not labels:
            value = TaintValue() if target else argument_value
            value = value.through(
                self._node(function, "propagator", f"call through {name}", expression, name)
            )

        if sanitizer.state is not SanitizerState.ABSENT:
            value = value.sanitized(
                sanitizer,
                self._node(
                    function,
                    "sanitizer",
                    f"{sanitizer.state.value}: {sanitizer.reason}",
                    expression,
                    name,
                ),
            )
        if cache is not None:
            cache[id(expression)] = value
        return value, findings

    def _index_intrinsic_source_functions(self) -> set[str]:
        direct_sources: set[str] = set()
        calls: dict[str, set[str]] = defaultdict(set)
        for function in self.index.functions.values():
            for node in ast.walk(function.node):
                if isinstance(node, ast.Call):
                    name = self.index.canonical(node.func, function)
                    labels = self._is_source_call(name)
                    if (
                        labels
                        or name in {"input", "builtins.input", "os.getenv", "getenv"}
                        or name.endswith(".get_json")
                        or (name.endswith(".json") and "request" in name)
                    ):
                        direct_sources.add(function.qualname)
                    target = self.index.resolve_function(node, function)
                    if target is not None:
                        calls[function.qualname].add(target.qualname)
                elif isinstance(node, ast.Attribute):
                    if self.index.canonical(node, function).endswith("os.environ"):
                        direct_sources.add(function.qualname)
                elif isinstance(node, ast.Subscript):
                    name = self.index.canonical(node.value, function)
                    if name.endswith(
                        ("request.json", "request.args", "request.form", "request.headers", "os.environ")
                    ):
                        direct_sources.add(function.qualname)

        source_functions = set(direct_sources)
        changed = True
        while changed:
            changed = False
            for caller, callees in calls.items():
                if caller not in source_functions and source_functions.intersection(callees):
                    source_functions.add(caller)
                    changed = True
        return source_functions

    def _call_environment(
        self,
        call: ast.Call,
        caller_environment: AbstractStore,
        caller: ProjectFunction,
        target: ProjectFunction,
        callstack: tuple[str, ...],
        cache: dict[int, TaintValue] | None = None,
    ) -> AbstractStore:
        environment = AbstractStore(
            max_alias_depth=self.session.limits.max_alias_depth,
            max_container_depth=self.session.limits.max_container_depth,
        )
        arguments = target.arguments
        positional_parameters = list(arguments)
        if target.class_name and positional_parameters and positional_parameters[0].arg in {"self", "cls"} and isinstance(call.func, ast.Attribute):
            parameter = positional_parameters.pop(0)
            receiver = self._location(call.func.value, caller, caller_environment)
            owner = target.symbol.symbol_id if target.symbol else target.qualname
            parameter_location = AbstractStore.local(owner, parameter.arg)
            if receiver is not None:
                self._copy_location_state(caller_environment, environment, receiver)
                environment.bind_alias(parameter_location, receiver)
        for parameter, expression in zip(positional_parameters, call.args, strict=False):
            value = self._eval(expression, caller_environment, caller, callstack, cache)
            if value.labels:
                value = value.through(
                    self._node(
                        target,
                        "propagator",
                        f"parameter {target.qualname}.{parameter.arg}",
                        target.node,
                        parameter.arg,
                    )
                )
            owner = target.symbol.symbol_id if target.symbol else target.qualname
            parameter_location = AbstractStore.local(owner, parameter.arg)
            source_location = self._location(expression, caller, caller_environment)
            if source_location is not None:
                self._copy_location_state(caller_environment, environment, source_location)
                environment.bind_alias(parameter_location, source_location)
            environment.write(parameter_location, value)
            self.session.record_data_flow(
                DataFlowEdge(
                    source_location,
                    parameter_location,
                    "argument-to-parameter",
                    node_range(str(caller.module.path), expression),
                    callstack,
                    self.index.resolution_for(call, caller).confidence,
                )
            )
        by_name = {argument.arg: argument for argument in arguments}
        for keyword in call.keywords:
            if keyword.arg and keyword.arg in by_name:
                value = self._eval(keyword.value, caller_environment, caller, callstack, cache)
                if value.labels:
                    value = value.through(
                        self._node(
                            target,
                            "propagator",
                            f"parameter {target.qualname}.{keyword.arg}",
                            target.node,
                            keyword.arg,
                        )
                    )
                owner = target.symbol.symbol_id if target.symbol else target.qualname
                parameter_location = AbstractStore.local(owner, keyword.arg)
                source_location = self._location(keyword.value, caller, caller_environment)
                if source_location is not None:
                    self._copy_location_state(caller_environment, environment, source_location)
                    environment.bind_alias(parameter_location, source_location)
                environment.write(parameter_location, value)
                self.session.record_data_flow(
                    DataFlowEdge(
                        source_location,
                        parameter_location,
                        "keyword-to-parameter",
                        node_range(str(caller.module.path), keyword.value),
                        callstack,
                    )
                )
        return environment

    @staticmethod
    def _copy_location_state(
        source: AbstractStore,
        target: AbstractStore,
        location: AbstractLocation,
    ) -> None:
        root = source.resolve(location)

        def related(candidate: AbstractLocation) -> bool:
            resolved = source.resolve(candidate)
            return (
                resolved.owner_symbol_id == root.owner_symbol_id
                and resolved.root == root.root
                and resolved.path[: len(root.path)] == root.path
            )

        for stored_location, value in source.values.items():
            if related(stored_location):
                target.values[source.resolve(stored_location)] = value.copy()
        for alias_source, alias_target in source.aliases.items():
            if related(alias_source) or related(alias_target):
                target.aliases[alias_source] = alias_target

    def _target_applicable(self, rule: Rule, function: ProjectFunction) -> bool:
        cache_key = (rule.id, function.module.module)
        cached = self.target_applicability.get(cache_key)
        if cached is not None:
            return cached
        if not rule.targets:
            return True
        targets = set(rule.targets)
        special_targets = targets.issubset({"skill", "plugin", "skill_manifest"}) or targets.issubset({"mcp_client"}) or targets.issubset({"mcp_server"}) or targets.issubset({"llm_client"}) or (targets and all(target.startswith("mcp") or target == "mcp" for target in targets))
        if not special_targets:
            self.target_applicability[cache_key] = True
            return True
        low_path = str(function.module.path).lower()
        low_source = function.module.source.lower()
        is_mcp = any(token in low_path or token in low_source for token in ("mcp", "mcpserver", "fastmcp", "@mcp."))
        is_skill = "skill" in low_path
        if targets.issubset({"skill", "plugin", "skill_manifest"}):
            result = is_skill
        elif targets.issubset({"mcp_client"}):
            result = any(token in low_source for token in ("stdio_client", "streamable_http_client", "clientsession", "mcp.client"))
        elif targets.issubset({"mcp_server"}):
            result = is_mcp
        elif targets.issubset({"llm_client"}):
            result = any(token in low_source for token in ("openai", "anthropic", "generativemodel", "chatgoogle", "azureopenai"))
        else:
            result = is_mcp
        self.target_applicability[cache_key] = result
        return result

    def _rules_for(
        self,
        labels: set[str],
        sinks: set[str],
        call_name: str,
        function: ProjectFunction,
    ) -> Iterable[Rule]:
        candidates: dict[str, Rule] = {}
        for label in labels:
            for sink in sinks:
                for rule in self.flow_rules.get((label, sink), ()):
                    candidates[rule.id] = rule
        for rule in sorted(candidates.values(), key=lambda item: item.id):
            if not self._target_applicable(rule, function):
                continue
            patterns = rule.match.get("call_patterns", []) if rule.match else []
            pattern_matches = not patterns or any(
                call_name == pattern or call_name.endswith(pattern) for pattern in patterns
            )
            if labels.intersection(rule.sources) and sinks.intersection(rule.sinks) and pattern_matches:
                yield rule

    def _finding(
        self,
        rule: Rule,
        function: ProjectFunction,
        call: ast.Call,
        evidence: list[EvidenceNode],
    ) -> Finding:
        call_name = self.index.canonical(call.func, function)
        code = self._code_line(function, call.lineno)
        normalized_call = ast.dump(call, annotate_fields=True, include_attributes=False)
        resolution = self.index.resolution_for(call, function)
        return Finding(
            rule.id,
            rule.name,
            rule.severity.title(),
            str(function.module.path),
            call.lineno,
            rule.message or rule.name,
            evidence,
            code,
            rule.analysis.type,
            semantic_anchor=f"{function.qualname}|{call_name}|{normalized_call}",
            engine_metadata={
                "resolution": resolution.confidence.value,
                "resolution_method": resolution.method,
                "containing_symbol_id": function.symbol.symbol_id if function.symbol else "",
                "containing_symbol": function.qualname,
                "engine": "project-python",
            },
        ).finalize(self.root)

    def _structural_findings(self, call: ast.Call, function: ProjectFunction) -> list[Finding]:
        name = self.index.canonical(call.func, function)
        keywords = {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg}
        checks: list[tuple[str, str]] = []
        if isinstance(keywords.get("trust_remote_code"), ast.Constant) and keywords["trust_remote_code"].value is True:
            checks.append(("AIR-MODEL-001", "trust_remote_code=True"))
        if isinstance(keywords.get("verify"), ast.Constant) and keywords["verify"].value is False:
            checks.append(("AIR-NET-004", "TLS certificate verification disabled"))
        if isinstance(keywords.get("shell"), ast.Constant) and keywords["shell"].value is True:
            checks.append(("AIR-EXEC-001", "shell=True process execution"))
        if isinstance(keywords.get("debug"), ast.Constant) and keywords["debug"].value is True:
            checks.append(("AIR-SECRET-005", "debug=True"))
        if name in {"pickle.load", "pickle.loads", "joblib.load", "dill.load"}:
            checks.append(("AIR-MODEL-002", name))
        if name.endswith("yaml.load"):
            checks.append(("AIR-OUT-006", name))
        findings: list[Finding] = []
        for rule_id, label in checks:
            rule = self.rules_by_id.get(rule_id)
            if rule:
                findings.append(
                    self._finding(rule, function, call, [self._node(function, "structural", label, call, name)])
                )
        return findings

    def _find_sinks_in_expression(
        self,
        expression: ast.AST,
        environment: AbstractStore,
        function: ProjectFunction,
        callstack: tuple[str, ...],
    ) -> tuple[list[Finding], dict[int, TaintValue]]:
        class PostOrderCalls(ast.NodeVisitor):
            def __init__(self) -> None:
                self.calls: list[ast.Call] = []

            def visit_Call(self, node: ast.Call) -> None:
                self.generic_visit(node)
                self.calls.append(node)

        visitor = PostOrderCalls()
        visitor.visit(expression)
        findings: list[Finding] = []
        cache: dict[int, TaintValue] = {}
        for call in visitor.calls:
            call_name = self.index.canonical(call.func, function)
            sinks = self._sink_kinds(call_name)
            argument_taint = TaintValue()
            for argument in call.args:
                argument_taint = argument_taint.merge(
                    self._eval(argument, environment, function, callstack, cache)
                )
            for keyword in call.keywords:
                argument_taint = argument_taint.merge(
                    self._eval(keyword.value, environment, function, callstack, cache)
                )
            effective_labels = argument_taint.effective_labels(sinks)
            if sinks and effective_labels:
                sink_node = self._node(function, "sink", ",".join(sorted(sinks)), call, call_name)
                for rule in self._rules_for(effective_labels, sinks, call_name, function):
                    findings.append(
                        self._finding(rule, function, call, [*argument_taint.path, sink_node])
                    )
            _, nested = self._eval_call(
                call,
                environment,
                function,
                callstack,
                cache,
                collect_findings=True,
            )
            findings.extend(nested)
        return findings, cache

    def _assign_target(
        self,
        target: ast.AST,
        value: TaintValue,
        environment: AbstractStore,
        function: ProjectFunction,
        statement: ast.AST,
        source_expression: ast.AST | None,
        callstack: tuple[str, ...],
        cache: dict[int, TaintValue] | None = None,
    ) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            source_items = source_expression.elts if isinstance(source_expression, (ast.Tuple, ast.List)) else []
            for index, element in enumerate(target.elts):
                child_expression = source_items[index] if index < len(source_items) else source_expression
                child_value = (
                    self._eval(child_expression, environment, function, callstack, cache)
                    if child_expression
                    else value
                )
                self._assign_target(
                    element,
                    child_value,
                    environment,
                    function,
                    statement,
                    child_expression,
                    callstack,
                    cache,
                )
            return
        location = self._location(target, function, environment)
        if location is None:
            return
        source_location = self._location(source_expression, function, environment) if source_expression is not None else None
        if source_location is not None and isinstance(source_expression, (ast.Name, ast.Attribute, ast.Subscript)):
            environment.bind_alias(location, source_location)
            location = environment.resolve(location)
        symbol = ast.unparse(target) if hasattr(ast, "unparse") else location.root
        propagated = value.through(
            self._node(function, "propagator", f"assigned to {symbol}", statement, symbol),
            max_nodes=self.session.limits.max_evidence_nodes,
        )
        written = environment.write(location, propagated)
        edge = DataFlowEdge(
            source_location,
            written,
            "assignment",
            node_range(str(function.module.path), statement),
            callstack,
            ResolutionConfidence.EXACT,
        )
        environment.record_edge(edge)
        self.session.record_data_flow(edge)

        if isinstance(source_expression, ast.Dict):
            for key, child_expression in zip(source_expression.keys, source_expression.values, strict=False):
                segment = self._literal_segment(key) if key is not None else "*"
                child_location = written.child(segment, AbstractLocationKind.CONTAINER)
                child_value = self._eval(child_expression, environment, function, callstack, cache)
                environment.write(child_location, child_value.through(self._node(function, "propagator", f"stored at {segment}", child_expression)))
        elif isinstance(source_expression, (ast.List, ast.Tuple)):
            for index, child_expression in enumerate(source_expression.elts):
                child_location = written.child(str(index), AbstractLocationKind.CONTAINER)
                child_value = self._eval(child_expression, environment, function, callstack, cache)
                environment.write(child_location, child_value.through(self._node(function, "propagator", f"stored at index {index}", child_expression)))

    def _run_block(
        self,
        body: list[ast.stmt],
        environment: AbstractStore,
        function: ProjectFunction,
        callstack: tuple[str, ...],
        collect_findings: bool = True,
    ) -> tuple[TaintValue, list[Finding]]:
        findings: list[Finding] = []
        returned = TaintValue()
        for statement in body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign)):
                value_node = statement.value
                cache: dict[int, TaintValue] = {}
                if collect_findings:
                    nested, cache = self._find_sinks_in_expression(
                        value_node, environment, function, callstack
                    )
                    findings.extend(nested)
                value = self._eval(value_node, environment, function, callstack, cache)
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                for target in targets:
                    self._assign_target(
                        target,
                        value,
                        environment,
                        function,
                        statement,
                        value_node,
                        callstack,
                        cache,
                    )
            elif isinstance(statement, ast.AugAssign):
                value = self._eval(statement.value, environment, function, callstack)
                location = self._location(statement.target, function, environment)
                if location is not None:
                    environment.write(location, environment.read(location).merge(value))
            elif isinstance(statement, ast.Expr):
                cache = {}
                if collect_findings:
                    nested, cache = self._find_sinks_in_expression(
                        statement.value, environment, function, callstack
                    )
                    findings.extend(nested)
                self._eval(statement.value, environment, function, callstack, cache)
            elif isinstance(statement, ast.Return):
                cache = {}
                if collect_findings and statement.value is not None:
                    nested, cache = self._find_sinks_in_expression(
                        statement.value, environment, function, callstack
                    )
                    findings.extend(nested)
                return_value = self._eval(
                    statement.value, environment, function, callstack, cache
                )
                returned = returned.merge(return_value)
                owner = function.symbol.symbol_id if function.symbol else function.qualname
                return_location = AbstractLocation(AbstractLocationKind.RETURN, owner, "<return>")
                source_location = self._location(statement.value, function, environment) if statement.value is not None else None
                environment.write(return_location, return_value)
                return_edge = DataFlowEdge(
                    source_location,
                    return_location,
                    "return",
                    node_range(str(function.module.path), statement),
                    callstack,
                )
                environment.record_edge(return_edge)
                self.session.record_data_flow(return_edge)
            elif isinstance(statement, ast.If):
                body_environment = environment.fork()
                else_environment = environment.fork()
                body_return, body_findings = self._run_block(
                    statement.body, body_environment, function, callstack, collect_findings
                )
                else_return, else_findings = self._run_block(
                    statement.orelse, else_environment, function, callstack, collect_findings
                )
                findings.extend(body_findings)
                findings.extend(else_findings)
                returned = returned.merge(body_return).merge(else_return)
                environment.merge_from(body_environment)
                environment.merge_from(else_environment)
            elif isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
                loop_environment = environment.fork()
                for _ in range(self.session.limits.max_loop_iterations):
                    if isinstance(statement, (ast.For, ast.AsyncFor)):
                        iterator = self._eval(statement.iter, loop_environment, function, callstack)
                        self._assign_target(statement.target, iterator, loop_environment, function, statement, statement.iter, callstack)
                    loop_return, loop_findings = self._run_block(
                        [*statement.body, *statement.orelse],
                        loop_environment,
                        function,
                        callstack,
                        collect_findings,
                    )
                    findings.extend(loop_findings)
                    returned = returned.merge(loop_return)
                environment.merge_from(loop_environment)
            elif isinstance(statement, (ast.With, ast.AsyncWith)):
                nested_return, nested_findings = self._run_block(
                    statement.body, environment, function, callstack, collect_findings
                )
                returned = returned.merge(nested_return)
                findings.extend(nested_findings)
            elif isinstance(statement, ast.Try):
                branches = [statement.body, statement.orelse, statement.finalbody]
                branches.extend(handler.body for handler in statement.handlers)
                for branch in branches:
                    branch_environment = environment.fork()
                    branch_return, branch_findings = self._run_block(
                        branch, branch_environment, function, callstack, collect_findings
                    )
                    environment.merge_from(branch_environment)
                    returned = returned.merge(branch_return)
                    findings.extend(branch_findings)
        return returned, findings

    def _is_external_entrypoint(self, function: ProjectFunction) -> bool:
        if isinstance(function.node, ast.Module):
            return False
        decorators: list[str] = []
        for decorator in function.node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            decorators.append(self.index.canonical(target, function).lower())
        return any(
            marker in decorator
            for decorator in decorators
            for marker in ("tool", "route", "endpoint", "handler", "mcp.")
        )

    def analyze(self) -> list[Finding]:
        findings: list[Finding] = []
        for function in self.index.functions.values():
            for call in self.index.iter_function_calls(function):
                findings.extend(self._structural_findings(call, function))
            _, internal_findings = self._run_block(
                function.body,
                AbstractStore(
                    max_alias_depth=self.session.limits.max_alias_depth,
                    max_container_depth=self.session.limits.max_container_depth,
                ),
                function,
                (function.qualname,),
                collect_findings=True,
            )
            findings.extend(internal_findings)
            if self._is_external_entrypoint(function):
                environment = AbstractStore(
                    max_alias_depth=self.session.limits.max_alias_depth,
                    max_container_depth=self.session.limits.max_container_depth,
                )
                owner = function.symbol.symbol_id if function.symbol else function.qualname
                for argument in function.arguments:
                    if argument.arg in {"self", "cls"}:
                        continue
                    environment.write(
                        AbstractStore.local(owner, argument.arg),
                        TaintValue(
                        {"user_input", "llm_output"},
                        [
                            self._node(
                                function,
                                "source",
                                f"external tool/endpoint parameter {argument.arg}",
                                function.node,
                                argument.arg,
                            )
                        ],
                        ),
                    )
                _, entry_findings = self._run_block(
                    function.body,
                    environment,
                    function,
                    (function.qualname,),
                    collect_findings=True,
                )
                findings.extend(entry_findings)
        return list({finding.fingerprint: finding for finding in findings}.values())
