from __future__ import annotations

import ast
import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from .models import CodeSymbol, SourceLocation, SourceRange, SymbolKind, node_range

if TYPE_CHECKING:
    from .resolver import CallResolution, CallResolver


@dataclass(slots=True)
class ProjectModule:
    path: Path
    module: str
    source: str
    tree: ast.Module
    imports: dict[str, str]
    is_package: bool = False
    symbol: CodeSymbol | None = None
    line_starts: tuple[int, ...] = ()

    def __post_init__(self) -> None:
        starts = [0]
        for index, character in enumerate(self.source):
            if character == "\n" or (
                character == "\r"
                and (index + 1 == len(self.source) or self.source[index + 1] != "\n")
            ):
                starts.append(index + 1)
        if self.source.endswith(("\n", "\r")):
            starts.pop()
        self.line_starts = tuple(starts) if self.source else ()

    @property
    def line_count(self) -> int:
        return len(self.line_starts)

    def line_text(self, line: int) -> str:
        if line < 1 or line > self.line_count:
            return ""
        start = self.line_starts[line - 1]
        end = self.line_starts[line] if line < self.line_count else len(self.source)
        return self.source[start:end].rstrip("\r\n")


@dataclass(slots=True)
class ProjectFunction:
    module: ProjectModule
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Module
    qualname: str
    body: list[ast.stmt]
    class_name: str = ""
    parent_qualname: str = ""
    symbol: CodeSymbol | None = None

    @property
    def arguments(self) -> list[ast.arg]:
        if isinstance(self.node, ast.Module):
            return []
        return [*self.node.args.posonlyargs, *self.node.args.args, *self.node.args.kwonlyargs]


class ProjectIndex:
    """Per-scan Python symbol index with compatibility helpers for existing analyzers."""

    def __init__(self, root: Path, sources: dict[Path, str]):
        self.root = root.resolve()
        self.modules: dict[str, ProjectModule] = {}
        self.functions: dict[str, ProjectFunction] = {}
        self.symbols: dict[str, CodeSymbol] = {}
        self.symbols_by_id: dict[str, CodeSymbol] = {}
        self.classes: dict[str, CodeSymbol] = {}
        self.parse_errors: list[tuple[Path, SyntaxError]] = []
        self.variable_types: dict[tuple[str, str], str] = {}
        self._calls_by_function: dict[str, tuple[ast.Call, ...]] = {}
        self._resolver: CallResolver | None = None
        for path, source in sorted(sources.items(), key=lambda item: str(item[0])):
            self._add_module(path.resolve(), source)
        for module in self.modules.values():
            self._index_module(module)
        self._index_variable_types()

    def set_resolver(self, resolver: CallResolver) -> None:
        self._resolver = resolver

    def _module_name(self, path: Path) -> tuple[str, bool]:
        relative = path.relative_to(self.root).with_suffix("")
        parts = list(relative.parts)
        is_package = bool(parts and parts[-1] == "__init__")
        if is_package:
            parts.pop()
        return ".".join(parts) or path.stem, is_package

    def _absolute_import(self, module: ProjectModule, node: ast.ImportFrom) -> str:
        if not node.level:
            return node.module or ""
        package = module.module.split(".") if module.is_package else module.module.split(".")[:-1]
        keep = max(0, len(package) - (node.level - 1))
        prefix = package[:keep]
        if node.module:
            prefix.extend(node.module.split("."))
        return ".".join(prefix)

    def _imports(self, module: ProjectModule) -> dict[str, str]:
        imports: dict[str, str] = {}
        for node in module.tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    local = alias.asname or alias.name.split(".")[0]
                    imports[local] = alias.name if alias.asname else local
            elif isinstance(node, ast.ImportFrom):
                base = self._absolute_import(module, node)
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    imports[alias.asname or alias.name] = f"{base}.{alias.name}".strip(".")
        return imports

    def _symbol_id(self, kind: SymbolKind, qualified_name: str) -> str:
        material = f"{self.root.name}|{kind.value}|{qualified_name.lower()}"
        return f"SYM-{hashlib.sha256(material.encode()).hexdigest()[:20].upper()}"

    def _symbol(
        self,
        kind: SymbolKind,
        name: str,
        qualified_name: str,
        module: ProjectModule,
        node: ast.AST,
        parent_symbol_id: str = "",
        decorators: tuple[str, ...] = (),
        parameters: tuple[str, ...] = (),
    ) -> CodeSymbol:
        source_range = node_range(str(module.path), node)
        decorator_nodes = getattr(node, "decorator_list", ())
        if decorator_nodes:
            first = min(decorator_nodes, key=lambda item: (getattr(item, "lineno", 1), getattr(item, "col_offset", 0)))
            source_range = SourceRange(
                SourceLocation(str(module.path), getattr(first, "lineno", source_range.start.line), getattr(first, "col_offset", source_range.start.column)),
                source_range.end,
            )
        symbol = CodeSymbol(
            self._symbol_id(kind, qualified_name),
            kind,
            name,
            qualified_name,
            module.module,
            source_range,
            parent_symbol_id,
            decorators,
            parameters,
            isinstance(node, ast.AsyncFunctionDef),
            node,
        )
        self.symbols[qualified_name] = symbol
        self.symbols_by_id[symbol.symbol_id] = symbol
        return symbol

    def _add_module(self, path: Path, source: str) -> None:
        module_name, is_package = self._module_name(path)
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as error:
            self.parse_errors.append((path, error))
            return
        module = ProjectModule(path, module_name, source, tree, {}, is_package)
        module.imports = self._imports(module)
        self.modules[module_name] = module

    def _decorators(self, module: ProjectModule, node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
        placeholder = ProjectFunction(module, node, "", node.body)
        return tuple(
            self.canonical(decorator.func if isinstance(decorator, ast.Call) else decorator, placeholder)
            for decorator in node.decorator_list
        )

    def _index_module(self, module: ProjectModule) -> None:
        module.symbol = self._symbol(SymbolKind.MODULE, module.module, module.module, module, module.tree)
        top_level = [
            node for node in module.tree.body
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        ]
        pseudo = ProjectFunction(module, module.tree, f"{module.module}.<module>", top_level, symbol=module.symbol)
        self.functions[pseudo.qualname] = pseudo
        for node in module.tree.body:
            self._index_definition(module, node, module.module, module.symbol.symbol_id, "", "")

    def _index_definition(
        self,
        module: ProjectModule,
        node: ast.AST,
        parent_qualname: str,
        parent_symbol_id: str,
        class_name: str,
        parent_function: str,
    ) -> None:
        if isinstance(node, ast.ClassDef):
            qualname = f"{parent_qualname}.{node.name}"
            symbol = self._symbol(SymbolKind.CLASS, node.name, qualname, module, node, parent_symbol_id)
            self.classes[qualname] = symbol
            for child in node.body:
                self._index_definition(module, child, qualname, symbol.symbol_id, node.name, parent_function)
            return
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return
        qualname = f"{parent_qualname}.{node.name}"
        kind = SymbolKind.METHOD if class_name and not parent_function else SymbolKind.NESTED_FUNCTION if parent_function else SymbolKind.FUNCTION
        parameters = tuple(arg.arg for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs])
        symbol = self._symbol(
            kind,
            node.name,
            qualname,
            module,
            node,
            parent_symbol_id,
            self._decorators(module, node),
            parameters,
        )
        function = ProjectFunction(module, node, qualname, node.body, class_name, parent_qualname, symbol)
        self.functions[qualname] = function
        for argument in function.arguments:
            arg_name = f"{qualname}.{argument.arg}"
            self._symbol(SymbolKind.PARAMETER, argument.arg, arg_name, module, argument, symbol.symbol_id)
        for child in node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self._index_definition(module, child, qualname, symbol.symbol_id, class_name, qualname)

    def _index_variable_types(self) -> None:
        for function in self.functions.values():
            for statement in function.body:
                for node in ast.walk(statement):
                    if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(node.value, ast.Call):
                        continue
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    constructor = self.canonical(node.value.func, function)
                    if constructor not in self.classes:
                        candidates = [name for name in self.classes if name.endswith(f".{constructor}")]
                        constructor = candidates[0] if len(candidates) == 1 else constructor
                    if constructor not in self.classes:
                        continue
                    for target in targets:
                        if isinstance(target, ast.Name):
                            self.variable_types[(function.qualname, target.id)] = constructor

    def canonical(self, node: ast.AST, function: ProjectFunction) -> str:
        if isinstance(node, ast.Name):
            if node.id in function.module.imports:
                return function.module.imports[node.id]
            scope = function.qualname
            while scope and scope != function.module.module:
                nested = f"{scope}.{node.id}"
                if nested in self.functions or nested in self.classes:
                    return nested
                scope = scope.rsplit(".", 1)[0]
            if function.class_name:
                method = f"{function.module.module}.{function.class_name}.{node.id}"
                if method in self.functions:
                    return method
            local = f"{function.module.module}.{node.id}"
            if local in self.functions or local in self.classes:
                return local
            return node.id
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name):
                if node.value.id in {"self", "cls"} and function.class_name:
                    return f"{function.module.module}.{function.class_name}.{node.attr}"
                receiver_type = self.variable_types.get((function.qualname, node.value.id))
                if receiver_type:
                    return f"{receiver_type}.{node.attr}"
            base = self.canonical(node.value, function)
            return f"{base}.{node.attr}" if base else node.attr
        return ""

    def resolution_for(self, call: ast.Call, caller: ProjectFunction) -> CallResolution:
        if self._resolver is None:
            from .resolver import CallResolver

            self._resolver = CallResolver(self)
        return self._resolver.resolve(call, caller)

    def resolve_function(self, call: ast.Call, caller: ProjectFunction) -> ProjectFunction | None:
        return self.resolution_for(call, caller).target

    def containing_symbol(self, path: Path | str, line: int, column: int = 0) -> CodeSymbol | None:
        resolved = Path(path).resolve()
        candidates = []
        for symbol in self.symbols.values():
            if Path(symbol.source_range.start.file).resolve() != resolved:
                continue
            start, end = symbol.source_range.start, symbol.source_range.end
            if (start.line, start.column) <= (line, column) <= (end.line, end.column):
                candidates.append(symbol)
        return min(candidates, key=lambda item: (item.source_range.end.line - item.source_range.start.line, -len(item.qualified_name)), default=None)

    def iter_function_calls(self, function: ProjectFunction) -> Iterable[ast.Call]:
        cached = self._calls_by_function.get(function.qualname)
        if cached is not None:
            return cached

        class Visitor(ast.NodeVisitor):
            def __init__(self, root: ast.AST):
                self.root = root
                self.calls: list[ast.Call] = []

            def visit_Call(self, node: ast.Call) -> None:
                self.calls.append(node)
                self.generic_visit(node)

            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
                if node is self.root:
                    self.generic_visit(node)

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                if node is self.root:
                    self.generic_visit(node)

            def visit_ClassDef(self, node: ast.ClassDef) -> None:
                if node is self.root:
                    self.generic_visit(node)

        visitor = Visitor(function.node)
        if isinstance(function.node, ast.Module):
            for statement in function.body:
                visitor.visit(statement)
        else:
            visitor.visit(function.node)
        calls = tuple(visitor.calls)
        self._calls_by_function[function.qualname] = calls
        return calls
