from __future__ import annotations

import ast
from dataclasses import dataclass

from .index import ProjectFunction, ProjectIndex
from .models import ResolutionConfidence


@dataclass(frozen=True, slots=True)
class CallResolution:
    canonical_name: str
    target: ProjectFunction | None
    confidence: ResolutionConfidence
    method: str
    candidates: tuple[str, ...] = ()


class CallResolver:
    def __init__(self, index: ProjectIndex):
        self.index = index

    def resolve(self, call: ast.Call, caller: ProjectFunction) -> CallResolution:
        name = self.index.canonical(call.func, caller)
        if name in self.index.functions:
            return CallResolution(name, self.index.functions[name], ResolutionConfidence.EXACT, "qualified-name")
        if isinstance(call.func, ast.Name):
            imported = caller.module.imports.get(call.func.id)
            if imported in self.index.functions:
                return CallResolution(imported, self.index.functions[imported], ResolutionConfidence.EXACT, "import-alias")
        candidates = tuple(sorted(qualname for qualname in self.index.functions if qualname.endswith(f".{name}")))
        if len(candidates) == 1:
            return CallResolution(name, self.index.functions[candidates[0]], ResolutionConfidence.MEDIUM, "unique-suffix", candidates)
        if candidates:
            return CallResolution(name, None, ResolutionConfidence.LOW, "ambiguous-suffix", candidates)
        return CallResolution(name, None, ResolutionConfidence.UNRESOLVED, "external-or-unresolved")
