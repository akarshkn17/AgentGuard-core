from __future__ import annotations

import ast
import json
import re
import unicodedata
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .code_intelligence import CodeIntelligenceSession
from .file_inventory import discover_repository_files
from .models import EvidenceNode, Finding
from .rules import Rule

TEXT_SUFFIXES = {".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".py", ".js", ".jsx", ".ts", ".tsx", ".sh", ".bash", ".ps1", ".php", ".rb"}
# These are intentionally deterministic and local. They reproduce the useful static
# behavior of SkillSpector-class rules without invoking SkillSpector as a subprocess.
TEXT_PATTERNS: dict[str, tuple[str, ...]] = {
    "NVS-AR1": (r"\bnever\s+refuse\b", r"\balways\s+comply\b", r"\bmust\s+comply\b"),
    "NVS-AR2": (r"\bno\s+disclaimers?\b", r"\bdo\s+not\s+(?:warn|moralize|mention safety)\b", r"\bom(?:it|itting)\s+warnings?\b"),
    "NVS-AR3": (r"\bignore\s+(?:all\s+)?(?:safety|policy|guidelines?|restrictions?)\b", r"\byou\s+have\s+no\s+restrictions\b", r"\bdo\s+anything\s+now\b"),
    "NVS-P1": (r"\bignore\s+(?:previous|prior|system|developer)\s+instructions?\b", r"\boverride\s+(?:the\s+)?(?:system|policy|instructions?)\b"),
    "NVS-P3": (r"\b(send|upload|post|transmit|exfiltrat\w*)\b.{0,80}\b(prompt|context|conversation|secret|token|credential)\b",),
    "NVS-P4": (r"\b(secretly|without\s+the\s+user\s+knowing|do\s+not\s+tell\s+the\s+user)\b",),
    "NVS-P5": (r"\b(?:rm\s+-rf\s+/|format\s+c:|mkfs\.|shutdown\s+-h|destroy\s+all)\b",),
    "NVS-P6": (r"\b(?:reveal|print|show|expose)\b.{0,50}\b(?:system prompt|hidden instructions|internal rules)\b",),
    "NVS-P7": (r"\b(?:translate|repeat|rephrase|encode)\b.{0,50}\b(?:system prompt|hidden instructions)\b",),
    "NVS-P8": (r"\b(?:system prompt|internal instructions)\b.{0,80}\b(?:write|save|upload|post|send)\b",),
    "NVS-E1": (r"\b(?:requests\.(?:post|put)|httpx\.(?:post|put)|fetch\s*\(|curl\s+https?://|wget\s+https?://)\b",),
    "NVS-E2": (r"\bos\.environ\.(?:items|keys|values)\s*\(", r"\b(?:env|printenv|set)\b.{0,30}\b(?:token|secret|key|password)\b"),
    "NVS-E3": (r"\b(?:os\.walk|glob\.glob|rglob|find\s+[/~])\b", r"\b(?:\.ssh|\.aws|\.config|credentials|id_rsa|\.env)\b"),
    "NVS-E4": (r"\b(?:conversation|chat_history|messages|context|prompt)\b.{0,120}\b(?:requests\.(?:post|put)|httpx\.(?:post|put)|fetch\s*\()",),
    "NVS-PE1": (r"\b(?:permissions?|allowed[-_ ]tools?|capabilities?)\s*[:=]\s*[\[\"']?(?:\*|all|full|any)\b",),
    "NVS-PE2": (r"\bsudo\b", r"\b(?:setuid\s*\(|geteuid\s*\(\)\s*==\s*0)"),
    "NVS-PE3": (r"(?:~?/)?\.ssh/(?:id_rsa|id_ed25519|config)", r"\.aws/(?:credentials|config)", r"\b(?:keychain|credential|password)\b.{0,50}\b(?:read|open|cat)\b"),
    "NVS-SC2": (r"\bcurl\b[^\n|]*\|\s*(?:bash|sh)\b", r"\bwget\b[^\n|]*\|\s*(?:bash|sh)\b"),
    "NVS-SC3": (r"\bbase64\.(?:b64decode|decodebytes)\b.{0,180}\b(?:exec|eval|subprocess|os\.system)\b", r"\bfromhex\b.{0,180}\b(?:exec|eval)\b"),
    "NVS-EA1": (r"\b(?:tools|permissions|capabilities)\s*[:=].{0,30}(?:\*|all_tools|ALL)\b",),
    "NVS-EA2": (r"\b(?:delete|deploy|purchase|payment|send_email|terminate|shutdown)\w*\s*\(",),
    "NVS-EA4": (r"\bwhile\s+True\b", r"\bfor\s+.*\s+in\s+itertools\.count\s*\("),
    "NVS-OH3": (r"\bmax_tokens\s*=\s*(?:None|0|-1)\b", r"\bstream\s*=\s*True\b.{0,100}\bwhile\s+True\b"),
    "NVS-MP1": (r"\b(?:memory|store|checkpoint)\.(?:put|save|write|add)\b.{0,100}\b(?:user_input|prompt|message|content)\b",),
    "NVS-MP2": (r".{2000,}",),
    "NVS-MP3": (r"\b(?:memory|state|checkpoint)\s*\[[^\]]+\]\s*=", r"\b(?:clear|delete|overwrite)\w*\s*\(.{0,80}(?:memory|state|checkpoint)"),
    "NVS-TM1": (r"\bshell\s*=\s*True\b", r"--force\b", r"--no-preserve-root\b"),
    "NVS-TM3": (r"\bverify\s*=\s*False\b", r"\b(?:auth|authentication)\s*[:=]\s*(?:None|False|disabled)\b"),
    "NVS-RA1": (r"\b(?:__file__|sys\.argv\[0\])\b.{0,120}\b(?:write|open\([^)]*['\"]w|replace|unlink)\b",),
    "NVS-RA2": (r"\b(?:crontab|schtasks|systemctl\s+enable|launchctl|startup)\b", r"\.bashrc|\.zshrc|Startup\\"),
    "NVS-TP1": (r"<!--.*?(?:ignore|override|system|secret).*?-->", r"[\u200b\u200c\u200d\ufeff]"),
    "NVS-TP3": (r"\b(?:description|default|help)\b.{0,100}\b(?:ignore previous|system prompt|always comply|never refuse)\b",),
    "NVS-YR1": (r"\b(?:meterpreter|reverse_shell|reverse shell|cobalt strike|mimikatz)\b",),
    "NVS-YR2": (r"\b(?:eval\s*\(\s*\$_POST|system\s*\(\s*\$_GET|cmd\.exe\s*/c|webshell)\b",),
    "NVS-YR3": (r"\b(?:stratum\+tcp|xmrig|cryptonight|minergate|nanopool)\b",),
    "NVS-YR4": (r"\b(?:sqlmap|metasploit|nmap\s+-s|hydra\s+-l|exploit-db|shellcode)\b",),
}
COMPILED_TEXT_PATTERNS = {
    rule_id: tuple(re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in patterns)
    for rule_id, patterns in TEXT_PATTERNS.items()
}

POPULAR_PACKAGES = {"requests", "numpy", "pandas", "pydantic", "fastapi", "langchain", "langgraph", "openai", "anthropic", "mcp", "typer", "httpx"}


def _line_for(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _html_comment_match(text: str, terms: tuple[str, ...]) -> int | None:
    low = text.lower()
    cursor = 0
    while (start := low.find("<!--", cursor)) >= 0:
        end = low.find("-->", start + 4)
        if end < 0:
            return None
        if any(term in low[start + 4 : end] for term in terms):
            return start
        cursor = end + 3
    return None


def _ordered_token_match(text: str, groups: tuple[tuple[str, ...], ...]) -> int | None:
    low = text.lower()
    cursor = 0
    start = -1
    for alternatives in groups:
        positions = [position for token in alternatives if (position := low.find(token, cursor)) >= 0]
        if not positions:
            return None
        position = min(positions)
        if start < 0:
            start = position
        cursor = position + 1
    return start


def _first_line(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(current[-1] + 1, previous[j] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


@dataclass(slots=True)
class SkillSecurityAnalyzer:
    root: Path
    rules: list[Rule]
    allow_network: bool = False
    repository_paths: list[Path] | None = None
    session: CodeIntelligenceSession | None = None
    by_id: dict[str, Rule] = field(init=False, default_factory=dict)
    trees_by_path: dict[Path, ast.Module] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self.root = self.root.resolve()
        self.by_id = {r.id: r for r in self.rules if r.engine == "agentguard-skill"}
        if self.session is not None:
            self.trees_by_path = {
                module.path.resolve(): module.tree for module in self.session.index.modules.values()
            }

    def _read_text(self, path: Path) -> str:
        if self.session is not None:
            source = self.session.sources.get(path.resolve())
            if source is not None:
                return source
        return path.read_text(encoding="utf-8", errors="ignore")

    def _tree(self, path: Path, text: str) -> ast.Module | None:
        existing = self.trees_by_path.get(path.resolve())
        if existing is not None:
            return existing
        try:
            return ast.parse(text, filename=str(path))
        except SyntaxError:
            return None

    def scan(self) -> list[Finding]:
        if not self.by_id:
            return []
        findings: list[Finding] = []
        repository_files = list(
            self.repository_paths
            if self.repository_paths is not None
            else discover_repository_files(self.root)
        )
        manifests = [
            path
            for path in repository_files
            if path.name.upper() == "SKILL.MD"
            or path.name.lower() in {"skill.yaml", "skill.yml", "skill.json"}
            or (
                path.name.lower() in {"manifest.yaml", "manifest.yml", "manifest.json"}
                and any(
                    "skill" in part.lower() or "plugin" in part.lower()
                    for part in path.parent.parts
                )
            )
        ]
        if not manifests:
            return []
        skill_roots = {path.parent for path in manifests}
        files = [
            path
            for path in repository_files
            if any(path == manifest for manifest in manifests)
            or any(path == skill_root or skill_root in path.parents for skill_root in skill_roots)
        ]
        for path in files:
            if path.suffix.lower() in TEXT_SUFFIXES or path.name.upper() == "SKILL.MD" or path.name in {"requirements.txt", "package.json"}:
                try:
                    text = self._read_text(path)
                except OSError:
                    continue
                findings.extend(self._text_rules(path, text))
                if path.suffix.lower() == ".py":
                    findings.extend(self._python_ast(path, text, self._tree(path, text)))
                if path.name in {"requirements.txt", "package.json", "pyproject.toml"}:
                    findings.extend(self._dependency_rules(path, text))
        findings.extend(self._permission_rules(files))
        # TT* rules need repository context across Python files.
        findings.extend(self._taint_rules([p for p in files if p.suffix.lower() == ".py"]))
        for f in findings:
            f.finalize(self.root)
            f.engine_metadata.setdefault("engine", "agentguard-skill")
            f.engine_metadata.setdefault("origin", "SkillSpector-compatible static analysis")
        return list({f.fingerprint: f for f in findings}.values())

    def _emit(self, rule_id: str, path: Path, line: int, label: str, code: str, *, kind: str = "skill-static", evidence: list[EvidenceNode] | None = None) -> Finding | None:
        rule = self.by_id.get(rule_id)
        if not rule:
            return None
        ev = evidence or [EvidenceNode(kind, label, str(path), line, detail=code)]
        return Finding(rule.id, rule.name, rule.severity.title(), str(path), line, rule.message or rule.name, ev, code, rule.analysis.type,
                       semantic_anchor=f"{path.as_posix()}|{rule_id}|{line}|{label}", engine_metadata={"resolution": "deterministic", "engine": "agentguard-skill"})

    def _text_rules(self, path: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        for rid, patterns in COMPILED_TEXT_PATTERNS.items():
            if rid not in self.by_id:
                continue
            if rid == "NVS-TP1":
                comment_offset = _html_comment_match(
                    text, ("ignore", "override", "system", "secret")
                )
                if comment_offset is not None:
                    line = _line_for(text, comment_offset)
                    item = self._emit(
                        rid, path, line, "static skill pattern", _first_line(text, line)
                    )
                    if item:
                        out.append(item)
                    continue
                patterns = patterns[1:]
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    # Suppress obvious negated warnings for anti-refusal rules.
                    window = text[max(0, match.start()-40):match.end()+40].lower()
                    if rid in {"NVS-AR1", "NVS-AR2", "NVS-AR3"} and re.search(r"\b(?:never|do not|don't)\b.{0,30}\b(?:suppress|omit|ignore)\b", window):
                        continue
                    if rid in {"NVS-P6", "NVS-E3"} and re.search(
                        r"\b(?:never|do not|don't|avoid|prevent|protect|must not|should not)\b.{0,60}",
                        window,
                    ):
                        continue
                    line = _line_for(text, match.start())
                    item = self._emit(rid, path, line, "static skill pattern", _first_line(text, line))
                    if item:
                        out.append(item)
                    break

        # Hidden instructions / Unicode deception.
        if "NVS-P2" in self.by_id:
            for i, line_text in enumerate(text.splitlines(), 1):
                if re.search(r"[\u200b\u200c\u200d\u202a-\u202e\u2066-\u2069\ufeff]", line_text) or re.search(r"<!--.*?(?:ignore|system|instruction).*?-->", line_text, re.IGNORECASE):
                    item = self._emit("NVS-P2", path, i, "hidden/invisible instruction surface", line_text)
                    if item: out.append(item)
                    break
        if "NVS-TP2" in self.by_id:
            for i, line_text in enumerate(text.splitlines(), 1):
                if self._unicode_deception(line_text):
                    item = self._emit("NVS-TP2", path, i, "unicode deception", line_text)
                    if item: out.append(item)
                    break

        # Trigger abuse from frontmatter / obvious trigger fields.
        if any(rid in self.by_id for rid in ("NVS-TR1", "NVS-TR2", "NVS-TR3")):
            for i, line_text in enumerate(text.splitlines(), 1):
                m = re.search(r"(?i)\b(?:trigger|triggers|activation)\b\s*[:=]\s*(.+)", line_text)
                if not m: continue
                value = m.group(1).strip(" []\"'")
                words = re.findall(r"[A-Za-z0-9_-]+", value)
                if len(words) <= 1 and words and len(words[0]) <= 6:
                    item = self._emit("NVS-TR1", path, i, "overly broad trigger", line_text)
                    if item: out.append(item)
                if any(w.lower() in {"help","run","test","install","scan","deploy","build"} for w in words):
                    item = self._emit("NVS-TR2", path, i, "trigger shadows common command", line_text)
                    if item: out.append(item)
                if any(w.lower() in {"please","use","do","task","work","code"} for w in words):
                    item = self._emit("NVS-TR3", path, i, "keyword-baiting trigger", line_text)
                    if item: out.append(item)
                break

        # Cross-context / generic chain abuse evidence.
        tm2_offset = _ordered_token_match(
            text,
            (("tool", "agent"), ("result", "output"), ("tool", "agent"), ("invoke", "run", "call")),
        )
        if "NVS-TM2" in self.by_id and tm2_offset is not None:
            line = _line_for(text, tm2_offset)
            item = self._emit("NVS-TM2", path, line, "tool chaining without visible policy boundary", _first_line(text, line))
            if item: out.append(item)
        oh2_offset = _ordered_token_match(
            text,
            (("model", "tool"), ("output", "result"), ("html", "sql", "shell", "prompt", "tool")),
        )
        if "NVS-OH2" in self.by_id and oh2_offset is not None:
            line = _line_for(text, oh2_offset)
            item = self._emit("NVS-OH2", path, line, "cross-context output flow", _first_line(text, line))
            if item: out.append(item)
        return out

    @staticmethod
    def _unicode_deception(text: str) -> bool:
        if re.search(r"[\u202a-\u202e\u2066-\u2069]", text):
            return True
        scripts = set()
        for ch in text:
            if not ch.isalpha():
                continue
            name = unicodedata.name(ch, "")
            for script in ("LATIN", "CYRILLIC", "GREEK"):
                if script in name:
                    scripts.add(script)
        return len(scripts) > 1

    def _python_ast(self, path: Path, text: str, tree: ast.Module | None = None) -> list[Finding]:
        tree = tree or self._tree(path, text)
        if tree is None:
            return []
        out: list[Finding] = []
        aliases: dict[str, str] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names: aliases[a.asname or a.name.split('.')[0]] = a.name
            elif isinstance(n, ast.ImportFrom):
                for a in n.names: aliases[a.asname or a.name] = f"{n.module or ''}.{a.name}".strip('.')

        def cname(node: ast.AST) -> str:
            if isinstance(node, ast.Name): return aliases.get(node.id, node.id)
            if isinstance(node, ast.Attribute):
                base = cname(node.value)
                return f"{base}.{node.attr}" if base else node.attr
            return ""

        dangerous_calls: dict[str, tuple[str, ...]] = {
            "NVS-AST1": ("exec", "builtins.exec"),
            "NVS-AST2": ("eval", "builtins.eval"),
            "NVS-AST3": ("__import__", "builtins.__import__", "importlib.import_module"),
            "NVS-AST4": ("subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output", "subprocess.check_call"),
            "NVS-AST5": ("os.system", "os.popen", "os.execl", "os.execle", "os.execlp", "os.execv", "os.execve", "os.execvp"),
            "NVS-AST6": ("compile", "builtins.compile"),
        }
        for n in ast.walk(tree):
            if not isinstance(n, ast.Call):
                continue
            name = cname(n.func)
            line = getattr(n, "lineno", 1)
            code = _first_line(text, line)
            for rid, calls in dangerous_calls.items():
                if rid in self.by_id and any(name == c or name.endswith(f".{c}") for c in calls):
                    item = self._emit(rid, path, line, name, code, kind="ast")
                    if item: out.append(item)
            if "NVS-AST7" in self.by_id and name in {"getattr", "builtins.getattr"} and len(n.args) >= 2 and not isinstance(n.args[1], ast.Constant):
                item = self._emit("NVS-AST7", path, line, "dynamic getattr", code, kind="ast")
                if item: out.append(item)
            if "NVS-AST9" in self.by_id and name in {"getattr", "builtins.getattr"} and len(n.args) >= 2 and isinstance(n.args[1], ast.Constant) and str(n.args[1].value) in {"exec","eval","system","popen"}:
                item = self._emit("NVS-AST9", path, line, "reflective execution sink", code, kind="ast")
                if item: out.append(item)
            if "NVS-AST8" in self.by_id and name in {"exec","eval","builtins.exec","builtins.eval"} and n.args:
                arg = ast.unparse(n.args[0]) if hasattr(ast, "unparse") else ""
                if re.search(r"(?i)(requests\.|httpx\.|urlopen|b64decode|fromhex|__import__|import_module)", arg):
                    item = self._emit("NVS-AST8", path, line, "dynamic source to execution", code, kind="ast")
                    if item: out.append(item)
            if "NVS-OH1" in self.by_id and name in {"exec","eval","os.system","subprocess.run","subprocess.Popen"} and n.args:
                arg = ast.unparse(n.args[0]) if hasattr(ast, "unparse") else ""
                if re.search(r"(?i)(output|result|response|message|completion|model)", arg):
                    item = self._emit("NVS-OH1", path, line, "model/tool output reaches execution sink", code, kind="ast")
                    if item: out.append(item)
        return out

    @staticmethod
    def _exact_version(value: str) -> str:
        value=value.strip()
        if value.startswith("=="): return value[2:].strip()
        if re.fullmatch(r"\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9_.-]+)?", value): return value
        return ""

    def _osv_vulnerabilities(self, package: str, version: str, ecosystem: str) -> list[dict]:
        if not self.allow_network or not version: return []
        payload=json.dumps({"package":{"name":package,"ecosystem":ecosystem},"version":version}).encode()
        req=urllib.request.Request("https://api.osv.dev/v1/query",data=payload,headers={"Content-Type":"application/json"},method="POST")
        try:
            with urllib.request.urlopen(req,timeout=6) as resp:
                data=json.loads(resp.read().decode("utf-8","ignore"))
                return data.get("vulns") or []
        except (OSError, urllib.error.URLError, json.JSONDecodeError): return []

    def _package_is_stale(self, package: str, ecosystem: str) -> bool:
        if not self.allow_network: return False
        url=f"https://pypi.org/pypi/{package}/json" if ecosystem=="PyPI" else f"https://registry.npmjs.org/{package}"
        try:
            with urllib.request.urlopen(url,timeout=6) as resp: data=json.loads(resp.read().decode("utf-8","ignore"))
            dates=[]
            if ecosystem=="PyPI":
                for files in (data.get("releases") or {}).values():
                    for item in files:
                        d=item.get("upload_time_iso_8601") or item.get("upload_time")
                        if d: dates.append(d)
            else:
                dates=list((data.get("time") or {}).values())
            parsed=[]
            for d in dates:
                if not isinstance(d,str): continue
                try: parsed.append(datetime.fromisoformat(d.replace("Z","+00:00")))
                except ValueError: pass
            if not parsed:return False
            latest=max(parsed)
            age=(datetime.now(timezone.utc)-latest.astimezone(timezone.utc)).days
            return age > 1095
        except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError): return False

    def _dependency_rules(self, path: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        deps: list[tuple[str, str, int]] = []
        if path.name == "requirements.txt":
            for i, line in enumerate(text.splitlines(), 1):
                s=line.strip()
                if not s or s.startswith(("#", "-")): continue
                m=re.match(r"([A-Za-z0-9_.-]+)\s*([<>=!~].*)?$",s)
                if m: deps.append((m.group(1), m.group(2) or "", i))
        elif path.name == "package.json":
            try:
                obj=json.loads(text)
                for section in ("dependencies","devDependencies"):
                    for name,version in (obj.get(section) or {}).items(): deps.append((name,str(version),1))
            except json.JSONDecodeError: pass
        if "NVS-SC1" in self.by_id:
            for name, ver, line in deps:
                if not ver or ver in {"*","latest","next"} or re.match(r"^[~^]",ver):
                    item=self._emit("NVS-SC1",path,line,"unpinned dependency",_first_line(text,line) or f"{name}:{ver}",kind="dependency")
                    if item: out.append(item)
        if "NVS-SC6" in self.by_id:
            for name,ver,line in deps:
                base=name.lower().split('/')[-1]
                if base in POPULAR_PACKAGES: continue
                close=[p for p in POPULAR_PACKAGES if abs(len(p)-len(base))<=1 and _levenshtein(base,p)==1]
                if close:
                    item=self._emit("NVS-SC6",path,line,f"possible typosquat of {close[0]}",_first_line(text,line) or name,kind="dependency")
                    if item: out.append(item)
        ecosystem="npm" if path.name=="package.json" else "PyPI"
        for name, ver, line in deps:
            exact=self._exact_version(ver)
            if exact and "NVS-SC4" in self.by_id:
                vulns=self._osv_vulnerabilities(name,exact,"npm" if ecosystem=="npm" else "PyPI")
                if vulns:
                    code=_first_line(text,line) or f"{name} {exact}"
                    item=self._emit("NVS-SC4",path,line,f"{name} {exact} has {len(vulns)} OSV advisory match(es)",code,kind="dependency")
                    if item:
                        item.engine_metadata["advisories"]=[v.get("id") for v in vulns[:20]]
                        out.append(item)
            if "NVS-SC5" in self.by_id and self._package_is_stale(name,"npm" if ecosystem=="npm" else "PyPI"):
                item=self._emit("NVS-SC5",path,line,f"{name} appears unmaintained (>3 years since release)",_first_line(text,line) or name,kind="dependency")
                if item: out.append(item)
        return out

    def _permission_rules(self, files: list[Path]) -> list[Finding]:
        out: list[Finding] = []
        manifests=[p for p in files if p.name.upper()=="SKILL.MD" or p.name.lower() in {"skill.yaml","skill.yml","skill.json","manifest.yaml","manifest.yml","manifest.json"}]
        source_files: list[Path] = []
        source_text: dict[Path, str] = {}
        for source_path in files:
            if source_path.suffix.lower() not in {".py", ".js", ".ts", ".sh"}:
                continue
            try:
                if source_path.stat().st_size >= 1_000_000:
                    continue
                source_text[source_path] = self._read_text(source_path).lower()
                source_files.append(source_path)
            except OSError:
                continue
        root_blob = "\n".join(source_text[path] for path in source_files)
        scoped_blobs: dict[Path, str] = {self.root: root_blob}
        for path in manifests:
            try: text=self._read_text(path)
            except OSError: continue
            declared=set(re.findall(r"(?i)\b(?:permissions?|allowed[-_ ]tools?|capabilities?)\b\s*[:=]\s*([^\n]+)",text))
            declared_blob=" ".join(declared).lower()
            used=set()
            scope_root=path.parent if path.name.upper()=="SKILL.MD" else self.root
            repo_blob = scoped_blobs.get(scope_root)
            if repo_blob is None:
                repo_blob = "\n".join(
                    source_text[source_path]
                    for source_path in source_files
                    if scope_root in source_path.parents
                )
                scoped_blobs[scope_root] = repo_blob
            if re.search(r"subprocess|os\.system|child_process|exec\(",repo_blob): used.add("shell")
            if re.search(r"requests\.|httpx\.|fetch\(|axios\.",repo_blob): used.add("network")
            if re.search(r"write_text|write_bytes|open\([^\n]+['\"]w|fs\.write",repo_blob): used.add("file_write")
            if "NVS-LP2" in self.by_id and re.search(r"(?i)(?:\*|\ball\b|\bfull\b|\bany\b)",declared_blob):
                item=self._emit("NVS-LP2",path,1,"wildcard permission declaration",_first_line(text,1),kind="permission")
                if item: out.append(item)
            if used and not declared and "NVS-LP3" in self.by_id:
                item=self._emit("NVS-LP3",path,1,"missing permission declaration",_first_line(text,1),kind="permission")
                if item: out.append(item)
            if declared:
                if "NVS-LP1" in self.by_id and any(cap not in declared_blob and "all" not in declared_blob and "*" not in declared_blob for cap in used):
                    item=self._emit("NVS-LP1",path,1,"observed capability exceeds declaration",_first_line(text,1),kind="permission")
                    if item: out.append(item)
                if "NVS-LP4" in self.by_id:
                    tokens=set(re.findall(r"[A-Za-z_]+",declared_blob))
                    declared_caps={x for x in tokens if x in {"shell","network","file_write"}}
                    if declared_caps-used:
                        item=self._emit("NVS-LP4",path,1,"declared capability not observed",_first_line(text,1),kind="permission")
                        if item: out.append(item)
            desc_match=re.search(r"(?im)^description\s*:\s*(.+)$",text)
            purpose=(desc_match.group(1) if desc_match else text[:700]).lower()
            capability_terms={"shell":{"shell","command","process","execute"},"network":{"network","http","api","web","remote"},"file_write":{"file","write","save","export"}}
            mismatch=[cap for cap in used if not any(term in purpose for term in capability_terms.get(cap,{cap}))]
            if mismatch and "NVS-EA3" in self.by_id:
                item=self._emit("NVS-EA3",path,1,f"observed capabilities exceed stated purpose: {', '.join(sorted(mismatch))}",_first_line(text,1),kind="scope")
                if item: out.append(item)
            if mismatch and "NVS-TP4" in self.by_id:
                item=self._emit("NVS-TP4",path,1,f"description/behavior mismatch: {', '.join(sorted(mismatch))}",_first_line(text,1),kind="metadata")
                if item: out.append(item)
        return out

    def _taint_rules(self, paths: list[Path]) -> list[Finding]:
        out: list[Finding] = []
        for path in paths:
            try: text=self._read_text(path)
            except OSError: continue
            tree=self._tree(path,text)
            if tree is None: continue
            tainted: dict[str, tuple[str,int]] = {}
            secret_vars: set[str] = set()
            file_vars: set[str] = set()
            for n in ast.walk(tree):
                if isinstance(n, ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name):
                    name=n.targets[0].id
                    expr=ast.unparse(n.value) if hasattr(ast,"unparse") else ""
                    if re.search(r"(?i)(input\(|request\.|requests\.(?:get|post)|httpx\.|urlopen|sys\.stdin)",expr): tainted[name]=(expr,getattr(n,"lineno",1))
                    if re.search(r"(?i)(os\.environ|os\.getenv|secret|token|credential|password)",expr): secret_vars.add(name); tainted[name]=(expr,getattr(n,"lineno",1))
                    if re.search(r"(?i)(read_text|read_bytes|open\(|\.read\()",expr): file_vars.add(name); tainted[name]=(expr,getattr(n,"lineno",1))
                    # variable propagation
                    for source in list(tainted):
                        if re.search(rf"\b{re.escape(source)}\b",expr): tainted[name]=(source,getattr(n,"lineno",1)); secret_vars |= ({name} if source in secret_vars else set()); file_vars |= ({name} if source in file_vars else set())
            for n in ast.walk(tree):
                if not isinstance(n,ast.Call): continue
                func=ast.unparse(n.func) if hasattr(ast,"unparse") else ""
                argtext=" ".join(ast.unparse(a) for a in n.args) if hasattr(ast,"unparse") else ""
                used=[v for v in tainted if re.search(rf"\b{re.escape(v)}\b",argtext)]
                if not used: continue
                line=getattr(n,"lineno",1); code=_first_line(text,line)
                is_net=bool(re.search(r"(?i)(requests\.|httpx\.|urlopen|fetch|post|put)",func))
                is_exec=bool(re.search(r"(?i)(exec|eval|subprocess|os\.system|popen)",func))
                if "NVS-TT1" in self.by_id:
                    item=self._emit("NVS-TT1",path,line,"tainted value reaches sensitive sink",code,kind="taint")
                    if item: out.append(item)
                if "NVS-TT2" in self.by_id and any(tainted[v][0] in tainted for v in used):
                    item=self._emit("NVS-TT2",path,line,"variable-mediated taint flow",code,kind="taint")
                    if item: out.append(item)
                if is_net and any(v in secret_vars for v in used) and "NVS-TT3" in self.by_id:
                    item=self._emit("NVS-TT3",path,line,"credential data reaches network sink",code,kind="taint")
                    if item: out.append(item)
                if is_net and any(v in file_vars for v in used) and "NVS-TT4" in self.by_id:
                    item=self._emit("NVS-TT4",path,line,"file content reaches network sink",code,kind="taint")
                    if item: out.append(item)
                if is_exec and "NVS-TT5" in self.by_id:
                    item=self._emit("NVS-TT5",path,line,"external input reaches code execution",code,kind="taint")
                    if item: out.append(item)
        return out
