from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any

import tomllib
import yaml

from .code_intelligence import CodeIntelligenceSession, ProjectIndex, ProjectModule
from .file_inventory import discover_repository_files
from .frameworks import (
    AGENT_CONSTRUCTORS,
    MCP_PROMPT_DECORATORS,
    MCP_RESOURCE_DECORATORS,
    MCP_SERVER_CONSTRUCTORS,
    MEMORY_CONSTRUCTORS,
    MODEL_CONSTRUCTORS,
    RETRIEVER_HINTS,
    TOOL_DECORATORS,
    VECTOR_CONSTRUCTORS,
)
from .models import InventoryEntity, Relationship

CATEGORY_BY_TYPE={
    "agent":"agentic","sub_agent":"agentic","orchestrator":"agentic","agent_proxy":"agentic",
    "tool":"tooling","function_tool":"tooling","skill":"tooling","plugin":"tooling",
    "mcp_server":"mcp","mcp_client":"mcp","mcp_gateway":"mcp","mcp_tool":"mcp","mcp_resource":"mcp","mcp_prompt":"mcp",
    "model":"model_runtime","embedding":"model_runtime","embedding_model":"model_runtime","llm_endpoint":"model_runtime","model_endpoint":"model_runtime",
    "vector_store":"data_retrieval","retriever":"data_retrieval","dataset":"data_retrieval","knowledge_base":"data_retrieval","feature_store":"data_retrieval","rag_pipeline":"data_retrieval",
    "memory":"memory_state","checkpoint_store":"memory_state","prompt":"prompting","guardrail":"safety","observability":"operations","deployment":"operations","identity":"operations","provider":"operations","service":"operations",
    "dependency":"dependency","package":"dependency","capability":"capability",
}
RELATIONSHIP_KEYWORDS={"tools":"USES_TOOL","handoffs":"USES_AGENT","agents":"USES_AGENT","sub_agents":"USES_AGENT","model":"USES_MODEL","memory":"USES_MEMORY","retriever":"USES_RETRIEVER","vector_store":"USES_VECTOR_STORE","mcp_servers":"USES_MCP_SERVER","mcp_server":"USES_MCP_SERVER","guardrails":"USES_GUARDRAIL","guardrail":"USES_GUARDRAIL"}
CAPABILITY_BY_CALL={
    "os.system":"process.execute","subprocess.run":"process.execute","subprocess.Popen":"process.execute","subprocess.call":"process.execute","eval":"code.execute","exec":"code.execute",
    "requests.get":"network.egress","requests.post":"network.egress","requests.request":"network.egress","httpx.get":"network.egress","httpx.post":"network.egress","fetch":"network.egress","axios.get":"network.egress","axios.post":"network.egress",
    "open":"file.access","Path.read_text":"file.read","Path.write_text":"file.write","cursor.execute":"database.query","execute":"database.query",
}
FRAMEWORK_PACKAGE_KEYS={"langchain":("langchain","langchain-openai","langchain-anthropic","langchain-google-genai","langchain-aws"),"langgraph":("langgraph",),"openai":("openai",),"openai-agents":("openai-agents","openai_agents"),"anthropic":("anthropic",),"aws-bedrock":("boto3","langchain-aws"),"google-vertexai":("google-cloud-aiplatform","google-generativeai","langchain-google-genai"),"huggingface-transformers":("transformers",),"mcp":("mcp",),"google-adk":("google-adk","google_adk"),"crewai":("crewai",),"autogen":("autogen","pyautogen"),"llamaindex":("llama-index","llama_index"),"semantic-kernel":("semantic-kernel",)}
PROMPT_CONSTRUCTORS={"PromptTemplate","ChatPromptTemplate","SystemMessagePromptTemplate","HumanMessagePromptTemplate"}
GUARDRAIL_HINTS=("guardrail","contentfilter","safetyfilter","moderation")
AGENT_BASE_HINTS=("Agent","BaseAgent","ConversableAgent","AssistantAgent","LlmAgent","ChatAgent")


def _string(node: ast.AST|None)->str:
    return node.value if isinstance(node,ast.Constant) and isinstance(node.value,str) else ""

def _canonical(index:ProjectIndex,module:ProjectModule,node:ast.AST)->str:
    ctx=index.functions.get(f"{module.module}.<module>")
    return index.canonical(node,ctx) if ctx else ""

def _list_nodes(node:ast.AST|None)->list[ast.AST]:
    if node is None:return []
    return list(node.elts) if isinstance(node,(ast.List,ast.Tuple,ast.Set)) else [node]

def _static_value(node:ast.AST|None,constants:dict[str,Any]|None=None)->Any:
    if isinstance(node,ast.Constant):return node.value
    if isinstance(node,ast.Name) and constants and node.id in constants:return constants[node.id]
    if isinstance(node,(ast.List,ast.Tuple,ast.Set)):
        values=[_static_value(item,constants) for item in node.elts]
        return values if all(value is not None for value in values) else None
    if isinstance(node,ast.Dict):
        keys=[_static_value(item,constants) for item in node.keys]; values=[_static_value(item,constants) for item in node.values]
        return dict(zip(keys,values,strict=True)) if all(item is not None for item in [*keys,*values]) else None
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr in {"getenv","get"} and len(node.args)>=2:
        return _static_value(node.args[1],constants)
    return None

def _configuration_source(node:ast.AST|None,sources:dict[str,str]|None=None)->str:
    if isinstance(node,ast.Constant):return "literal"
    if isinstance(node,ast.Name):return (sources or {}).get(node.id,"module_constant")
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute):
        if node.func.attr=="getenv":return "environment_default"
        if node.func.attr=="get":return "configuration_default"
    return "static_expression"


class InventoryDiscoverer:
    """Repository AI inventory with stable identity and explicit version provenance."""
    def __init__(self,root:Path,session:CodeIntelligenceSession|None=None):
        self.root=root.resolve(); self.session=session; self.repo_identity=self._repo_identity(); self.packages=self._package_versions(); self.project_version=self._project_version(); self.git=self._git_context()
        self.entities:list[InventoryEntity]=[]; self.relationships:list[Relationship]=[]; self.variables:dict[str,dict[str,InventoryEntity]]={}; self.symbols:dict[str,InventoryEntity]={}; self.functions:dict[str,tuple[ProjectModule,ast.AST]]={}

    def _repo_identity(self)->str:
        try:
            v=subprocess.check_output(["git","config","--get","remote.origin.url"],cwd=self.root,text=True,stderr=subprocess.DEVNULL).strip(); return v or self.root.name
        except (OSError,subprocess.SubprocessError): return self.root.name

    def _git_cmd(self,args:list[str])->str:
        try:return subprocess.check_output(args,cwd=self.root,text=True,stderr=subprocess.DEVNULL).strip()
        except (OSError,subprocess.SubprocessError):return ""

    def _git_context(self)->dict[str,str]:
        tag=self._git_cmd(["git","describe","--tags","--exact-match","HEAD"])
        return {"commit":self._git_cmd(["git","rev-parse","HEAD"]),"branch":self._git_cmd(["git","branch","--show-current"]),"tag":tag,"remote":self.repo_identity if self.repo_identity!=self.root.name else ""}

    def git_context(self)->dict[str,str]: return dict(self.git)

    def _project_version(self)->tuple[str,str]:
        p=self.root/"pyproject.toml"
        if p.exists():
            try:
                v=str(tomllib.loads(p.read_text(encoding="utf-8")).get("project",{}).get("version") or "").strip()
                if v:return v,"project_manifest"
            except (OSError,tomllib.TOMLDecodeError):pass
        p=self.root/"package.json"
        if p.exists():
            try:
                v=str(json.loads(p.read_text(encoding="utf-8")).get("version") or "").strip()
                if v:return v,"project_manifest"
            except (OSError,json.JSONDecodeError):pass
        return "",""

    def _package_versions(self)->dict[str,str]:
        versions={}
        p=self.root/"pyproject.toml"
        if p.exists():
            try:
                for dep in tomllib.loads(p.read_text(encoding="utf-8")).get("project",{}).get("dependencies",[]) or []:
                    m=re.match(r"\s*([A-Za-z0-9_.-]+)\s*(.*)",str(dep));
                    if m:versions[m.group(1).lower()]=m.group(2).strip() or "declared"
            except (OSError,tomllib.TOMLDecodeError,AttributeError):pass
        for name in ("requirements.txt","requirements-dev.txt"):
            p=self.root/name
            if not p.exists():continue
            for line in p.read_text(encoding="utf-8",errors="ignore").splitlines():
                s=line.strip()
                if not s or s.startswith(("#","-")):continue
                m=re.match(r"([A-Za-z0-9_.-]+)\s*([<>=!~].*)?$",s)
                if m:versions[m.group(1).lower()]=(m.group(2) or "declared").strip()
        p=self.root/"package.json"
        if p.exists():
            try:
                d=json.loads(p.read_text(encoding="utf-8"))
                for sec in ("dependencies","devDependencies","peerDependencies"):
                    for k,v in (d.get(sec) or {}).items():versions[str(k).lower()]=str(v)
            except (OSError,json.JSONDecodeError):pass
        return versions

    @staticmethod
    def _framework(symbol:str)->str:
        low=symbol.lower()
        if "langgraph" in low or symbol.endswith("StateGraph"):return "langgraph"
        if "langchain" in low:return "langchain"
        if "azure" in low and "openai" in low:return "openai"
        if low.startswith("agents.") or "openai.agents" in low:return "openai-agents"
        if "openai" in low:return "openai"
        if "anthropic" in low:return "anthropic"
        if "bedrock" in low:return "aws-bedrock"
        if any(value in low for value in ("vertexai","generativemodel","gemini","google.generative")):return "google-vertexai"
        if any(value in low for value in ("transformers","huggingface","from_pretrained")):return "huggingface-transformers"
        if "crewai" in low:return "crewai"
        if "autogen" in low:return "autogen"
        if "llama_index" in low or "llamaindex" in low:return "llamaindex"
        if "google" in low and ("adk" in low or "agent" in low):return "google-adk"
        if "semantic_kernel" in low or "semantickernel" in low:return "semantic-kernel"
        if "mcp" in low:return "mcp"
        return ""

    def _framework_version(self,framework:str)->tuple[str,str]:
        for key in FRAMEWORK_PACKAGE_KEYS.get(framework,(framework,)):
            if key and key.lower() in self.packages:return key,self.packages[key.lower()]
        return "",""

    def _stable_id(self,etype:str,qualified:str)->str:
        digest=hashlib.sha256(f"{self.repo_identity}|{etype}|{qualified.lower()}".encode()).hexdigest()[:16]
        return f"{etype.upper()}-{digest}"

    def _version(self,etype:str,content_hash:str,explicit:str="",model_id:str="")->tuple[str,str,str,dict[str,Any]]:
        if model_id:
            if explicit:return explicit,"model_revision","declared",{"model_identifier":model_id,"model_revision":explicit}
            return "unknown","unknown","unknown",{"model_identifier":model_id,"revision":"not_observed"}
        if explicit:return explicit,"constructor","declared",{"declared_version":explicit}
        pv,ps=self.project_version
        if pv and etype in {"agent","sub_agent","orchestrator","agent_proxy","tool","mcp_tool","mcp_server","skill","plugin","prompt","guardrail"}:
            return pv,ps,"declared",{"project_version":pv}
        if self.git.get("tag"):return self.git["tag"],"git_tag","git-tag",{"git_tag":self.git["tag"]}
        if self.git.get("commit"):return self.git["commit"][:12],"git_commit","git-commit",{"git_commit":self.git["commit"]}
        return f"rev-{content_hash[:12]}","content_hash","content-digest",{"sha256":content_hash}

    def _add(self,etype:str,name:str,qualified:str,path:Path,line:int,definition:str,framework:str="",attributes:dict[str,Any]|None=None,detection_source:str="code_analysis",explicit_version:str="",model_id:str="")->InventoryEntity:
        eid=self._stable_id(etype,qualified); existing=next((e for e in self.entities if e.entity_id==eid),None)
        if existing:
            if explicit_version and existing.version_source in {"git_commit","content_hash","project_manifest"}: existing.version=explicit_version; existing.version_source="agent_manifest"; existing.version_scheme="declared"; existing.version_evidence={"declared_version":explicit_version}; existing.finalize(self.root)
            if attributes:existing.attributes.update(attributes)
            return existing
        content_hash=hashlib.sha256(definition.encode()).hexdigest(); pkg,pkgv=self._framework_version(framework); version,vsource,vscheme,vevidence=self._version(etype,content_hash,explicit_version,model_id)
        e=InventoryEntity(eid,etype,name,str(path),line,framework,pkgv,content_hash,{"detection_method":"resolved_ast",**(attributes or {})},qualified,category=CATEGORY_BY_TYPE.get(etype,"other"),version=version,version_source=vsource,package_name=pkg,package_version=pkgv,detection_source=detection_source,bom_ref=eid,version_scheme=vscheme,version_evidence=vevidence)
        e.finalize(self.root); self.entities.append(e); self.symbols[qualified]=e; return e

    def _relationship(self,s:InventoryEntity,relation:str,t:InventoryEntity,path:Path,line:int,attrs:dict[str,Any]|None=None)->None:
        evidence={"file":str(path),"line":line}
        self.relationships.append(Relationship(
            s.entity_id,
            relation,
            t.entity_id,
            str(path),
            line,
            {"resolution":"exact",**(attrs or {})},
            relationship_type="explicit/direct",
            confidence="exact",
            derivation_method="resolved-ast-reference",
            source_evidence=[evidence],
        ))

    def _discover_functions(self,index:ProjectIndex,module:ProjectModule)->None:
        vars=self.variables.setdefault(module.module,{})
        for node in ast.walk(module.tree):
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                q=f"{module.module}.{node.name}"; self.functions[q]=(module,node)
                for dec in node.decorator_list:
                    target=dec.func if isinstance(dec,ast.Call) else dec; dn=_canonical(index,module,target)
                    if any(dn.endswith(x) for x in TOOL_DECORATORS):
                        et="mcp_tool" if "mcp" in dn.lower() else "tool"; e=self._add(et,node.name,q,module.path,node.lineno,ast.get_source_segment(module.source,node) or node.name,"mcp" if et=="mcp_tool" else self._framework(dn),{"decorator":dn}); vars[node.name]=e
                    if any(dn.endswith(x) for x in MCP_RESOURCE_DECORATORS):vars[node.name]=self._add("mcp_resource",node.name,q,module.path,node.lineno,ast.get_source_segment(module.source,node) or node.name,"mcp",{"decorator":dn})
                    if any(dn.endswith(x) for x in MCP_PROMPT_DECORATORS):vars[node.name]=self._add("mcp_prompt",node.name,q,module.path,node.lineno,ast.get_source_segment(module.source,node) or node.name,"mcp",{"decorator":dn})
            elif isinstance(node,ast.ClassDef):
                bases=[_canonical(index,module,b) for b in node.bases]
                if any(any(h.lower()==b.split('.')[-1].lower() or h.lower() in b.lower() for h in AGENT_BASE_HINTS) for b in bases):
                    q=f"{module.module}.{node.name}"; e=self._add("agent",node.name,q,module.path,node.lineno,ast.get_source_segment(module.source,node) or node.name,self._framework(" ".join(bases)),{"bases":bases,"construction":"class"}); vars[node.name]=e

    def _infer_function_entity(self,module:ProjectModule,node:ast.AST,etype:str)->InventoryEntity|None:
        if isinstance(node,ast.Name):
            existing=self.variables.get(module.module,{}).get(node.id)
            if existing:return existing
            q=f"{module.module}.{node.id}"
            fn=self.functions.get(q)
            if fn:
                m,n=fn; e=self._add(etype,node.id,q,m.path,getattr(n,"lineno",1),ast.get_source_segment(m.source,n) or node.id,self._framework(q),{"inferred_from":"constructor_reference"}); self.variables.setdefault(module.module,{})[node.id]=e; return e
        return None

    def _discover_assignments(self,index:ProjectIndex,module:ProjectModule)->None:
        vars=self.variables.setdefault(module.module,{})
        constants:dict[str,Any]={}
        constant_sources:dict[str,str]={}
        for statement in module.tree.body:
            if isinstance(statement,(ast.Assign,ast.AnnAssign)):
                target=statement.targets[0] if isinstance(statement,ast.Assign) and statement.targets else statement.target
                value=_static_value(statement.value,constants)
                if isinstance(target,ast.Name) and value is not None:
                    constants[target.id]=value
                    constant_sources[target.id]=_configuration_source(statement.value,constant_sources)
        for node in module.tree.body:
            if not isinstance(node,(ast.Assign,ast.AnnAssign)) or not isinstance(node.value,ast.Call):continue
            target_node=node.targets[0] if isinstance(node,ast.Assign) and node.targets else node.target
            if not isinstance(target_node,ast.Name):continue
            target=target_node.id; call=node.value; ctor=_canonical(index,module,call.func); tail=ctor.split('.')[-1]; kw={k.arg:k.value for k in call.keywords if k.arg}; display=_string(kw.get("name")) or (_string(call.args[0]) if call.args else "") or target; framework=self._framework(ctor); et=""
            if tail in {x.split('.')[-1] for x in MCP_SERVER_CONSTRUCTORS}:et,framework="mcp_server","mcp"
            elif tail in {x.split('.')[-1] for x in AGENT_CONSTRUCTORS}:et="orchestrator" if tail=="StateGraph" else "agent"
            elif tail in {x.split('.')[-1] for x in MODEL_CONSTRUCTORS} or (tail=="from_pretrained" and any(value in ctor for value in ("AutoModel","AutoTokenizer","transformers"))):et="model"
            elif tail in {x.split('.')[-1] for x in VECTOR_CONSTRUCTORS}:et="vector_store"
            elif tail in {x.split('.')[-1] for x in MEMORY_CONSTRUCTORS}:et="memory"
            elif tail in PROMPT_CONSTRUCTORS:et="prompt"
            elif any(h in tail.lower() for h in GUARDRAIL_HINTS):et="guardrail"
            elif any(h.lower() in ctor.lower() for h in RETRIEVER_HINTS):et="retriever"
            elif "mcp" in ctor.lower() and (tail.endswith("Client") or "stdio_client" in ctor or "streamable_http_client" in ctor):et,framework="mcp_client","mcp"
            if not et:continue
            attrs={"constructor":ctor}
            parameters={}
            for k,vnode in kw.items():
                v=_static_value(vnode,constants)
                if v is not None:parameters[k]=v
            for k in ("model","model_name","model_id","modelId","base_url","endpoint","azure_endpoint","url","version","agent_version","revision","model_revision","deployment_name","azure_deployment"):
                if k in parameters and isinstance(parameters[k],(str,int,float,bool)):attrs[k]=parameters[k]
            if et=="model":
                attrs["parameters"]=parameters
                model_node=kw.get("model") or kw.get("model_name") or kw.get("model_id") or kw.get("modelId") or kw.get("deployment_name") or kw.get("azure_deployment") or (call.args[0] if call.args else None)
                attrs["configuration_source"]=_configuration_source(model_node,constant_sources)
            explicit=str(((attrs.get("revision") or attrs.get("model_revision")) if et=="model" else (attrs.get("version") or attrs.get("agent_version"))) or ""); model_id=str(attrs.get("model") or attrs.get("model_name") or attrs.get("model_id") or attrs.get("modelId") or attrs.get("deployment_name") or attrs.get("azure_deployment") or (_static_value(call.args[0],constants) if call.args else "") or "") if et=="model" else ""
            if et=="model" and not model_id and tail in {"OpenAI","AsyncOpenAI","Anthropic","BedrockRuntimeClient"}:et="provider";display=tail
            if et=="model" and model_id: display=model_id
            if et=="model":
                low=ctor.lower(); attrs["provider"]="azure-openai" if "azure" in low else "anthropic" if "anthropic" in low else "aws-bedrock" if "bedrock" in low else "google" if any(value in low for value in ("google","vertex","gemini","generative")) else "huggingface" if any(value in low for value in ("transformers","huggingface","from_pretrained")) else "openai" if "openai" in low else "unknown"
                if attrs["provider"]=="huggingface":attrs["repository"]=model_id;attrs["access_type"]="downloaded"
            q=f"{module.module}.{target}"; e=self._add(et,display,q,module.path,node.lineno,ast.get_source_segment(module.source,node) or target,framework,attrs,explicit_version=explicit,model_id=model_id); vars[target]=e
            # Agent literal model creates a concrete model asset and relation.
            if et in {"agent","sub_agent"}:
                mval=attrs.get("model") or attrs.get("model_name") or attrs.get("model_id") or attrs.get("modelId")
                if mval:
                    me=self._add("model",mval,f"model.{mval}",module.path,node.lineno,mval,framework, {"model_id":mval,"referenced_by":e.entity_id}, model_id=mval); self._relationship(e,"USES_MODEL",me,module.path,node.lineno,{"keyword":"model"})
            endpoint=attrs.get("base_url") or attrs.get("endpoint") or attrs.get("azure_endpoint") or (attrs.get("url") if et in {"mcp_server","mcp_client"} else "")
            if endpoint:
                ep_type="llm_endpoint" if et=="model" else "mcp_gateway" if et=="mcp_client" else "model_endpoint"
                ep=self._add(ep_type,str(endpoint),f"endpoint.{endpoint}",module.path,node.lineno,str(endpoint),framework,{"url":endpoint}); self._relationship(e,"CONNECTS_TO" if et!="model" else "USES_LLM_ENDPOINT",ep,module.path,node.lineno)

    def _discover_model_calls(self,index:ProjectIndex,module:ProjectModule)->None:
        constants:dict[str,Any]={}
        constant_sources:dict[str,str]={}
        for statement in module.tree.body:
            if isinstance(statement,(ast.Assign,ast.AnnAssign)):
                target=statement.targets[0] if isinstance(statement,ast.Assign) and statement.targets else statement.target
                value=_static_value(statement.value,constants)
                if isinstance(target,ast.Name) and value is not None:
                    constants[target.id]=value
                    constant_sources[target.id]=_configuration_source(statement.value,constant_sources)
        call_suffixes=("chat.completions.create","responses.create","messages.create","invoke_model","generate_content")
        for node in ast.walk(module.tree):
            if not isinstance(node,ast.Call):continue
            name=_canonical(index,module,node.func)
            kw={item.arg:item.value for item in node.keywords if item.arg}
            model_value=_static_value(kw.get("model") or kw.get("modelId") or kw.get("model_id"),constants)
            if model_value is None and name.endswith("invoke_model"):model_value=_static_value(kw.get("modelId"),constants)
            if model_value is None or not any(name.endswith(suffix) for suffix in call_suffixes):continue
            model_id=str(model_value); low=name.lower(); provider="anthropic" if "anthropic" in low or "messages.create" in low else "aws-bedrock" if "bedrock" in low or "invoke_model" in low else "google" if "generate_content" in low else "openai"
            framework="anthropic" if provider=="anthropic" else "aws-bedrock" if provider=="aws-bedrock" else "google-vertexai" if provider=="google" else "openai"
            model_node=kw.get("model") or kw.get("modelId") or kw.get("model_id")
            model=self._add("model",model_id,f"model.{provider}.{model_id}",module.path,node.lineno,ast.get_source_segment(module.source,node) or model_id,framework,{"model_id":model_id,"provider":provider,"parameters":{key:value for key,item in kw.items() if (value:=_static_value(item,constants)) is not None},"configuration_source":f"api_call:{_configuration_source(model_node,constant_sources)}"},model_id=model_id)
            containing=index.containing_symbol(module.path,node.lineno,getattr(node,"col_offset",0))
            owner=self.symbols.get(containing.qualified_name) if containing else None
            if owner and owner.entity_type in {"tool","mcp_tool","agent","sub_agent"}:self._relationship(owner,"USES_MODEL",model,module.path,node.lineno,{"call":name})

    def _discover_model_usage(self,index:ProjectIndex,module:ProjectModule)->None:
        vars=self.variables.get(module.module,{})
        for node in ast.walk(module.tree):
            if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):continue
            owner=self.symbols.get(f"{module.module}.{node.name}")
            if not owner or owner.entity_type not in {"tool","mcp_tool","agent","sub_agent"}:continue
            for child in ast.walk(node):
                if not isinstance(child,ast.Call) or not isinstance(child.func,ast.Attribute) or not isinstance(child.func.value,ast.Name):continue
                model=vars.get(child.func.value.id)
                if model and model.entity_type=="model":self._relationship(owner,"USES_MODEL",model,module.path,child.lineno,{"call":_canonical(index,module,child.func)})

    def _resolve(self,module:ProjectModule,node:ast.AST,etype:str="")->InventoryEntity|None:
        if isinstance(node,ast.Name):return self.variables.get(module.module,{}).get(node.id) or (self._infer_function_entity(module,node,etype) if etype else None)
        return None

    def _discover_relationships(self,index:ProjectIndex,module:ProjectModule)->None:
        vars=self.variables.get(module.module,{})
        for node in module.tree.body:
            if not isinstance(node,(ast.Assign,ast.AnnAssign)) or not isinstance(node.value,ast.Call):continue
            tnode=node.targets[0] if isinstance(node,ast.Assign) and node.targets else node.target
            if not isinstance(tnode,ast.Name):continue
            src=vars.get(tnode.id)
            if not src:continue
            kw={k.arg:k.value for k in node.value.keywords if k.arg}
            for key,rel in RELATIONSHIP_KEYWORDS.items():
                if rel=="USES_MODEL" and src.entity_type=="model": continue
                for item in _list_nodes(kw.get(key)):
                    if rel=="USES_MODEL" and isinstance(item,ast.Constant) and isinstance(item.value,str): trg=self._add("model",item.value,f"model.{item.value}",module.path,node.lineno,item.value,src.framework,{"model_id":item.value},model_id=item.value)
                    else: trg=self._resolve(module,item,"tool" if rel=="USES_TOOL" else "sub_agent" if rel=="USES_AGENT" else "")
                    if trg:self._relationship(src,rel,trg,module.path,node.lineno,{"keyword":key})
        # MCP decorator exposure
        for node in ast.walk(module.tree):
            if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):continue
            asset=self.symbols.get(f"{module.module}.{node.name}")
            if not asset or asset.entity_type not in {"mcp_tool","mcp_resource","mcp_prompt"}:continue
            for dec in node.decorator_list:
                t=dec.func if isinstance(dec,ast.Call) else dec
                if isinstance(t,ast.Attribute) and isinstance(t.value,ast.Name):
                    server=vars.get(t.value.id)
                    if server and server.entity_type=="mcp_server":self._relationship(server,{"mcp_tool":"EXPOSES_TOOL","mcp_resource":"EXPOSES_RESOURCE","mcp_prompt":"EXPOSES_PROMPT"}[asset.entity_type],asset,module.path,node.lineno)
        # LangGraph nodes
        for node in ast.walk(module.tree):
            if not isinstance(node,ast.Call) or not isinstance(node.func,ast.Attribute) or node.func.attr!="add_node" or len(node.args)<2:continue
            graph=self._resolve(module,node.func.value)
            if not graph:continue
            label=_string(node.args[0]); trg=self._resolve(module,node.args[1],"sub_agent")
            if trg is None:
                name=node.args[1].id if isinstance(node.args[1],ast.Name) else label or f"node-{node.lineno}"; trg=self._add("sub_agent",name,f"{module.module}.{name}",module.path,node.lineno,ast.get_source_segment(module.source,node) or name,"langgraph",{"graph_node":label})
            self._relationship(graph,"CONTAINS_NODE",trg,module.path,node.lineno,{"label":label})

    def _infer_capabilities(self,index:ProjectIndex)->None:
        for module in index.modules.values():
            for node in ast.walk(module.tree):
                if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):continue
                owner=self.symbols.get(f"{module.module}.{node.name}") or self.variables.get(module.module,{}).get(node.name)
                if not owner or owner.entity_type not in {"tool","mcp_tool","sub_agent","agent"}:continue
                seen=set()
                for child in ast.walk(node):
                    if not isinstance(child,ast.Call):continue
                    name=_canonical(index,module,child.func); cap=next((v for k,v in CAPABILITY_BY_CALL.items() if name==k or name.endswith(f".{k}")),"")
                    if cap and cap not in seen:
                        seen.add(cap); ce=self._add("capability",cap,f"capability.{cap}",module.path,child.lineno,cap,attributes={"virtual":True},detection_source="derived"); self._relationship(owner,"HAS_CAPABILITY",ce,module.path,child.lineno,{"call":name})
                if seen:owner.attributes["capabilities"]=sorted(seen)

    def _discover_skill_manifests(self,paths:list[Path])->None:
        for path in paths:
            is_skill=path.name.upper()=="SKILL.MD" or (path.suffix.lower() in {".md",".yaml",".yml",".json"} and "skill" in path.name.lower())
            if not is_skill:continue
            text=path.read_text(encoding="utf-8",errors="ignore"); name=path.parent.name if path.name.upper()=="SKILL.MD" else path.stem; version=""
            m=re.search(r"(?im)^version\s*:\s*['\"]?([^\s'\"]+)",text); version=m.group(1) if m else ""; rel=path.relative_to(self.root).as_posix(); self._add("skill",name,f"skill.{rel}",path,1,text,attributes={"format":path.suffix.lower()},detection_source="config_file",explicit_version=version)

    def _manifest_obj(self,path:Path)->dict[str,Any]|None:
        try:
            text=path.read_text(encoding="utf-8",errors="ignore")
            data=json.loads(text) if path.suffix.lower()==".json" else yaml.safe_load(text)
            return data if isinstance(data,dict) else None
        except (OSError, json.JSONDecodeError, yaml.YAMLError):return None

    def _discover_agent_manifests(self,paths:list[Path])->None:
        names={"agent-card.json","agent_card.json","agent.json","agent.yaml","agent.yml","agents.yaml","agents.yml"}
        for path in paths:
            low=path.as_posix().lower()
            if path.name.lower() not in names and "/.well-known/agent-card.json" not in low:continue
            obj=self._manifest_obj(path)
            if not obj:continue
            candidates=obj.get("agents") if isinstance(obj.get("agents"),list) else [obj]
            for idx,a in enumerate(candidates):
                if not isinstance(a,dict):continue
                name=str(a.get("name") or a.get("id") or a.get("title") or f"agent-{idx+1}"); version=str(a.get("version") or a.get("agentVersion") or ""); framework=str(a.get("framework") or ""); q=f"manifest.{path.relative_to(self.root).as_posix()}.{name}"; existing=next((e for e in self.entities if e.entity_type in {"agent","sub_agent"} and e.name.lower()==name.lower()),None)
                attrs={k:a.get(k) for k in ("description","url","capabilities","skills","provider","protocolVersion") if a.get(k) is not None}; e=existing or self._add("agent",name,q,path,1,json.dumps(a,sort_keys=True),framework,attrs,detection_source="agent_manifest",explicit_version=version)
                if existing:
                    if version:e.version=version;e.version_source="agent_manifest";e.version_scheme="declared";e.version_evidence={"manifest":path.relative_to(self.root).as_posix(),"declared_version":version};e.finalize(self.root)
                    e.attributes.update(attrs)
                model=a.get("model") or a.get("modelId")
                if isinstance(model,str) and model:
                    me=self._add("model",model,f"model.{model}",path,1,model,framework,{"model_id":model},detection_source="agent_manifest",model_id=model); self._relationship(e,"USES_MODEL",me,path,1)
                for s in a.get("skills") or []:
                    if isinstance(s,dict): sn=str(s.get("name") or s.get("id") or "skill"); sv=str(s.get("version") or "")
                    else: sn=str(s); sv=""
                    se=next((x for x in self.entities if x.entity_type=="skill" and x.name.lower()==sn.lower()),None)
                    if se is None:
                        se=self._add("skill",sn,f"manifest.skill.{sn}",path,1,json.dumps(s) if isinstance(s,dict) else sn,attributes={"manifest":True},detection_source="agent_manifest",explicit_version=sv)
                    elif sv and se.version != sv:
                        se.version=sv; se.version_source="agent_manifest"; se.version_scheme="declared"; se.version_evidence={"manifest":path.relative_to(self.root).as_posix(),"declared_version":sv}; se.finalize(self.root)
                    self._relationship(e,"USES_SKILL",se,path,1)

    def _discover_js_ts(self,paths:list[Path])->None:
        for path in paths:
            if path.suffix.lower() not in {".js",".jsx",".ts",".tsx"}:continue
            text=path.read_text(encoding="utf-8",errors="ignore")
            for m in re.finditer(r"(?m)\b(?:const|let|var)\s+(\w+)\s*=\s*new\s+(Agent|AssistantAgent|MCPServer|FastMCP|OpenAI|Anthropic)\s*\((.*?)\)",text,re.DOTALL):
                var,ctor,args=m.group(1),m.group(2),m.group(3); line=text.count("\n",0,m.start())+1; et="mcp_server" if ctor in {"MCPServer","FastMCP"} else "model" if ctor in {"OpenAI","Anthropic"} else "agent"; framework="mcp" if et=="mcp_server" else ""; name_match=re.search(r"name\s*:\s*['\"]([^'\"]+)",args); name=name_match.group(1) if name_match else var; e=self._add(et,name,f"js.{path.relative_to(self.root).as_posix()}.{var}",path,line,m.group(0),framework,{"constructor":ctor},detection_source="tree_sitter_fallback")
                model_match=re.search(r"model\s*:\s*['\"]([^'\"]+)",args)
                if et=="agent" and model_match:
                    model=model_match.group(1); me=self._add("model",model,f"model.{model}",path,line,model,model_id=model); self._relationship(e,"USES_MODEL",me,path,line)

    def _add_dependencies(self)->None:
        for name,ver in self.packages.items():
            e=self._add("dependency",name,f"dependency.{name}",self.root/"pyproject.toml",1,f"{name}{ver}",attributes={"package":name,"declared_version":ver},detection_source="dependency_manifest",explicit_version=ver)
            e.package_name=name;e.package_version=ver

    def discover(self, repository_paths:list[Path]|None=None)->tuple[list[InventoryEntity],list[Relationship]]:
        candidates=repository_paths if repository_paths is not None else discover_repository_files(self.root)
        paths=[p for p in candidates if p.suffix.lower() in {".py",".js",".jsx",".ts",".tsx",".md",".yaml",".yml",".json",".toml"} or p.name.upper()=="SKILL.MD"]
        if self.session is not None:
            index=self.session.index
        else:
            py={p:p.read_text(encoding="utf-8",errors="ignore") for p in paths if p.suffix.lower()==".py"}
            index=ProjectIndex(self.root,py)
        for m in index.modules.values():self._discover_functions(index,m);self._discover_assignments(index,m);self._discover_model_calls(index,m)
        for m in index.modules.values():self._discover_relationships(index,m)
        for m in index.modules.values():self._discover_model_usage(index,m)
        self._infer_capabilities(index);self._discover_skill_manifests(paths);self._discover_agent_manifests(paths);self._discover_js_ts(paths)
        self.entities=list({e.entity_id:e for e in self.entities}.values());self.relationships=list({(r.source_id,r.relation,r.target_id):r for r in self.relationships}.values())
        for e in self.entities:e.finalize(self.root)
        for r in self.relationships:r.normalize_paths(self.root)
        return self.entities,self.relationships
