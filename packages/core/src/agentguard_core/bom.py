from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from typing import Any

from .contracts import ENGINE_VERSION, ScanResult

CYCLONEDX_TYPE={"model":"machine-learning-model","embedding":"machine-learning-model","embedding_model":"machine-learning-model","vector_store":"data","dataset":"data","knowledge_base":"data","memory":"data","mcp_resource":"data","mcp_prompt":"data","prompt":"data","agent":"application","sub_agent":"application","orchestrator":"application","agent_proxy":"application","mcp_server":"application","mcp_client":"application","mcp_gateway":"application","llm_endpoint":"application","model_endpoint":"application","deployment":"application","tool":"library","function_tool":"library","mcp_tool":"library","skill":"library","plugin":"library","guardrail":"library","retriever":"library","capability":"library","dependency":"library"}


def _version_properties(e)->list[dict[str,str]]:
    props=[
        {"name":"agentguard:identity:entity_id","value":e.entity_id},
        {"name":"agentguard:identity:version_id","value":e.version_id},
        {"name":"agentguard:version:value","value":e.version or "unknown"},
        {"name":"agentguard:version:scheme","value":e.version_scheme or "unknown"},
        {"name":"agentguard:version:source","value":e.version_source or "unknown"},
    ]
    if e.framework_version:props.append({"name":"agentguard:framework:version","value":e.framework_version})
    if e.package_version:props.append({"name":"agentguard:package:version","value":e.package_version})
    if e.content_hash:props.append({"name":"agentguard:content:sha256","value":e.content_hash})
    return props


def generate_cyclonedx(result:ScanResult)->dict[str,Any]:
    deps:dict[str,set[str]]=defaultdict(set); outgoing:dict[str,list[str]]=defaultdict(list)
    for r in result.relationships:deps[r.source_id].add(r.target_id);outgoing[r.source_id].append(f"{r.relation}:{r.target_id}")
    components=[]
    for e in result.inventory:
        props=_version_properties(e)+[
            {"name":"agentguard:entity:type","value":e.entity_type},{"name":"agentguard:entity:category","value":e.category or "other"},{"name":"agentguard:detection:source","value":e.detection_source},{"name":"agentguard:source:file","value":e.file},{"name":"agentguard:source:line","value":str(e.line)}]
        if e.framework:props.append({"name":"agentguard:framework:name","value":e.framework})
        for rel in outgoing.get(e.entity_id,[]):props.append({"name":"agentguard:relationship","value":rel})
        c={"type":CYCLONEDX_TYPE.get(e.entity_type,"application"),"bom-ref":e.bom_ref or e.entity_id,"name":e.name,"version":e.version or "unknown","properties":props}
        if e.framework:c["group"]=e.framework
        components.append(c)
    try:serial=uuid.UUID(result.scan.scan_id)
    except ValueError:serial=uuid.uuid5(uuid.NAMESPACE_URL,result.scan.scan_id)
    return {"$schema":"https://cyclonedx.org/schema/bom-1.7.schema.json","bomFormat":"CycloneDX","specVersion":"1.7","serialNumber":f"urn:uuid:{serial}","version":1,"metadata":{"timestamp":result.scan.completed_at or result.scan.started_at,"tools":{"components":[{"type":"application","name":"AgentGuard Core","version":ENGINE_VERSION}]},"properties":[{"name":"agentguard:scan:id","value":result.scan.scan_id},{"name":"agentguard:repository","value":result.scan.root},{"name":"agentguard:git:commit","value":result.scan.git_commit},{"name":"agentguard:git:branch","value":result.scan.git_branch}]},"components":components,"dependencies":[{"ref":e.entity_id,"dependsOn":sorted(deps.get(e.entity_id,set()))} for e in result.inventory]}


def generate_agent_bom(result:ScanResult)->dict[str,Any]:
    """Agent-centric BOM with separate logical identity and version identity."""
    by_id={e.entity_id:e for e in result.inventory}; outgoing:dict[str,list[Any]]=defaultdict(list); incoming:dict[str,list[Any]]=defaultdict(list)
    for r in result.relationships:outgoing[r.source_id].append(r);incoming[r.target_id].append(r)
    agent_types={"agent","sub_agent","orchestrator","agent_proxy"}; agents=[]
    for e in result.inventory:
        if e.entity_type not in agent_types:continue
        deps=[]
        for r in outgoing.get(e.entity_id,[]):
            t=by_id.get(r.target_id)
            if not t:continue
            deps.append({"relation":r.relation,"asset_id":t.entity_id,"asset_version_id":t.version_id,"type":t.entity_type,"name":t.name,"version":t.version,"version_source":t.version_source,"framework":t.framework,"source":{"file":r.evidence_file,"line":r.evidence_line}})
        parents=[]
        for r in incoming.get(e.entity_id,[]):
            s=by_id.get(r.source_id)
            if s and s.entity_type in agent_types:parents.append({"relation":r.relation,"agent_id":s.entity_id,"name":s.name})
        agents.append({
            "agent_id":e.entity_id,"agent_version_id":e.version_id,"name":e.name,"type":e.entity_type,"qualified_name":e.qualified_name,
            "version":{"value":e.version,"scheme":e.version_scheme,"source":e.version_source,"evidence":e.version_evidence,"content_sha256":e.content_hash},
            "framework":{"name":e.framework,"version":e.framework_version,"package":e.package_name,"package_version":e.package_version},
            "source":{"file":e.file,"line":e.line},"capabilities":e.attributes.get("capabilities",[]),"attributes":e.attributes,"dependencies":deps,"parent_agents":parents,
        })
    versions=[{"entity_id":e.entity_id,"version_id":e.version_id,"version":e.version,"scheme":e.version_scheme,"source":e.version_source,"content_sha256":e.content_hash,"source_location":{"file":e.file,"line":e.line}} for e in result.inventory]
    type_counts=Counter(e.entity_type for e in result.inventory)
    return {"schema":"agentguard-agent-bom/2.0","scan":{"scan_id":result.scan.scan_id,"repository":result.scan.root,"remote":result.scan.git_remote,"commit":result.scan.git_commit,"branch":result.scan.git_branch},"summary":{"agents":len(agents),"assets":len(result.inventory),"relationships":len(result.relationships),"asset_types":dict(type_counts)},"agents":agents,"assets":[e.to_dict() for e in result.inventory],"versions":versions,"relationships":[r.to_dict() for r in result.relationships]}
