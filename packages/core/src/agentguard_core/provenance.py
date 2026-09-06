from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from typing import Any

from .contracts import ScanResult


def _id(prefix: str, *parts: object) -> str:
    raw="|".join(str(x) for x in parts)
    return f"{prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:20].upper()}"


def generate_provenance_graph(result: ScanResult) -> dict[str, Any]:
    """Create a UI-friendly provenance/security graph from one scan result.

    This is a data contract, not a layout. UI clients are free to cluster/filter
    nodes while preserving stable IDs, typed edges, evidence and finding links.
    """
    nodes: list[dict[str, Any]]=[]; edges:list[dict[str,Any]]=[]; attack_paths:list[dict[str,Any]]=[]
    node_ids=set(); edge_ids=set()

    repo_id=_id("REPO",result.scan.git_remote or result.scan.root)
    nodes.append({"id":repo_id,"kind":"repository","subtype":"repository","label":result.scan.git_remote or result.scan.root,"version":{"value":result.scan.git_commit[:12] if result.scan.git_commit else "workspace","scheme":"git-commit" if result.scan.git_commit else "workspace","source":"git"},"source":{},"risk":{"finding_count":len(result.findings)},"attributes":{"branch":result.scan.git_branch,"remote":result.scan.git_remote}}); node_ids.add(repo_id)

    for e in result.inventory:
        n={"id":e.entity_id,"kind":"asset","subtype":e.entity_type,"category":e.category,"label":e.name,"qualified_name":e.qualified_name,"framework":{"name":e.framework,"version":e.framework_version},"version":{"id":e.version_id,"value":e.version,"scheme":e.version_scheme,"source":e.version_source,"evidence":e.version_evidence},"package":{"name":e.package_name,"version":e.package_version},"content_digest":f"sha256:{e.content_hash}" if e.content_hash else "","source":{"file":e.file,"line":e.line},"risk":{"finding_count":0,"max_severity":"None"},"attributes":e.attributes}
        nodes.append(n);node_ids.add(e.entity_id)
        eid=_id("EDGE",repo_id,"DEFINES",e.entity_id)
        edges.append({"id":eid,"source":repo_id,"target":e.entity_id,"relation":"DEFINES","directed":True,"evidence":[{"file":e.file,"line":e.line}],"finding_ids":[],"attributes":{"resolution":"exact"}});edge_ids.add(eid)

    for r in result.relationships:
        if r.source_id not in node_ids or r.target_id not in node_ids:continue
        eid=_id("EDGE",r.source_id,r.relation,r.target_id)
        if eid in edge_ids:continue
        edges.append({"id":eid,"source":r.source_id,"target":r.target_id,"relation":r.relation,"directed":True,"evidence":[{"file":r.evidence_file,"line":r.evidence_line}] if r.evidence_file else [],"finding_ids":[],"attributes":r.attributes});edge_ids.add(eid)

    entities_by_file:dict[str,list[Any]]=defaultdict(list)
    for e in result.inventory:entities_by_file[e.file].append(e)
    severity_rank={"Critical":5,"High":4,"Medium":3,"Low":2,"Info":1}
    risk_by_entity:dict[str,list[Any]]=defaultdict(list)

    for f in result.findings:
        fnid=f.finding_id or _id("FINDING",f.rule_id,f.file,f.line)
        nodes.append({"id":fnid,"kind":"finding","subtype":f.category or "security_finding","label":f.title or f.name,"version":{"value":f.rule_version,"scheme":"rule-version","source":"rule_catalog"},"source":{"file":f.file,"line":f.line},"risk":{"severity":f.severity,"rule_id":f.rule_id,"analysis_type":f.analysis_type},"attributes":{"description":f.description,"remediation":f.remediation,"fingerprint":f.fingerprint,"mappings":f.mappings,"cwe":f.cwe,"engine_metadata":f.engine_metadata}});node_ids.add(fnid)
        candidates=entities_by_file.get(f.file,[])
        affected=min(candidates,key=lambda e:abs(e.line-f.line)) if candidates else None
        if affected:
            risk_by_entity[affected.entity_id].append(f)
            eid=_id("EDGE",affected.entity_id,"HAS_FINDING",fnid)
            edges.append({"id":eid,"source":affected.entity_id,"target":fnid,"relation":"HAS_FINDING","directed":True,"evidence":[{"file":f.file,"line":f.line}],"finding_ids":[fnid],"attributes":{"rule_id":f.rule_id}});edge_ids.add(eid)
        else:
            eid=_id("EDGE",repo_id,"HAS_FINDING",fnid);edges.append({"id":eid,"source":repo_id,"target":fnid,"relation":"HAS_FINDING","directed":True,"evidence":[{"file":f.file,"line":f.line}],"finding_ids":[fnid],"attributes":{"rule_id":f.rule_id}});edge_ids.add(eid)

        evidence_node_ids=[]; evidence_edge_ids=[]
        previous=None
        for idx,ev in enumerate(f.evidence):
            evid=_id("EVIDENCE",fnid,idx,ev.kind,ev.file,ev.line,ev.symbol,ev.label)
            evidence_node_ids.append(evid)
            nodes.append({"id":evid,"kind":"evidence","subtype":ev.kind,"label":ev.label,"version":{},"source":{"file":ev.file,"line":ev.line,"symbol":ev.symbol},"risk":{"severity":f.severity},"attributes":{"detail":ev.detail,"finding_id":fnid}});node_ids.add(evid)
            if previous:
                ee=_id("EDGE",previous,"EVIDENCE_FLOW",evid);edges.append({"id":ee,"source":previous,"target":evid,"relation":"EVIDENCE_FLOW","directed":True,"evidence":[],"finding_ids":[fnid],"attributes":{"sequence":idx}});edge_ids.add(ee);evidence_edge_ids.append(ee)
            previous=evid
        if evidence_node_ids:
            ee=_id("EDGE",fnid,"HAS_EVIDENCE",evidence_node_ids[0]);edges.append({"id":ee,"source":fnid,"target":evidence_node_ids[0],"relation":"HAS_EVIDENCE","directed":True,"evidence":[],"finding_ids":[fnid],"attributes":{}});edge_ids.add(ee);evidence_edge_ids.append(ee)
        attack_paths.append({"path_id":_id("PATH",fnid),"finding_id":fnid,"rule_id":f.rule_id,"severity":f.severity,"title":f.title or f.name,"entry_node_id":evidence_node_ids[0] if evidence_node_ids else (affected.entity_id if affected else repo_id),"impact_node_id":evidence_node_ids[-1] if evidence_node_ids else fnid,"asset_node_id":affected.entity_id if affected else repo_id,"node_ids":([affected.entity_id] if affected else [repo_id])+[fnid]+evidence_node_ids,"edge_ids":evidence_edge_ids,"explanation":f.description or f.message,"remediation":f.remediation})

    # back-fill per-asset risk summary
    by_node={n["id"]:n for n in nodes}
    for eid,fs in risk_by_entity.items():
        if eid in by_node:
            by_node[eid]["risk"]={"finding_count":len(fs),"max_severity":max((f.severity for f in fs),key=lambda x:severity_rank.get(x,0),default="None"),"finding_ids":[f.finding_id for f in fs]}

    kinds=Counter(n["subtype"] for n in nodes if n["kind"]=="asset"); rels=Counter(e["relation"] for e in edges)
    return {"schema":"agentguard-provenance-graph/1.0","scan":{"scan_id":result.scan.scan_id,"repository":result.scan.root,"git_commit":result.scan.git_commit,"git_branch":result.scan.git_branch},"summary":{"nodes":len(nodes),"edges":len(edges),"attack_paths":len(attack_paths),"asset_types":dict(kinds),"relationship_types":dict(rels)},"nodes":nodes,"edges":edges,"attack_paths":attack_paths,"ui_hints":{"default_node_label":"label","group_by":"category","severity_field":"risk.max_severity","edge_label":"relation","expand_evidence_on_demand":True}}
