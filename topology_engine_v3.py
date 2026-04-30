"""
ObserveX Topology Engine v3 — advanced multi-flow engine

V6 upgrades over v2:
- separates flows by HTTP method + endpoint at the app layer
- detects payment ecosystem nodes from payloads: BBPS, Setu, UPI Gateway
- detects core loan lookup dependency: LMS/Flexcube
- avoids mixing loanDetails and payment traces into one topology
- emits richer confidence/hints for topology quality
"""
from __future__ import annotations
import re
from collections import defaultdict
import topology_engine_v2 as v2

# Extend v2 dictionaries in-place so all v2 helper functions benefit.
for item in [
    (r"/paymentengine/payment|paymentengine\\payment|before payment|after payment|payment log|paymentstatus|paymentmode", "Payment Processing"),
    (r"bbps|bill payment", "BBPS Payment"),
    (r"setu", "Setu Integration"),
    (r"upi|vpa", "UPI Payment"),
    (r"flexcube|fcubs|core banking", "Flexcube"),
]:
    if item not in v2._BUSINESS_PATTERNS:
        v2._BUSINESS_PATTERNS.insert(0, item)

for item in [
    (r"sourceModule[\"']?\s*[:=]\s*[\"']?BBPS|\bbbps\b|bill payment", "BBPS"),
    (r"intermediaryId[\"']?\s*[:=]\s*[\"']?setu|\bsetu\b", "Setu"),
    (r"paymentApp[\"']?\s*[:=]\s*[\"']?UPI|\bupi\b|\bvpa\b", "UPI Gateway"),
    (r"flexcube|fcubs|core banking", "Flexcube"),
    (r"loan details|loandetails|loan.management|lms", "LMS / Flexcube"),
]:
    if item not in v2._DOWNSTREAM_PATTERNS:
        v2._DOWNSTREAM_PATTERNS.insert(0, item)


def _extract_all_downstreams(message: str, processor: str = "", endpoint: str = "") -> list[str]:
    """Return all meaningful downstream systems found in one log payload, in business order."""
    combined = f"{message} {processor} {endpoint}"
    found: list[str] = []
    for pattern, label in v2._DOWNSTREAM_PATTERNS:
        if re.search(pattern, combined, re.I) and label not in found:
            found.append(label)
    # Endpoint-aware pruning keeps loan lookup and payment flows from mixing.
    ep_low = str(endpoint or '').lower()
    if 'loandetails' in ep_low:
        found = [x for x in found if x in ['LMS / Flexcube','Flexcube','LMS Core']]
        if not found:
            found = ['LMS / Flexcube']
        return found[:2]
    if 'payment' in ep_low:
        allowed = ['BBPS','Setu','UPI Gateway']
        found = [x for x in found if x in allowed]

    # Payment payloads often contain all three systems in one JSON body.
    low = combined.lower()
    if 'sourcemodule' in low and 'bbps' in low and 'BBPS' not in found:
        found.append('BBPS')
    if 'intermediaryid' in low and 'setu' in low and 'Setu' not in found:
        found.append('Setu')
    if 'paymentapp' in low and 'upi' in low and 'UPI Gateway' not in found:
        found.append('UPI Gateway')
    if 'payment' in ep_low:
        allowed = ['BBPS','Setu','UPI Gateway']
        found = [x for x in found if x in allowed]

    # Remove overly generic dependency once specific one exists.
    if 'Payment Engine' in found and any(x in found for x in ['BBPS', 'Setu', 'UPI Gateway']):
        found = [x for x in found if x != 'Payment Engine']
    if 'LMS Core' in found and 'LMS / Flexcube' in found:
        found = [x for x in found if x != 'LMS Core']
    return found[:5]


def _extract_flow_from_trace_v3(api_name: str, trace_rows: list, endpoint_hint: str = ""):
    rows = sorted(trace_rows or [], key=lambda r: str(r.get("time") or ""))
    api = v2._clean_service_name(api_name) or ""
    method = ""
    endpoint = endpoint_hint or ""
    business = ""
    stages: list[str] = []

    for r in rows:
        msg = str(r.get("message") or "")
        a, m, ep = v2._extract_mule_route(msg)
        if a:
            api = api or a
        if m:
            method = method or m
        if ep and ep != "/":
            endpoint = endpoint or ep
        if not method or endpoint == "/":
            gm, gep = v2._extract_generic_route(msg)
            if gm and not method:
                method = gm
            if gep and gep != "/" and endpoint == "/":
                endpoint = gep

        proc_m = re.search(r"\[processor:\s*([^\];]+)", msg, re.I)
        proc_name = (proc_m.group(1) if proc_m else "") or r.get("flow") or ""
        fn_match = re.search(r"Flow Name:\s*'([^']+)'", msg, re.I)
        if fn_match and not proc_name:
            proc_name = fn_match.group(1)

        business = business or v2._infer_business_label(msg, proc_name, endpoint)
        low = msg.lower()

        if re.search(r"\bentry\s*>>|call-entry\s*>>|entered into|flow started|start of the flow", low):
            stages.append("Request Entry")

        ep_label = v2._endpoint_label(method, endpoint, business)
        if ep_label and ep_label != "API Endpoint":
            stages.append(ep_label)

        st = v2._processor_stage_name(proc_name, msg, endpoint)
        if st:
            stages.append(st)

        # V3: inspect every request/response payload, not only generic "request to" text.
        for ds in _extract_all_downstreams(msg, proc_name, endpoint):
            if ds and ds not in ("External System", ""):
                stages.append(ds)

        if re.search(r"\bcall-exit\s*<<|\bexit\s*<<|exited from|flow completed", low):
            stages.append("Response Exit")

    api = api or v2._clean_service_name(api_name) or "Application"
    flow = [api] + sorted(v2._clean_flow_sequence(stages), key=v2._stage_order)
    if not any(x.lower() in ("response", "response exit") for x in flow):
        flow.append("Response")
    return v2._clean_flow_sequence(flow), method, endpoint or "/"


def _extract_flow_steps_from_mule_rows(api_name: str, rows: list, endpoint: str = ""):
    groups: dict[str, list] = defaultdict(list)
    for r in rows or []:
        tid = str(r.get("trace") or r.get("event") or r.get("trace_id") or "")[:160] or "all"
        groups[tid].append(r)
    if not groups:
        return v2._clean_flow_sequence([api_name or "Application", "Response"]), "", endpoint or "/"

    def score(items):
        text = "\n".join(str(x.get("message") or "") for x in items[:120])
        route_bonus = 2 if endpoint and endpoint.lower() in text.lower().replace('\\\\', '/') else 0
        downstream_bonus = len(_extract_all_downstreams(text, '', endpoint))
        processors = len({(re.search(r"\[processor:\s*([^\];]+)", str(x.get("message") or ""), re.I) or type("", (), {"group": lambda self, n: None})()).group(1) for x in items})
        return (route_bonus, downstream_bonus, processors, len(items))

    best = max(groups.values(), key=score)
    return _extract_flow_from_trace_v3(api_name, best, endpoint)


def _build_clean_execution_flow(api_name: str, rows: list, arch: dict = None) -> list:
    flow, _, _ = _extract_flow_steps_from_mule_rows(api_name, rows or [], "")
    if len(flow) >= 3:
        return flow
    return v2._build_clean_execution_flow(api_name, rows, arch)


def extract_architecture_graph(rows: list, raw: str, env: str, session_id: int, user_id: int, api_name: str = "", endpoint: str = "") -> dict:
    # V7: pass the V3 flow extractor as a callback instead of monkey-patching v2.
    # This is thread-safe for parallel uploads because no shared module function is replaced.
    arch = v2.extract_architecture_graph(
        rows, raw, env, session_id, user_id, api_name, endpoint,
        flow_extractor=_extract_flow_steps_from_mule_rows,
    )

    flow = arch.get('simple_flow') or []
    raw_low = str(raw or '').lower()
    if 'payment' in str(endpoint or '').lower():
        for ds, keys in [('BBPS',['bbps','sourcemodule']), ('Setu',['setu','intermediaryid']), ('UPI Gateway',['upi','paymentapp'])]:
            if ds not in flow and all(k in raw_low for k in keys):
                flow.insert(max(1, len(flow)-1), ds)
        preferred = ['s-paymentengine-api']
        # Stable payment dependency order.
        payment_order = {'POST':1, 'Payment Processing':2, 'BBPS':3, 'Setu':4, 'UPI Gateway':5, 'Response':99}
        if any(x in flow for x in ['BBPS','Setu','UPI Gateway']):
            first = flow[0] if flow else 'Application'
            middle = [x for x in flow[1:] if x.lower() != 'response']
            middle = sorted(middle, key=lambda x: payment_order.get(x, payment_order.get(str(x).split(' ')[0], 50)))
            flow = [first] + middle + ['Response']
            arch['simple_flow'] = v2._clean_flow_sequence(flow)
    hints = arch.setdefault('hints', [])
    hints.insert(0, 'V6 topology engine: endpoint-separated flow with BBPS / Setu / UPI / Flexcube detection.')
    # Ensure payment-related flows are not rendered as just generic Payment Engine.
    if any('payment' in str(x).lower() for x in flow) and not any(x in flow for x in ['BBPS', 'Setu', 'UPI Gateway']):
        payload = '\n'.join(str(r.get('message') or '') for r in (rows or [])[:300])
        for ds in _extract_all_downstreams(payload, '', endpoint):
            if ds not in flow:
                insert_at = max(1, len(flow)-1)
                flow.insert(insert_at, ds)
        arch['simple_flow'] = v2._clean_flow_sequence(flow)
        nodes, edges = v2._build_nodes_and_edges(arch['simple_flow'], len(rows or []), sum(1 for r in (rows or []) if str(r.get('level','')).upper() in ('ERROR','FAILURE')), 0)
        arch['nodes'] = nodes
        arch['edges'] = edges
        arch['matrix'] = [{'from':e['from'],'to':e['to'],'calls':e['count'],'errors':e['errors'],'avg_latency_ms':e['avg_latency_ms'],'error_rate':e['error_rate']} for e in edges]
    return arch
