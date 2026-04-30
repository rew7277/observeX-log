"""
ObserveX Topology Engine v4 — generic Mule/API topology reconstruction.

Adds broad flow detection beyond hard-coded payment examples:
- Mule sub-flow and flow-ref names
- HTTP target URLs/hosts/paths
- generic CBS/LMS/Core/Bureau/KYC/UPI/payment rails signals
- stronger processor-event noise filtering
"""
from __future__ import annotations
import re
from collections import defaultdict
import topology_engine_v2 as v2
import topology_engine_v3 as v3

# Make the shared v2 cleaner reject raw Mule processor paths as display labels.
def _looks_like_processor_event_name_v4(name: str) -> bool:
    s = str(name or "")
    return bool(re.search(
        r"(processor-[a-f0-9]{6,}|event-[a-f0-9]{8,}|[./-]processors?/\d+|/processors?/\d+|"
        r"before .* log|after .* log|^(before|after|log|logging|info|debug|warn|error)$|"
        r"\d{6,}|uuid|mule\.runtime|org\.mule)",
        s, re.I,
    ))
v2._looks_like_processor_event_name = _looks_like_processor_event_name_v4

EXTRA_BUSINESS = [
    (r"\bkyc\b|aadhaar|aadhar|pan.?verify|ckyc", "KYC Verification"),
    (r"credit.?bureau|cibil|experian|equifax|crif|credit.?score", "Credit Bureau"),
    (r"\bcbs\b|core.?banking|finacle|flexcube|fcubs", "CBS / Core Banking"),
    (r"\blms\b|loan.?management|loan.?details", "LMS"),
    (r"upi|bbps|setu|payment.?rail|payment.?gateway", "Payment Rails"),
    (r"sanction|eligibility|underwriting", "Underwriting"),
]
EXTRA_DOWNSTREAM = [
    (r"\bcbs\b|core.?banking|finacle|flexcube|fcubs", "CBS / Core Banking"),
    (r"credit.?bureau|cibil|experian|equifax|crif", "Credit Bureau"),
    (r"\blms\b|loan.?management", "LMS"),
    (r"kyc|aadhaar|aadhar|pan.?verify|ckyc", "KYC Provider"),
    (r"upi", "UPI Gateway"),
    (r"bbps|bill.?payment", "BBPS"),
    (r"setu", "Setu"),
]
for item in reversed(EXTRA_BUSINESS):
    if item not in v2._BUSINESS_PATTERNS:
        v2._BUSINESS_PATTERNS.insert(0, item)
for item in reversed(EXTRA_DOWNSTREAM):
    if item not in v2._DOWNSTREAM_PATTERNS:
        v2._DOWNSTREAM_PATTERNS.insert(0, item)


def _title_from_slug(s: str) -> str:
    s = re.sub(r"(?i)-?(api|svc|service)$", "", str(s or ""))
    s = re.sub(r"[^A-Za-z0-9]+", " ", s).strip()
    return " ".join(w.upper() if w.lower() in {"kyc","cbs","lms","upi","bbps"} else w.capitalize() for w in s.split())[:80]


def _extract_subflow_from_processor(proc: str) -> str:
    p = str(proc or "")
    # Only explicit sub-flow / flow-ref segments. Do NOT extract from s-kyc-api/processors/0.
    pats = [
        r"(?:sub[-_ ]?flow|flow[-_ ]?ref|private[-_ ]?flow)[/:=\s]+([A-Za-z0-9_.-]{3,80})",
        r"/(?:subflows?|flow-refs?)/([A-Za-z0-9_.-]{3,80})",
        r"\bflowName[=:\"']+([A-Za-z0-9_.-]{3,80})",
    ]
    for pat in pats:
        m = re.search(pat, p, re.I)
        if m:
            label = _title_from_slug(m.group(1))
            if label and not _looks_like_processor_event_name_v4(label):
                return label
    return ""


def _extract_http_services(text: str) -> list[str]:
    msg = str(text or "")
    found = []
    # URLs and explicit target service fields.
    for pat in [
        r"https?://([^/\s\"'?,;]+)(?:/([^\s\"'<>;,]+))?",
        r"(?:target|service|downstream|dependency|system|host|baseUrl|url|uri)\s*[:=]\s*[\"']?([^\s\"',;{}]+)",
    ]:
        for m in re.finditer(pat, msg, re.I):
            token = m.group(1) or ""
            if token.startswith("/") and len(m.groups()) > 1:
                token = m.group(2) or token
            token = token.split("?")[0].strip("/: ")
            if not token or token.lower() in {"http", "https", "localhost", "request", "response"}:
                continue
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", token):
                continue
            label = _title_from_slug(token.split(".")[0])
            if label and label.lower() not in {"api", "www"} and label not in found:
                found.append(label)
    return found[:4]


def _extract_all_downstreams_v4(message: str, processor: str = "", endpoint: str = "") -> list[str]:
    combined = f"{message} {processor} {endpoint}"
    found = []
    for ds in v3._extract_all_downstreams(message, processor, endpoint):
        if ds and ds not in found:
            found.append(ds)
    for pattern, label in EXTRA_DOWNSTREAM:
        if re.search(pattern, combined, re.I) and label not in found:
            found.append(label)
    for label in _extract_http_services(combined):
        if label not in found:
            found.append(label)
    # Semantic de-dupe: prefer specific bureau/core labels over generic ones.
    if "Credit Bureau" in found:
        found = [x for x in found if x not in {"Credit Score", "CRIF SMS"}]
    if "CBS / Core Banking" in found:
        found = [x for x in found if x not in {"Flexcube", "LMS / Flexcube", "LMS Core"}]
    return found[:8]


def _extract_flow_from_trace_v4(api_name: str, trace_rows: list, endpoint_hint: str = ""):
    rows = sorted(trace_rows or [], key=lambda r: str(r.get("time") or ""))
    api = v2._clean_service_name(api_name) or ""
    method = ""; endpoint = endpoint_hint or ""; business = ""; stages = []
    for r in rows:
        msg = str(r.get("message") or "")
        a, m, ep = v2._extract_mule_route(msg)
        if a: api = api or a
        if m: method = method or m
        if ep and ep != "/": endpoint = endpoint or ep
        if not method or endpoint == "/":
            gm, gep = v2._extract_generic_route(msg)
            if gm and not method: method = gm
            if gep and gep != "/" and endpoint == "/": endpoint = gep
        proc_m = re.search(r"\[processor:\s*([^\];]+)", msg, re.I)
        proc = (proc_m.group(1) if proc_m else "") or r.get("flow") or ""
        fn = re.search(r"Flow Name:\s*'([^']+)'", msg, re.I)
        if fn and not proc: proc = fn.group(1)
        business = business or v2._infer_business_label(msg, proc, endpoint)
        low = msg.lower()
        if re.search(r"\bentry\s*>>|call-entry\s*>>|entered into|flow started|start of the flow", low):
            stages.append("Request Entry")
        ep_label = v2._endpoint_label(method, endpoint, business)
        if ep_label and ep_label != "API Endpoint": stages.append(ep_label)
        sub = _extract_subflow_from_processor(proc)
        if sub: stages.append(sub)
        st = v2._processor_stage_name(proc, msg, endpoint)
        if st and not _looks_like_processor_event_name_v4(st): stages.append(st)
        for ds in _extract_all_downstreams_v4(msg, proc, endpoint):
            if ds and ds not in {"External System", "API"}: stages.append(ds)
        if re.search(r"\bcall-exit\s*<<|\bexit\s*<<|exited from|flow completed", low):
            stages.append("Response Exit")
    api = api or v2._clean_service_name(api_name) or "Application"
    flow = [api] + sorted(v2._clean_flow_sequence(stages), key=v2._stage_order)
    flow = [x for x in flow if not _looks_like_processor_event_name_v4(x)]
    if not any(str(x).lower() in ("response", "response exit") for x in flow):
        flow.append("Response")
    return v2._clean_flow_sequence(flow), method, endpoint or "/"


def _extract_flow_steps_from_mule_rows(api_name: str, rows: list, endpoint: str = ""):
    groups = defaultdict(list)
    for r in rows or []:
        tid = str(r.get("trace") or r.get("event") or r.get("trace_id") or "")[:160] or "all"
        groups[tid].append(r)
    if not groups:
        return v2._clean_flow_sequence([api_name or "Application", "Response"]), "", endpoint or "/"
    def score(items):
        text = "\n".join(str(x.get("message") or "") for x in items[:160])
        route_bonus = 3 if endpoint and endpoint.lower() in text.lower().replace('\\\\','/') else 0
        ds_bonus = len(_extract_all_downstreams_v4(text, "", endpoint))
        proc_bonus = len({(re.search(r"\[processor:\s*([^\];]+)", str(x.get("message") or ""), re.I) or type("", (), {"group": lambda self, n: None})()).group(1) for x in items})
        return (route_bonus, ds_bonus, proc_bonus, len(items))
    best = max(groups.values(), key=score)
    return _extract_flow_from_trace_v4(api_name, best, endpoint)


def _build_clean_execution_flow(api_name: str, rows: list, arch: dict = None) -> list:
    flow, _, _ = _extract_flow_steps_from_mule_rows(api_name, rows or [], "")
    return flow if len(flow) >= 3 else v3._build_clean_execution_flow(api_name, rows, arch)


def extract_architecture_graph(rows: list, raw: str, env: str, session_id: int, user_id: int, api_name: str = "", endpoint: str = "") -> dict:
    arch = v2.extract_architecture_graph(rows, raw, env, session_id, user_id, api_name, endpoint, flow_extractor=_extract_flow_steps_from_mule_rows)
    flow = arch.get("simple_flow") or []
    # Enrich sparse backend results from full raw payload.
    if len(flow) <= 3:
        payload = raw or "\n".join(str(r.get("message") or "") for r in (rows or [])[:500])
        for ds in _extract_all_downstreams_v4(payload, "", endpoint):
            if ds not in flow:
                flow.insert(max(1, len(flow)-1), ds)
    flow = v2._clean_flow_sequence([x for x in flow if not _looks_like_processor_event_name_v4(x)])
    if flow and str(flow[-1]).lower() not in {"response", "response exit"}:
        flow.append("Response")
    arch["simple_flow"] = flow
    err_count = sum(1 for r in (rows or []) if str(r.get('level','')).upper() in ('ERROR','FAILURE'))
    lats = [int(r.get('latency') or 0) for r in (rows or []) if str(r.get('latency') or '').isdigit()]
    avg_lat = round(sum(lats)/len(lats)) if lats else 0
    nodes, edges = v2._build_nodes_and_edges(flow, len(rows or []), err_count, avg_lat)
    arch["nodes"] = nodes; arch["edges"] = edges
    arch["matrix"] = [{"from":e["from"],"to":e["to"],"calls":e["count"],"errors":e["errors"],"avg_latency_ms":e["avg_latency_ms"],"error_rate":e["error_rate"]} for e in edges]
    arch["tiers"] = sorted({n["tier"] for n in nodes}, key=lambda t: {"Client":0,"Gateway":1,"API":2,"Service":3,"External":4,"Data":5}.get(t,9))
    arch.setdefault("hints", []).insert(0, "V4 topology engine: reconstructs generic Mule subflows, HTTP downstreams, CBS/LMS/Bureau/KYC/payment dependencies, and filters processor noise.")
    return arch
