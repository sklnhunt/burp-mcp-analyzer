#!/usr/bin/env python3
"""
Burp Suite .burp File Analyzer — Custom MCP Server  v2.0
Analyze Burp project files offline. No Burp running required.
19 tools total.
"""

import asyncio, base64, json, re, xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs

import mcp.server.stdio
import mcp.types as types
from mcp.server import Server

# ── Global state ──────────────────────────────────────────────────────────────
state: dict[str, Any] = {
    "file_path": None,
    "proxy_history": [],
    "scanner_issues": [],
    "raw_files": {},
    "metadata": {},
}

# ── Sensitive data patterns ───────────────────────────────────────────────────
SENSITIVE_PATTERNS: dict[str, str] = {
    "JWT Token":           r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
    "Bearer Token":        r"(?i)bearer\s+([a-zA-Z0-9_\-\.]{20,})",
    "Basic Auth":          r"(?i)basic\s+([a-zA-Z0-9+/=]{10,})",
    "API Key (Generic)":   r"(?i)(api[_-]?key|x-api-key)\s*[=:]\s*['\"]?([a-zA-Z0-9_\-]{20,})",
    "AWS Access Key":      r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":      r"(?i)aws[_-]?secret[_-]?(?:access)?[_-]?key\s*[=:]\s*['\"]?([a-zA-Z0-9/+]{40})",
    "Google API Key":      r"AIza[0-9A-Za-z_\-]{35}",
    "GitHub Token":        r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "Slack Token":         r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24}",
    "Stripe Key":          r"sk_live_[a-zA-Z0-9]{24,}",
    "SendGrid Key":        r"SG\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}",
    "Private Key":         r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
    "Password in URL":     r"(?i)[?&](password|passwd|pwd|pass)=([^&\s\"']+)",
    "Password in Body":    r"(?i)\"password\"\s*:\s*\"([^\"]+)\"",
    "DB Connection String": r"(?i)(postgresql|mysql|mongodb|redis|mssql):\/\/[^\s\"']+:[^\s\"'@]+@",
    "Session Cookie":      r"(?i)(PHPSESSID|JSESSIONID|connect\.sid|sessionid)\s*[=:]\s*([a-zA-Z0-9_\-\.]{10,})",
    "SQL Error":           r"(?i)(SQLITE_ERROR|SQL syntax.*MySQL|ORA-[0-9]{5}|PostgreSQL.*ERROR|SequelizeDatabaseError)",
    "Stack Trace":         r"(?i)at [a-zA-Z0-9_.]+\([a-zA-Z0-9_.]+\.(js|py|java|rb|php|cs):\d+\)",
    "Internal IP":         r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    "Email Address":       r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    "Credit Card":         r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
}

INTERESTING_PATHS = [
    "/admin", "/administrator", "/manage", "/management", "/dashboard",
    "/api/v1", "/api/v2", "/api/internal", "/internal",
    "/debug", "/test", "/dev", "/development",
    "/backup", "/bak", "/.git", "/.env", "/config",
    "/swagger", "/api-docs", "/openapi", "/graphql",
    "/metrics", "/health", "/status", "/actuator",
    "/phpmyadmin", "/wp-admin", "/wp-login",
    "/console", "/shell", "/terminal",
    "/upload", "/uploads", "/files", "/attachments",
]

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS",
    "Content-Security-Policy":   "Prevents XSS and injection",
    "X-Frame-Options":           "Prevents clickjacking",
    "X-Content-Type-Options":    "Prevents MIME sniffing",
    "Referrer-Policy":           "Controls referrer info",
    "Permissions-Policy":        "Controls browser features",
    "Cache-Control":             "Controls response caching",
    "Access-Control-Allow-Origin": "CORS policy",
}

server = Server("burp-file-analyzer")

# ══════════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════════

def b64decode(s: str) -> str:
    try:
        return base64.b64decode(s).decode("utf-8", errors="replace")
    except Exception:
        return s

def parse_proxy_xml(xml_text: str) -> list[dict]:
    items = []
    try:
        root = ET.fromstring(xml_text)
        els  = root.findall(".//item") if root.tag != "item" else [root]
        for el in els:
            def g(tag): n = el.find(tag); return (n.text or "").strip() if n is not None else ""
            req_el  = el.find("request");  resp_el = el.find("response")
            req_raw = b64decode(req_el.text)  if req_el  is not None and req_el.text  and req_el.get("base64")  == "true" else (req_el.text  or "") if req_el  else ""
            resp_raw= b64decode(resp_el.text) if resp_el is not None and resp_el.text and resp_el.get("base64") == "true" else (resp_el.text or "") if resp_el else ""
            items.append({"time":g("time"),"url":g("url"),"host":g("host"),"port":g("port"),
                          "protocol":g("protocol"),"method":g("method"),"path":g("path"),
                          "extension":g("extension"),"status":g("status"),"length":g("responselength"),
                          "mimetype":g("mimetype"),"comment":g("comment"),
                          "request_raw":req_raw,"response_raw":resp_raw})
    except ET.ParseError:
        pass
    return items

def parse_issues_xml(xml_text: str) -> list[dict]:
    issues = []
    try:
        root = ET.fromstring(xml_text)
        for el in root.findall(".//issue"):
            def g(tag): n = el.find(tag); return (n.text or "").strip() if n is not None else ""
            issues.append({"name":g("name"),"severity":g("severity"),"confidence":g("confidence"),
                           "host":g("host"),"path":g("path"),"location":g("location"),
                           "detail":g("issueDetail"),"background":g("issueBackground"),
                           "remediation":g("remediationBackground")})
    except ET.ParseError:
        pass
    return issues

def _parse_xml_content(text: str, r: dict, source_name: str = "file") -> None:
    """Parse XML text and populate proxy_history / scanner_issues in r."""
    r["files"][source_name] = text
    if "<items" in text or ("<item>" in text and "<request" in text):
        items = parse_proxy_xml(text)
        r["proxy_history"].extend(items)
    if "<issues" in text or ("<issue>" in text and "<severity>" in text):
        issues = parse_issues_xml(text)
        r["scanner_issues"].extend(issues)


def load_file(path: str) -> dict:
    """
    Loader — tries formats in order:
      1. Plain XML  (.xml Burp export)
      2. Gzip-compressed XML
    """
    import gzip as _gzip

    r: dict = {"files": {}, "zip_contents": [], "proxy_history": [],
               "scanner_issues": [], "format": "unknown"}

    # ── 1. Try plain XML ──────────────────────────────────────────────────────
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        if text.lstrip().startswith("<") and (
            "<items" in text or "<issues" in text or
            "<item>" in text or "<issue>" in text
        ):
            r["format"] = "xml"
            r["zip_contents"] = [Path(path).name]
            _parse_xml_content(text, r, Path(path).name)
            return r
    except Exception:
        pass

    # ── 2. Try gzip-compressed XML ────────────────────────────────────────────
    try:
        with _gzip.open(path, "rb") as gz:
            raw = gz.read()
        text = raw.decode("utf-8", errors="replace")
        if "<items" in text or "<issues" in text or "<item>" in text:
            r["format"] = "gzip+xml"
            r["zip_contents"] = [Path(path).name + " (gzip)"]
            _parse_xml_content(text, r, Path(path).name)
            return r
    except Exception:
        pass

    # ── Nothing worked ────────────────────────────────────────────────────────
    r["error"] = (
        "Could not parse this file. Only Burp XML exports are supported.\n\n"
        "How to export from Burp Suite:\n\n"
        "  Option A — Proxy history only (quickest):\n"
        "    Proxy tab → HTTP History → Ctrl+A (select all)\n"
        "    → Right-click → Save items → save as .xml\n\n"
        "  Option B — Everything including scanner issues (Pro only):\n"
        "    Top menu → Project → Save copy → choose XML format"
    )
    return r

def scan_sensitive(text: str, ctx: str = "") -> list[dict]:
    hits = []
    for name, pat in SENSITIVE_PATTERNS.items():
        for m in re.finditer(pat, text):
            hits.append({"type": name, "context": ctx, "match": m.group(0)[:200]})
    return hits

def parse_headers(raw: str) -> dict[str, str]:
    """Extract headers from raw HTTP request or response."""
    headers: dict[str, str] = {}
    lines = raw.split("\n")
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
        if line.strip() == "":
            break
    return headers

def require_loaded() -> str | None:
    return None if state["file_path"] else "❌ No file loaded. Call load_burp_file first."

def out(text: str) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=text)]

# ══════════════════════════════════════════════════════════════════════════════
# Tool definitions
# ══════════════════════════════════════════════════════════════════════════════

@server.list_tools()
async def list_tools() -> list[types.Tool]:
    def T(name, desc, props=None, req=None):
        schema: dict = {"type":"object","properties": props or {}}
        if req: schema["required"] = req
        return types.Tool(name=name, description=desc, inputSchema=schema)

    return [
        # ── Core ──────────────────────────────────────────────────────────────
        T("load_burp_file",         "Load and parse a Burp XML export file (.xml). Export from Burp via Proxy → HTTP History → Save items. Call this first.",
          {"file_path":{"type":"string","description":"Absolute path to Burp XML export file"}}, ["file_path"]),
        T("explore_file_structure", "Show the raw internal files inside the .burp ZIP archive."),
        T("get_statistics",         "Status codes, HTTP methods, top hosts, MIME types breakdown."),
        T("generate_report",        "Full summary report: stats, vulnerabilities, secrets, recommendations."),

        # ── Traffic ───────────────────────────────────────────────────────────
        T("get_proxy_history",      "List HTTP requests with optional filters (method/status/host/mimetype).",
          {"limit":{"type":"integer"},"method":{"type":"string"},"status":{"type":"string"},
           "host":{"type":"string"},"mimetype":{"type":"string"}}),
        T("analyze_request",        "Deep-dive a single request by index number.",
          {"index":{"type":"integer","description":"0-based index from proxy history"}}, ["index"]),
        T("search_requests",        "Search request/response bodies and URLs by keyword or regex.",
          {"query":{"type":"string"},"search_in":{"type":"string","enum":["requests","responses","both","urls"]}}, ["query"]),
        T("find_errors",            "Show all 4xx and 5xx responses with details.",
          {"min_status":{"type":"integer","description":"Min status code to include (default 400)"}}),

        # ── Recon ─────────────────────────────────────────────────────────────
        T("find_endpoints",         "Map all unique URL paths/endpoints, grouped by host."),
        T("find_parameters",        "Extract all query string and POST body parameters seen across requests."),
        T("get_cookies",            "List all cookies seen across requests and responses."),
        T("detect_technologies",    "Fingerprint the tech stack from Server, X-Powered-By, and other headers."),
        T("find_interesting_paths", "Highlight admin, debug, backup, config, and API paths found in traffic."),
        T("find_file_uploads",      "Identify multipart/form-data upload endpoints."),

        # ── Security analysis ─────────────────────────────────────────────────
        T("get_vulnerabilities",    "List Burp scanner findings. Burp Pro projects only.",
          {"severity":{"type":"string","enum":["High","Medium","Low","Information"]}}),
        T("find_sensitive_data",    "Scan all traffic for secrets: API keys, JWTs, passwords, AWS creds, PII.",
          {"pattern_types":{"type":"array","items":{"type":"string"}}}),
        T("analyze_security_headers","Check all responses for missing/misconfigured security headers.",
          {"host":{"type":"string","description":"Filter to a specific host"}}),
        T("find_injection_points",  "Identify GET params and POST body params that could be injection targets."),
        T("export_as_curl",         "Convert one or more requests to copy-paste curl commands.",
          {"indexes":{"type":"array","items":{"type":"integer"},"description":"Request indexes (empty = first 5)"},
           "include_headers":{"type":"boolean","description":"Include all request headers (default true)"}}),
    ]

# ══════════════════════════════════════════════════════════════════════════════
# Tool handlers
# ══════════════════════════════════════════════════════════════════════════════

@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[types.TextContent]:

    # ── load_burp_file ────────────────────────────────────────────────────────
    if name == "load_burp_file":
        path = arguments.get("file_path","").strip()
        if not Path(path).exists():
            return out(f"❌ File not found: {path}")
        state.update({"file_path":path,"proxy_history":[],"scanner_issues":[],"raw_files":{},"metadata":{
            "file_path":path,"file_size":Path(path).stat().st_size}})
        data = load_file(path)
        if "error" in data:
            return out(f"⚠️  {data['error']}\n\nFile: {path}\nSize: {state['metadata']['file_size']:,} bytes")
        state["proxy_history"]  = data["proxy_history"]
        state["scanner_issues"] = data["scanner_issues"]
        state["raw_files"]      = data["files"]
        state["metadata"]["zip_contents"] = data["zip_contents"]
        fmt_labels = {"xml":"Burp XML export", "gzip+xml":"Gzip-compressed XML"}
        fmt = fmt_labels.get(data.get("format",""), data.get("format","unknown"))
        lines = [f"✅  Loaded: {Path(path).name}",
                 f"📄  Format:         {fmt}",
                 f"📦  Size:           {state['metadata']['file_size']:,} bytes",
                 f"📁  Internal files: {len(data['zip_contents'])}",
                 f"🌐  Proxy items:    {len(state['proxy_history'])}",
                 f"🔴  Scanner issues: {len(state['scanner_issues'])}","",
                 "Files parsed:"]
        for f in data["zip_contents"]: lines.append(f"   • {f}")
        if not state["proxy_history"] and not state["scanner_issues"]:
            lines += ["","⚠️  Nothing auto-parsed. Try explore_file_structure to inspect raw contents."]
        return out("\n".join(lines))

    # ── explore_file_structure ────────────────────────────────────────────────
    if name == "explore_file_structure":
        if e := require_loaded(): return out(e)
        lines = [f"📁  {Path(state['file_path']).name} — internal structure\n"]
        for fname, content in state["raw_files"].items():
            if isinstance(content, str):
                lines.append(f"── {fname}  ({len(content):,} chars)")
                lines.append(f"   {content[:400].replace(chr(10),' ')}…\n")
            else:
                lines.append(f"── {fname}  (parsed JSON)\n")
        return out("\n".join(lines))

    # ── get_proxy_history ─────────────────────────────────────────────────────
    if name == "get_proxy_history":
        if e := require_loaded(): return out(e)
        items = state["proxy_history"]
        if f := arguments.get("method"):   items = [i for i in items if i["method"].upper()==f.upper()]
        if f := arguments.get("status"):   items = [i for i in items if i["status"]==f]
        if f := arguments.get("host"):     items = [i for i in items if f.lower() in i["host"].lower()]
        if f := arguments.get("mimetype"): items = [i for i in items if f.lower() in i["mimetype"].lower()]
        total  = len(items)
        items  = items[:arguments.get("limit", 50)]
        if not items: return out("No items match the given filters.")
        lines  = [f"🌐  Proxy History — {len(items)} of {total} items\n"]
        for idx, i in enumerate(items):
            lines.append(f"[{idx:>3}] {i['method']:<7} {i['url']}")
            lines.append(f"        Status: {i['status']}  Size: {i['length']}  Type: {i['mimetype']}")
            if i.get("comment"): lines.append(f"        💬 {i['comment']}")
            lines.append("")
        return out("\n".join(lines))

    # ── analyze_request ───────────────────────────────────────────────────────
    if name == "analyze_request":
        if e := require_loaded(): return out(e)
        idx = arguments.get("index", 0)
        if idx >= len(state["proxy_history"]):
            return out(f"❌ Index {idx} out of range (total: {len(state['proxy_history'])})")
        i = state["proxy_history"][idx]
        sens = scan_sensitive(i.get("request_raw","") + i.get("response_raw",""), f"Request #{idx}")
        lines = [f"🔍  Request #{idx}","─"*52,
                 f"  URL:     {i['url']}",f"  Method:  {i['method']}",
                 f"  Status:  {i['status']}",f"  Size:    {i['length']} bytes",
                 f"  Type:    {i['mimetype']}",f"  Time:    {i.get('time') or 'N/A'}",
                 f"  Comment: {i.get('comment') or '(none)'}","",
                 "── REQUEST ──────────────────────────────────────────",
                 i.get("request_raw","")[:3000] or "(empty)","",
                 "── RESPONSE ─────────────────────────────────────────",
                 i.get("response_raw","")[:3000] or "(empty)"]
        if sens:
            lines += ["",f"── ⚠️  SENSITIVE DATA ({len(sens)} hit/s) ───────────────────"]
            for h in sens[:15]: lines.append(f"  [{h['type']}]  {h['match'][:120]}")
        return out("\n".join(lines))

    # ── search_requests ───────────────────────────────────────────────────────
    if name == "search_requests":
        if e := require_loaded(): return out(e)
        q = arguments.get("query",""); where = arguments.get("search_in","both")
        try: pat = re.compile(q, re.IGNORECASE)
        except: pat = re.compile(re.escape(q), re.IGNORECASE)
        results = []
        for idx, i in enumerate(state["proxy_history"]):
            hit = []
            if where in ("urls","both") and pat.search(i.get("url","")): hit.append("URL")
            if where in ("requests","both") and pat.search(i.get("request_raw","")): hit.append("Request")
            if where in ("responses","both") and pat.search(i.get("response_raw","")): hit.append("Response")
            if hit: results.append((idx, i, hit))
        if not results: return out(f"No matches for: {q}")
        lines = [f"🔍  '{q}' — {len(results)} match(es)\n"]
        for idx, i, hit in results[:50]:
            lines.append(f"[{idx:>3}] {i['method']:<7} {i['url']}")
            lines.append(f"        Found in: {', '.join(hit)}  Status: {i['status']}\n")
        if len(results) > 50: lines.append(f"… and {len(results)-50} more")
        return out("\n".join(lines))

    # ── get_vulnerabilities ───────────────────────────────────────────────────
    if name == "get_vulnerabilities":
        if e := require_loaded(): return out(e)
        issues = state["scanner_issues"]
        if sv := arguments.get("severity"): issues = [i for i in issues if i["severity"].lower()==sv.lower()]
        if not issues: return out("No scanner issues. (Only available in Burp Pro project files.)")
        order = {"High":0,"Medium":1,"Low":2,"Information":3}
        icons = {"High":"🔴","Medium":"🟠","Low":"🟡","Information":"🔵"}
        issues = sorted(issues, key=lambda x: order.get(x["severity"],9))
        lines  = [f"🔴  Scanner Issues — {len(issues)} finding(s)\n"]
        for i in issues:
            lines.append(f"{icons.get(i['severity'],'⚪')} [{i['severity']}]  {i['name']}")
            lines.append(f"   Host: {i['host']}  Path: {i['path']}")
            lines.append(f"   Location: {i['location']}  Confidence: {i['confidence']}")
            if i.get("detail"):      lines.append(f"   Detail: {i['detail'][:300]}")
            if i.get("remediation"): lines.append(f"   Fix: {i['remediation'][:200]}")
            lines.append("")
        return out("\n".join(lines))

    # ── find_sensitive_data ───────────────────────────────────────────────────
    if name == "find_sensitive_data":
        if e := require_loaded(): return out(e)
        ft = arguments.get("pattern_types", [])
        all_hits: list[dict] = []
        for idx, i in enumerate(state["proxy_history"]):
            for text, ctx in [(i.get("request_raw",""), f"[{idx}] Req  {i['method']} {i['url']}"),
                              (i.get("response_raw",""), f"[{idx}] Resp {i['method']} {i['url']} → {i['status']}")]:
                if not text: continue
                hits = scan_sensitive(text, ctx)
                if ft: hits = [h for h in hits if h["type"] in ft]
                all_hits.extend(hits)
        if not all_hits: return out("✅  No sensitive data detected.")
        by_type: dict = {}
        for h in all_hits: by_type.setdefault(h["type"], []).append(h)
        lines = [f"⚠️   Sensitive Data — {len(all_hits)} hit(s) in {len(by_type)} categories\n"]
        for cat, hits in sorted(by_type.items()):
            lines.append(f"── {cat}  ({len(hits)} hit{'s' if len(hits)>1 else ''})")
            for h in hits[:5]:
                lines.append(f"   Context: {h['context']}")
                lines.append(f"   Match:   {h['match'][:120]}\n")
            if len(hits) > 5: lines.append(f"   … and {len(hits)-5} more\n")
        return out("\n".join(lines))

    # ── get_statistics ────────────────────────────────────────────────────────
    if name == "get_statistics":
        if e := require_loaded(): return out(e)
        items = state["proxy_history"]
        if not items: return out("No proxy history.")
        methods = Counter(i["method"] for i in items)
        statuses= Counter(i["status"] for i in items)
        hosts   = Counter(i["host"]   for i in items)
        mimes   = Counter(i["mimetype"] for i in items)
        exts    = Counter(i.get("extension","-") for i in items)
        mx      = max(statuses.values()) if statuses else 1
        lines   = [f"📊  Statistics — {len(items):,} requests\n",
                   "── HTTP Methods ──────────────────────────────────"]
        for m, c in methods.most_common():
            lines.append(f"  {m:<8} {c:>5}  {'█'*int(c/mx*25)}")
        lines.append("\n── Status Codes ──────────────────────────────────")
        for s, c in sorted(statuses.items()):
            icon = "✅" if s.startswith("2") else "🔀" if s.startswith("3") else "❌"
            lines.append(f"  {icon} {s}   ×{c:,}")
        lines.append("\n── Top Hosts ─────────────────────────────────────")
        for h, c in hosts.most_common(10): lines.append(f"  {h:<45} ×{c:,}")
        lines.append("\n── MIME Types ────────────────────────────────────")
        for t, c in mimes.most_common(10):  lines.append(f"  {t:<25} ×{c:,}")
        lines.append("\n── File Extensions ───────────────────────────────")
        for x, c in exts.most_common(10):   lines.append(f"  .{x:<20} ×{c:,}")
        return out("\n".join(lines))

    # ── find_errors ───────────────────────────────────────────────────────────
    if name == "find_errors":
        if e := require_loaded(): return out(e)
        min_s = str(arguments.get("min_status", 400))
        errors = [(idx, i) for idx, i in enumerate(state["proxy_history"])
                  if i["status"] >= min_s]
        if not errors: return out(f"No responses with status >= {min_s}.")
        by_code: dict = defaultdict(list)
        for idx, i in errors: by_code[i["status"]].append((idx, i))
        lines = [f"❌  Error Responses — {len(errors)} total (status ≥ {min_s})\n"]
        for code in sorted(by_code):
            lines.append(f"── HTTP {code}  ({len(by_code[code])} requests)")
            for idx, i in by_code[code][:5]:
                lines.append(f"  [{idx:>3}] {i['method']} {i['url']}")
                body = i.get("response_raw","")
                body_preview = body.split("\r\n\r\n",1)[-1][:200] if "\r\n\r\n" in body else body[:200]
                if body_preview.strip(): lines.append(f"         Body: {body_preview.strip()}")
            if len(by_code[code]) > 5: lines.append(f"  … and {len(by_code[code])-5} more")
            lines.append("")
        return out("\n".join(lines))

    # ── find_endpoints ────────────────────────────────────────────────────────
    if name == "find_endpoints":
        if e := require_loaded(): return out(e)
        by_host: dict = defaultdict(set)
        for i in state["proxy_history"]:
            try:
                p = urlparse(i["url"]).path
                by_host[i["host"]].add(f"{i['method']} {p}")
            except: pass
        lines = [f"🗺️   Endpoints — {sum(len(v) for v in by_host.values())} unique paths across {len(by_host)} host(s)\n"]
        for host in sorted(by_host):
            lines.append(f"── {host}  ({len(by_host[host])} paths)")
            for ep in sorted(by_host[host]): lines.append(f"   {ep}")
            lines.append("")
        return out("\n".join(lines))

    # ── find_parameters ───────────────────────────────────────────────────────
    if name == "find_parameters":
        if e := require_loaded(): return out(e)
        query_params: Counter = Counter()
        body_params:  Counter = Counter()
        for i in state["proxy_history"]:
            try:
                qs = urlparse(i["url"]).query
                for k in parse_qs(qs): query_params[k] += 1
            except: pass
            body = ""
            if "\r\n\r\n" in i.get("request_raw",""):
                body = i["request_raw"].split("\r\n\r\n",1)[1]
            ct = ""
            for line in i.get("request_raw","").split("\n"):
                if line.lower().startswith("content-type:"): ct = line.lower(); break
            if "application/x-www-form-urlencoded" in ct:
                for k in parse_qs(body): body_params[k] += 1
            elif "application/json" in ct:
                try:
                    for k in json.loads(body): body_params[k] += 1
                except: pass
        lines = [f"🔎  Parameters Found\n",
                 f"── Query String Params ({len(query_params)}) ───────────────────"]
        for p, c in query_params.most_common(30): lines.append(f"  ?{p}   ×{c}")
        lines.append(f"\n── POST Body Params ({len(body_params)}) ─────────────────────")
        for p, c in body_params.most_common(30): lines.append(f"  {p}   ×{c}")
        return out("\n".join(lines))

    # ── get_cookies ───────────────────────────────────────────────────────────
    if name == "get_cookies":
        if e := require_loaded(): return out(e)
        sent: dict = {}; received: dict = {}
        for i in state["proxy_history"]:
            raw_req = i.get("request_raw","")
            for line in raw_req.split("\n"):
                if line.lower().startswith("cookie:"):
                    for pair in line.split(":",1)[1].split(";"):
                        if "=" in pair:
                            k, _, v = pair.strip().partition("=")
                            sent[k.strip()] = v.strip()[:80]
            raw_resp = i.get("response_raw","")
            for line in raw_resp.split("\n"):
                if line.lower().startswith("set-cookie:"):
                    pair = line.split(":",1)[1].split(";")[0].strip()
                    if "=" in pair:
                        k, _, v = pair.partition("=")
                        received[k.strip()] = v.strip()[:80]
        lines = [f"🍪  Cookies\n── Sent by Client ({len(sent)}) ───────────────────────"]
        for k, v in sorted(sent.items()): lines.append(f"  {k} = {v[:60]}")
        lines.append(f"\n── Set by Server ({len(received)}) ─────────────────────────")
        for k, v in sorted(received.items()): lines.append(f"  {k} = {v[:60]}")
        return out("\n".join(lines))

    # ── detect_technologies ───────────────────────────────────────────────────
    if name == "detect_technologies":
        if e := require_loaded(): return out(e)
        tech: dict = defaultdict(set)
        for i in state["proxy_history"]:
            raw = i.get("response_raw","")
            for line in raw.split("\n"):
                l = line.strip()
                kl = l.lower()
                if kl.startswith("server:"):           tech["Server"].add(l.split(":",1)[1].strip())
                elif kl.startswith("x-powered-by:"):   tech["Runtime/Framework"].add(l.split(":",1)[1].strip())
                elif kl.startswith("x-generator:"):    tech["Generator"].add(l.split(":",1)[1].strip())
                elif kl.startswith("x-aspnet"):        tech["Framework"].add("ASP.NET")
                elif "laravel" in kl:                  tech["Framework"].add("Laravel (PHP)")
                elif "django" in kl:                   tech["Framework"].add("Django (Python)")
                elif "rails" in kl:                    tech["Framework"].add("Ruby on Rails")
                elif kl.startswith("x-wp-"):           tech["CMS"].add("WordPress")
                elif kl.startswith("x-drupal"):        tech["CMS"].add("Drupal")
            body = raw.split("\r\n\r\n",1)[-1] if "\r\n\r\n" in raw else ""
            if "angular" in body.lower():   tech["Frontend"].add("Angular")
            if "react" in body.lower():     tech["Frontend"].add("React")
            if "vue" in body.lower():       tech["Frontend"].add("Vue.js")
            if "jquery" in body.lower():    tech["Frontend"].add("jQuery")
            if "bootstrap" in body.lower(): tech["Frontend"].add("Bootstrap")
            if "sequelize" in body.lower(): tech["ORM/DB"].add("Sequelize (Node.js ORM)")
            if "sqlite" in body.lower():    tech["ORM/DB"].add("SQLite")
            if "socket.io" in body.lower(): tech["Protocol"].add("Socket.IO (WebSocket)")
        lines = [f"🔬  Technology Fingerprint\n"]
        if not any(tech.values()): lines.append("No technology indicators detected.")
        for category in sorted(tech):
            lines.append(f"── {category}")
            for t in sorted(tech[category]): lines.append(f"   • {t}")
            lines.append("")
        return out("\n".join(lines))

    # ── find_interesting_paths ────────────────────────────────────────────────
    if name == "find_interesting_paths":
        if e := require_loaded(): return out(e)
        found = []
        for idx, i in enumerate(state["proxy_history"]):
            try:
                path = urlparse(i["url"]).path.lower()
                for ip in INTERESTING_PATHS:
                    if path.startswith(ip) or ip in path:
                        found.append((idx, i, ip))
                        break
            except: pass
        if not found: return out("No interesting paths found in traffic.")
        lines = [f"⚑   Interesting Paths — {len(found)} found\n"]
        by_cat: dict = defaultdict(list)
        cats = {"/admin":"Admin Panel","/manage":"Admin Panel","/administrator":"Admin Panel",
                "/dashboard":"Admin Panel","/debug":"Debug/Dev","/test":"Debug/Dev",
                "/dev":"Debug/Dev","/development":"Debug/Dev","/backup":"Backup/Config",
                "/.git":"Backup/Config","/.env":"Backup/Config","/config":"Backup/Config",
                "/swagger":"API Docs","/api-docs":"API Docs","/openapi":"API Docs",
                "/graphql":"API Docs","/metrics":"Monitoring","/health":"Monitoring",
                "/status":"Monitoring","/actuator":"Monitoring","/upload":"File Upload",
                "/uploads":"File Upload","/files":"File Upload",}
        for idx, i, ip in found:
            cat = cats.get(ip, "Other")
            by_cat[cat].append((idx, i))
        for cat in sorted(by_cat):
            lines.append(f"── {cat}")
            for idx, i in by_cat[cat]:
                lines.append(f"  [{idx:>3}] {i['method']} {i['url']}  → {i['status']}")
            lines.append("")
        return out("\n".join(lines))

    # ── find_file_uploads ─────────────────────────────────────────────────────
    if name == "find_file_uploads":
        if e := require_loaded(): return out(e)
        uploads = [(idx, i) for idx, i in enumerate(state["proxy_history"])
                   if "multipart/form-data" in i.get("request_raw","").lower() or
                      "filename=" in i.get("request_raw","").lower()]
        if not uploads: return out("No file upload requests detected.")
        lines = [f"📎  File Upload Endpoints — {len(uploads)} found\n"]
        for idx, i in uploads:
            lines.append(f"[{idx:>3}] {i['method']} {i['url']}  → {i['status']}")
            req = i.get("request_raw","")
            for line in req.split("\n"):
                if "filename=" in line.lower():
                    lines.append(f"        {line.strip()}")
            lines.append("")
        return out("\n".join(lines))

    # ── analyze_security_headers ──────────────────────────────────────────────
    if name == "analyze_security_headers":
        if e := require_loaded(): return out(e)
        host_filter = arguments.get("host","").lower()
        # Track present/absent per host
        host_headers: dict = defaultdict(lambda: defaultdict(set))
        for i in state["proxy_history"]:
            if host_filter and host_filter not in i["host"].lower(): continue
            h = parse_headers(i.get("response_raw",""))
            hk = {k.lower() for k in h}
            for hdr in SECURITY_HEADERS:
                if hdr.lower() in hk:
                    host_headers[i["host"]]["present"].add(hdr)
                    # Check CORS wildcard
                    if hdr == "Access-Control-Allow-Origin":
                        v = h.get(hdr,"")
                        if v.strip() == "*": host_headers[i["host"]]["cors_wildcard"].add(hdr)
                else:
                    host_headers[i["host"]]["missing"].add(hdr)
        if not host_headers: return out("No response headers to analyze.")
        lines = [f"🛡️   Security Header Analysis — {len(host_headers)} host(s)\n"]
        for host in sorted(host_headers):
            d = host_headers[host]
            present = d.get("present", set())
            missing = d.get("missing", set())
            cors_wc = d.get("cors_wildcard", set())
            lines.append(f"── {host}")
            for hdr in sorted(present):
                flag = "  ⚠️  CORS wildcard (*) — dangerous with credentials!" if hdr in cors_wc else ""
                lines.append(f"  ✅  {hdr}{flag}")
            for hdr in sorted(missing):
                lines.append(f"  ❌  {hdr} MISSING  ({SECURITY_HEADERS[hdr]})")
            lines.append("")
        return out("\n".join(lines))

    # ── find_injection_points ─────────────────────────────────────────────────
    if name == "find_injection_points":
        if e := require_loaded(): return out(e)
        points = []
        for idx, i in enumerate(state["proxy_history"]):
            params_found = []
            # Query string params
            try:
                qs = urlparse(i["url"]).query
                qp = parse_qs(qs)
                for k, vals in qp.items():
                    params_found.append(("Query", k, vals[0][:50] if vals else ""))
            except: pass
            # POST body
            req = i.get("request_raw","")
            if "\r\n\r\n" in req:
                body = req.split("\r\n\r\n",1)[1]
                ct   = ""
                for line in req.split("\n"):
                    if line.lower().startswith("content-type:"): ct = line.lower(); break
                if "application/x-www-form-urlencoded" in ct:
                    for k, vals in parse_qs(body).items():
                        params_found.append(("POST form", k, vals[0][:50] if vals else ""))
                elif "application/json" in ct:
                    try:
                        for k, v in json.loads(body).items():
                            params_found.append(("JSON body", k, str(v)[:50]))
                    except: pass
            if params_found:
                points.append((idx, i, params_found))
        if not points: return out("No injection points found.")
        lines = [f"💉  Injection Points — {sum(len(p[2]) for p in points)} params across {len(points)} requests\n"]
        for idx, i, params in points[:30]:
            lines.append(f"[{idx:>3}] {i['method']} {i['url']}")
            for ptype, pname, pval in params:
                lines.append(f"        [{ptype}] {pname} = {pval}")
            lines.append("")
        return out("\n".join(lines))

    # ── export_as_curl ────────────────────────────────────────────────────────
    if name == "export_as_curl":
        if e := require_loaded(): return out(e)
        idxs = arguments.get("indexes", list(range(min(5, len(state["proxy_history"])))))
        inc_headers = arguments.get("include_headers", True)
        lines = [f"🔁  curl Commands — {len(idxs)} request(s)\n"]
        for idx in idxs:
            if idx >= len(state["proxy_history"]): continue
            i   = state["proxy_history"][idx]
            req = i.get("request_raw","")
            raw_lines = req.split("\n")
            method = i["method"]
            url    = i["url"]
            headers= []
            body   = ""
            in_body= False
            for line in raw_lines[1:]:
                l = line.rstrip()
                if l == "" or l == "\r": in_body = True; continue
                if in_body: body += line
                elif ":" in l and inc_headers:
                    k, _, v = l.partition(":")
                    if k.strip().lower() not in ("host","content-length"):
                        headers.append(f"-H '{k.strip()}: {v.strip()}'")
            curl = f"curl -X {method} '{url}'"
            if headers: curl += " \\\n  " + " \\\n  ".join(headers)
            if body.strip(): curl += f" \\\n  -d '{body.strip()[:500]}'"
            lines.append(f"# [{idx}] {i.get('comment','')}")
            lines.append(curl)
            lines.append("")
        return out("\n".join(lines))

    # ── generate_report ───────────────────────────────────────────────────────
    if name == "generate_report":
        if e := require_loaded(): return out(e)
        items  = state["proxy_history"]
        issues = state["scanner_issues"]
        fname  = Path(state["file_path"]).name
        all_hits: list[dict] = []
        for i in items:
            all_hits.extend(scan_sensitive(i.get("request_raw","")+i.get("response_raw",""),""))
        sens_types = {h["type"] for h in all_hits}
        hosts   = Counter(i["host"]     for i in items)
        statuses= Counter(i["status"]   for i in items)
        sev_cnt = Counter(i["severity"] for i in issues)
        uploads = sum(1 for i in items if "multipart/form-data" in i.get("request_raw","").lower())
        errors  = sum(1 for i in items if i["status"] >= "400")
        lines   = [
            "╔══════════════════════════════════════════════════════╗",
            "║         BURP FILE ANALYSIS REPORT                   ║",
            "╚══════════════════════════════════════════════════════╝",
            f"  File:       {fname}",
            f"  Generated:  {datetime.now().strftime('%Y-%m-%d %H:%M')}","",
            "── OVERVIEW ───────────────────────────────────────────",
            f"  Total Requests:       {len(items):,}",
            f"  Unique Hosts:         {len(hosts):,}",
            f"  Error Responses:      {errors:,}",
            f"  File Uploads:         {uploads:,}",
            f"  Scanner Issues:       {len(issues):,}",
            f"  Sensitive Findings:   {len(all_hits):,}","",
            "── SECURITY ISSUES ────────────────────────────────────",
        ]
        for sev, icon in [("High","🔴"),("Medium","🟠"),("Low","🟡"),("Information","🔵")]:
            lines.append(f"  {icon} {sev:<14} {sev_cnt.get(sev,0):>4}")
        if sens_types:
            lines += ["","── SENSITIVE DATA ──────────────────────────────────"]
            for t in sorted(sens_types):
                cnt = sum(1 for h in all_hits if h["type"]==t)
                lines.append(f"  ⚠️  {t:<38} ×{cnt}")
        lines += ["","── TOP TARGETS ─────────────────────────────────────"]
        for h, c in hosts.most_common(8): lines.append(f"  {h:<45} {c:>5} req")
        lines += ["","── STATUS BREAKDOWN ────────────────────────────────"]
        for s, c in sorted(statuses.items()):
            icon = "✅" if s.startswith("2") else "🔀" if s.startswith("3") else "❌"
            lines.append(f"  {icon} HTTP {s}   ×{c:,}")
        lines += ["","── RECOMMENDATIONS ─────────────────────────────────"]
        recs = []
        if sev_cnt.get("High",0):     recs.append("🔴 Fix all HIGH severity scanner findings immediately")
        if sev_cnt.get("Medium",0):   recs.append("🟠 Review MEDIUM severity findings for exploitability")
        if len(all_hits):             recs.append("⚠️  Sensitive data in traffic — investigate exposure")
        if statuses.get("500",0):     recs.append(f"💥 {statuses['500']} server errors — check for info disclosure")
        if "SQL Error" in sens_types: recs.append("🚨 SQL errors detected — likely SQLi attack surface")
        if "Stack Trace" in sens_types:recs.append("🚨 Stack traces exposed — reveals internal tech stack")
        if uploads:                   recs.append(f"📎 {uploads} file upload endpoint(s) — verify type validation")
        if not recs:                  recs.append("✅ No critical issues detected in automated scan")
        for r in recs: lines.append(f"  {r}")
        return out("\n".join(lines))

    return out(f"❌ Unknown tool: {name}")

# ══════════════════════════════════════════════════════════════════════════════
async def main() -> None:
    async with mcp.server.stdio.stdio_server() as (r, w):
        await server.run(r, w, server.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
