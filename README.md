# 🔥 Burp Suite MCP Analyzer

An **MCP (Model Context Protocol) server** that lets AI assistants analyze Burp Suite XML exports — offline, no Burp running required.

Ask AI (or any MCP-compatible AI) to map endpoints, find secrets, detect vulnerabilities, analyze headers, export curl commands, and generate pentest reports — all from a Burp XML export file.

---

## ✨ Features — 19 Tools

| Category     | Tools                                                                                                                    |
| ------------ | ------------------------------------------------------------------------------------------------------------------------ |
| **Core**     | `load_burp_file`, `explore_file_structure`, `get_statistics`, `generate_report`                                          |
| **Traffic**  | `get_proxy_history`, `analyze_request`, `search_requests`, `find_errors`                                                 |
| **Recon**    | `find_endpoints`, `find_parameters`, `get_cookies`, `detect_technologies`, `find_interesting_paths`, `find_file_uploads` |
| **Security** | `get_vulnerabilities`, `find_sensitive_data`, `analyze_security_headers`, `find_injection_points`, `export_as_curl`      |

---

## 📋 Prerequisites

- Python 3.10+
- Any MCP-compatible AI client (Claude Desktop, Claude Code, OpenCode, Cursor, GitHub Copilot, Windsurf)
- Burp Suite (any version — just for exporting XML)

---

## 🚀 Installation

**1. Clone the repo**
```bash
git clone https://github.com/YOUR_USERNAME/burp-mcp-analyzer.git
cd burp-mcp-analyzer
```

**2. Install dependencies**
```bash
pip install -r requirements.txt
```

**3. Configure your AI client** — see [Configuration](#configuration) below

---

## 📤 Exporting from Burp Suite

The server works with **Burp XML exports** (not raw `.burp` project files).

**Option A — Proxy history only (quickest):**
```
Proxy tab → HTTP History → Ctrl+A (select all)
→ Right-click → Save items → save as export.xml
```

**Option B — Site map scanner issues:**
```
Target tab → Site map → Select URL → Under Contents → Right-click → Save items → save as export.xml
```

---

## ⚙️ Configuration

### Claude Desktop

Edit `%APPDATA%\Claude\claude_desktop_config.json` (Windows) or `~/Library/Application Support/Claude/claude_desktop_config.json` (Mac):

```json
{
  "mcpServers": {
    "burp-analyzer": {
      "command": "python3",
      "args": ["/path/to/burp_mcp_server.py"]
    }
  }
}
```

**Windows with WSL:**
```json
{
  "mcpServers": {
    "burp-analyzer": {
      "command": "wsl.exe",
      "args": ["python3", "/home/YOUR_USERNAME/burp-mcp-analyzer/burp_mcp_server.py"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add burp-analyzer python3 /path/to/burp_mcp_server.py
```

Or import from Claude Desktop if already configured:
```bash
claude mcp add-from-claude-desktop
```

### OpenCode

Edit `~/.config/opencode/config.json`:
```json
{
  "mcpServers": {
    "burp-analyzer": {
      "command": "python3",
      "args": ["/path/to/burp_mcp_server.py"],
      "type": "stdio"
    }
  }
}
```

### GitHub Copilot (VS Code)

Create `.vscode/mcp.json` in your project:
```json
{
  "servers": {
    "burp-analyzer": {
      "type": "stdio",
      "command": "python3",
      "args": ["/path/to/burp_mcp_server.py"]
    }
  }
}
```

### Cursor

Edit `~/.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "burp-analyzer": {
      "command": "python3",
      "args": ["/path/to/burp_mcp_server.py"]
    }
  }
}
```

### Windsurf

Edit `~/.codeium/windsurf/mcp_config.json`:
```json
{
  "mcpServers": {
    "burp-analyzer": {
      "command": "python3",
      "args": ["/path/to/burp_mcp_server.py"]
    }
  }
}
```

> Restart your AI client after editing config files.

---

## 💬 Usage

Once configured, load a Burp XML export and start asking:

```
Load this file: /path/to/export.xml
```

### Example Prompts

**Recon**
```
Show me all unique endpoints and paths discovered
```

**Security Analysis**
```
Scan all traffic for secrets, API keys, and credentials
Check all responses for missing or misconfigured security headers
```

**Traffic**
```
Show me all POST requests that returned 200
Find all 500 errors with the full response body
```

**Reporting**
```
Generate a full penetration test report with all findings
```

**Chained**
```
Load the file, map all endpoints, find injection points, then tell me the top 3 things to test
Find all sensitive data exposed in responses and group by risk level
```

For a full list of example prompts, see [PROMPTS.md](PROMPTS.md).

---

## 🔍 Sensitive Data Patterns Detected

The server automatically scans for 20+ patterns:

- JWT Tokens, Bearer Tokens, Basic Auth
- AWS Access Keys & Secret Keys
- Google API Keys, GitHub Tokens, Slack Tokens, Stripe Keys, SendGrid Keys
- Passwords in URLs and request bodies
- Database connection strings
- Private keys (RSA, EC)
- Session cookies (PHPSESSID, JSESSIONID, connect.sid)
- SQL errors and stack traces
- Internal IP addresses
- Email addresses, Credit card numbers

---

## 🛡️ Security Headers Checked

`Strict-Transport-Security` · `Content-Security-Policy` · `X-Frame-Options` · `X-Content-Type-Options` · `Referrer-Policy` · `Permissions-Policy` · `Cache-Control` · `Access-Control-Allow-Origin`

---

## 🗂️ Supported File Formats

| Format                   | How to get it                            |
| ------------------------ | ---------------------------------------- |
| Burp XML export (`.xml`) | Proxy → HTTP History → Save items        |
| Gzip-compressed XML      | Project → Save copy (some Burp versions) |

> Raw `.burp` project files are **not supported** — they use a proprietary binary format. Use the XML export instead.

---

## ⚠️ Legal & Ethical Use

This tool is intended for **authorized security testing only**.

- Only analyze traffic from systems you have explicit permission to test
- Unauthorized interception or analysis of network traffic may be illegal
- The authors are not responsible for misuse of this tool
