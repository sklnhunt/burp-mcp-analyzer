# 💬 Prompts

A reference of prompts to use with the Burp MCP Analyzer after loading your XML export.

**Always start with:**
```
Load this file: /path/to/your/export.xml
```

---

## 🗺️ Map the Target First

```
Show me all unique endpoints and paths discovered
```

```
What technologies is this app running on?
```

```
Give me a full statistical breakdown of the traffic
```

```
List all hosts and domains in this traffic
```

---

## 🔍 Find Vulnerabilities

```
Scan everything for secrets, API keys, tokens and passwords
```

```
Check all responses for missing or misconfigured security headers
```

```
Find all injection points — every GET param and POST body field
```

```
Look for SQL errors or stack traces being exposed in responses
```

```
Are there any CORS misconfigurations with credentials?
```

```
Find any admin, debug, or backup paths that were accessed
```

```
Show me all file upload endpoints and what was accepted
```

---

## 🎯 Dig Into Traffic

```
Show me all POST requests that returned 200
```

```
Find all 500 errors with the full response body
```

```
Search for "Authorization" in all requests
```

```
Find every request with no Authorization header — potential unauth access
```

```
Show me all JWT tokens found and decode them
```

```
List all cookies being set and check for missing security flags
```

```
Find all requests where the response contains "error" or "exception"
```

---

## 🔐 Auth & Session Testing

```
Show me all login and authentication endpoints
```

```
Find all password reset flows in the traffic
```

```
Are the same session tokens being reused across requests?
```

```
Find any requests where credentials appear in the URL
```

---

## 📋 Reporting & Export

```
Generate a full penetration test report with all findings
```

```
List all scanner vulnerabilities sorted by severity with remediation steps
```

```
Convert the 5 most interesting requests to curl commands
```

```
Give me a summary I can paste into a bug report
```

---

## 🔗 Best Chained Prompts

```
Load the file, map all endpoints, find injection points, then tell me the top 3 things to test
```

```
Find all sensitive data exposed in responses and group by risk level
```

```
Show me all POST requests, check which ones have no auth, export them as curl commands
```

```
Analyze the login flow — find the request, check for rate limiting, look for weak session handling
```

```
Give me everything: endpoints, parameters, sensitive data, security headers, and a final risk summary
```