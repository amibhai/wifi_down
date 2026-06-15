# Security Policy

## Scope

This policy covers vulnerabilities **in the wifi_down tool itself**, not
vulnerabilities discovered *using* the tool. Examples in scope:

- Path traversal via crafted SSID or BSSID values in capture file paths
- Command injection via unsanitized subprocess arguments
- HMAC audit log bypass
- Privilege escalation from the tool's root requirement

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately by emailing the maintainer (see commit history for contact).
Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional)

## Response Timeline

| Stage                   | Target     |
|-------------------------|------------|
| Acknowledgement         | 48 hours   |
| Initial assessment      | 7 days     |
| Fix or workaround       | 30 days    |
| Public disclosure       | After fix  |

## Legal

Security research on wifi_down itself is welcome. Testing of third-party
networks without authorization remains illegal regardless of this policy.
