# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Shuttle, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: **enwaiax@users.noreply.github.com**

Include:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if any)

You will receive a response within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.2.x   | Yes       |
| < 0.2   | No        |

## Security Considerations

Shuttle handles SSH credentials and executes remote commands. Key security features:

- **Credential encryption:** All SSH passwords and private keys are encrypted at rest using Fernet (AES-128-CBC)
- **Command security:** Regex rules are `block` or `allow` only. Unmatched commands are scored by a fail-closed LLM gate; the uncertain band parks a Hold for an operator. There is no confirm-token or approval-id protocol.
- **API token authentication:** Web panel requires a bearer token
- **No credential logging:** Passwords and keys are never written to logs or command history
