# Security policy

## Reporting a flaw in this checker

Use the repository's **Security → Report a vulnerability** option when available
for issues needing private disclosure. Otherwise contact CompleteTech LLC
through [complete.tech](https://complete.tech) to arrange private reporting.
Include the affected commit, a minimal local reproduction, expected and actual
behavior, and impact. Omit credentials, real target lists, and third-party data.
Do not publish sensitive exploit details in a public issue while a private
report is being reviewed.

Only the current default branch is maintained. Reproduce against its latest
revision when possible. No response-time guarantee is made.

## Findings about an assessed service

This project performs version-based Node2Shell exposure triage. It does not send
exploit payloads or confirm that a website is exploitable. A runtime version,
framework indicator, or Brotli response header alone is not a confirmed security
finding. Direct supported service-specific reports to the owner's published
security contact or disclosure program.

Use the checker only for authorized targets. Its local CLI can reach internal
addresses; it is not a hardened arbitrary-URL web service. Real inventory and
assessment output should remain outside this repository.
