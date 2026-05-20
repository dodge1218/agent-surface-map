# Security Notes

Agent Surface Map reviews untrusted MCP/tool repositories. Its own MCP server must stay boring and constrained.

## MCP Server Constraints

- Does not execute repository code.
- `scan_github_tool` only accepts simple public GitHub repository URLs.
- Git clone uses:
  - shallow clone
  - no tags
  - no submodules
  - no file protocol
  - no terminal prompt
  - disabled hooks path
  - isolated temporary `HOME`
- `.git` is removed before scanning.
- `scan_local_tool` refuses filesystem root and obvious credential/profile directories.
- `ASM_ALLOWED_ROOTS` can restrict local scans to explicit parent directories.
- MCP responses are bounded and findings are truncated for large reports.
- Secret-looking values are redacted in evidence excerpts.
- Gemma calls receive only the redacted surface map, not raw repository contents or secret values.
- Gemma failure does not block scanning; reports fall back to deterministic local review.
- MCP config parsing records env key names only, not env values.
- Public API scans are per-IP rate limited with best-effort in-memory demo throttles.
- Public Gemma reviews are separately rate limited and guarded by a best-effort estimated daily budget throttle.

Current public defaults:

- scans: 30 per IP per hour
- Gemma reviews: 6 per IP per hour
- estimated Gemma budget throttle: $10 per UTC day
- estimated cost reservation: $0.02 per attempted Gemma review

The hosted demo uses OpenRouter's free Gemma 4 31B route when available. Provider-side 429s or budget gates fall back to deterministic local review. Hard spend enforcement requires a provider-side capped key or a durable external budget store.

## Public-Safe Rule Layer

The scanner includes generic public rules for common MCP/agent install risks:

- all-interface binds such as `0.0.0.0`
- local HTTP listener hints
- shell/terminal execution surfaces
- filesystem tool surfaces
- broad filesystem mounts
- package install scripts
- Docker socket references
- Kubernetes config references
- cloud credential references
- database connection references
- prompt-override language
- browser profile/session reuse

These rules are intentionally generic. They do not encode private bug classes, target-specific findings, bounty methodology, or exploit chains.

See `docs/rules.md` for the public rule catalog.

## Intended Use

Use this before adding a new MCP server, browser automation tool, coding-agent skill, plugin, or repo instruction pack.

The result should constrain the calling agent:

- do not install globally when posture is `sandbox_first` or `do_not_add`
- do not reuse logged-in browser profiles
- do not pass `.env` values into prompts
- require human approval before shell commands
- start read-only and narrow writable paths

## Non-Goals

- This is not a malware sandbox.
- This is not a full code audit.
- This is not a replacement for reviewing the source manually before high-trust installation.
