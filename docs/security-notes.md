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

## Intended Use

Use this before adding a new MCP server, browser automation tool, coding-agent skill, plugin, or repo instruction pack.

The result should constrain the calling agent:

- do not install globally when verdict is `sandbox_first` or `do_not_add`
- do not reuse logged-in browser profiles
- do not pass `.env` values into prompts
- require human approval before shell commands
- start read-only and narrow writable paths

## Non-Goals

- This is not a malware sandbox.
- This is not a full code audit.
- This is not a replacement for reviewing the source manually before high-trust installation.

