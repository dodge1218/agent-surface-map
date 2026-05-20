# Agent Surface Map PRD

## Goal

Help developers decide how to install MCP servers, skills, plugins, and agent tools before those tools reach shell, browser profiles, files, or credentials.

## Primary User

A developer using a coding agent who is about to add a new tool from a GitHub repo or example config.

## User Promise

In under a minute, the user can paste a repo link and get:

- install posture: `add_carefully`, `sandbox_first`, or `do_not_add`
- why the posture was chosen
- parsed MCP server names, commands, args, and env key names
- risk signals from install-facing files
- copyable constraints for the coding agent

## Judging-Critical Requirements

- Gemma 4 must visibly produce the install judgment, not only summarize scanner output.
- The UI must show static scan vs Gemma judgment.
- The demo must include a reliable verified Gemma review path.
- Fallback mode must be visually distinct from Gemma mode.
- Wording must say install-risk review, not safety certification.

## Functional Requirements

- Scan local directories from CLI.
- Scan public GitHub repos through the web API.
- Run as an MCP stdio server for coding-agent workflows.
- Parse MCP configs.
- Detect generic public rules for shell, browser, filesystem, credential, database, cloud, listener, prompt-instruction, and install-script surfaces.
- Generate a machine-readable policy block for agents.
- Provide common MCP example reviews.

## Security Requirements

- No untrusted code execution.
- GitHub zip extraction must reject traversal, absolute paths, symlinks, devices, too many files, and excessive decompressed size.
- Hosted API must not return raw model prompts.
- Local MCP scans default to the server working directory unless `ASM_ALLOWED_ROOTS` explicitly widens access.
- Secret redaction must cover common env assignments, bearer tokens, GitHub tokens, OpenAI-style keys, npm tokens, JWTs, URL credentials, and private key headers.

## Non-Goals

- Full malware analysis.
- Guaranteeing a repo is benign.
- Publishing private security-research workflow.
- Replacing human review for high-trust tool installs.
