# Source Idea Notes

These are sanitized notes from the local OpenClaw workspace review. Do not copy private CyberClaw/OpenClaw operational details into the public submission.

## Contest Requirements Observed

Source: DEV Gemma 4 Challenge page.

- Build category: five winners at $500 each.
- Writing category: five winners at $100 each.
- Deadline: May 24, 2026 at 11:59 PM PDT.
- Build submission asks for: what was built, demo, code, and how Gemma 4 was used.
- Gemma 4 model variants named by the submission template: E2B, E4B, and 31B Dense.

## Local Ideas Reviewed

### `research/frontier-builder-study.md`

Useful idea: agents that make money are not demos; they remove operational friction for builders and businesses.

Why not the contest entry: the strongest ideas there are commerce and SMB revenue plays. They are useful, but they would look like generic agent SaaS unless built deeply.

### `research/commerce-agent-ideas.md`

Useful idea: quote-to-checkout, store-in-a-box, and approved catalogs are strong business systems.

Why not the contest entry: a commerce agent would require external integrations, a believable deployment, and customer workflow polish. Good product direction, worse one-week contest risk.

### CyberClaw PRDs and notes

Useful idea: local agents now have an operating surface: shell, browser, MCP, memory, skills, writable paths, repo instructions, network access, and provider spend.

Why it wins: it is specific, timely, developer-native, and a natural Gemma 4 use case. Deterministic code can scan the machine, while Gemma 4 explains risk and priorities.

## Chosen Entry

Agent Surface Map.

Pitch:

```text
Before you hand a coding agent more tools, know what you have already handed it.
```

Why this has contest energy:

- Novel but immediately understandable.
- Works locally with a demo repo.
- Clear reason for Gemma 4: judgment and prioritization over a redacted technical inventory.
- Builds from real local pain without publishing private details.
- Can be expanded after the contest into a stronger OpenClaw/CyberClaw-adjacent product.

## What To Build Next

- Add a drag-and-drop upload path for `sample-report.json`.
- Add a one-command `--serve` mode.
- Add MCP-specific parsing instead of regex-only detection.
- Add before/after remediation diff mode.
- Capture a 60-90 second demo video.

