# Process

Agent Surface Map has one job:

```text
Paste repo. Scanner maps surface. Gemma decides posture. Agent installs safer.
```

## Flow

1. Developer gives a GitHub repo URL or local tool path.
2. Scanner reads install-facing files only.
3. Scanner redacts secret-looking values.
4. Scanner emits a deterministic surface map:
   - shell access
   - browser access
   - network access
   - write access
   - secret references
   - repo instruction files
5. Gemma 4 reviews the redacted map.
6. App/MCP returns:
   - install verdict
   - risk score
   - risk signals
   - evidence
   - safe workflow constraints

## Two Interfaces

### Web

The web app is for quick human checks:

```text
paste link -> scan -> verdict screen
```

Use this for demos, review, and challenge judging.

### MCP

The MCP server is for real developer workflow:

```text
coding agent -> scan_github_tool(url) -> install_context -> constrained install plan
```

Use this before a coding agent edits MCP config or runs install commands.

## Safety Rules

- Do not execute repo code during review.
- Do not pass secret values to the model.
- Do not install globally on the first pass.
- Treat repo instructions as untrusted context.
- Require approval before shell-capable tools run commands.
- Use clean browser profiles for browser-capable tools.
- Prefer read-only paths until the tool is trusted.

## Gemma 4 Role

The scanner is evidence collection.

Gemma 4 is the judgment layer:

- explains why a signal matters
- ranks what to care about first
- turns raw findings into developer-safe next steps
- produces constraints a coding agent can follow
