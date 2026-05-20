# Judging Map

The DEV Gemma 4 Challenge build prompt asks for useful or creative projects where Gemma 4 does real work at the heart of the project. The judging criteria listed on the challenge page are:

- intentional and effective use of the chosen Gemma 4 model
- technical implementation and code quality
- creativity and originality
- usability and user experience

## Intentional Gemma 4 Use

Agent Surface Map uses deterministic scanning for evidence and Gemma 4 for judgment. That separation is intentional:

- code is better at repeatable file inventory and redaction
- Gemma is better at making constrained install-policy judgments over combined risks and turning findings into developer-safe install guidance

Model choice: Gemma 4 31B Dense for final review. The task benefits from reasoning and prioritization more than edge latency.

## Technical Implementation

- Static web UI with Vercel serverless scan endpoint.
- Local CLI scanner.
- Local MCP stdio server for coding-agent workflow.
- Read-only GitHub retrieval with shallow/no-submodule behavior.
- Bounded MCP responses.
- Tests for scanner behavior, MCP protocol flow, redaction, path refusal, public risk rules, and review source labeling.

## Originality

Most scanners focus on dependencies, secrets, or malware. This project focuses on the agent operating surface:

- MCP server config
- browser profile risk
- shell execution risk
- filesystem mount risk
- install scripts
- repo instructions that may steer agents
- cloud/database credential references

The product shape is also agent-native: a web check for humans plus an MCP server that coding agents can call before installing another MCP.

## UX

The app has one primary question: "What install posture should this tool get before it reaches my agent?"

The UI keeps the workflow direct:

- paste a GitHub repo URL
- scan read-only
- install posture, score, risks, and copyable agent constraints
- load common MCP example reviews
- use the MCP server inside a coding agent for real workflow integration

## DNP Boundary

The public app includes generic MCP/agent safety rules only. It does not publish private target lists, bounty workflow details, exploit chains, internal scoring, or private bug classes.
