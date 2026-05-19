# Public Rule Catalog

Agent Surface Map is a pre-install review tool. These checks focus on files that commonly describe what an agent tool can do before a developer installs it.

| Signal | What it means | Safer workflow |
| --- | --- | --- |
| MCP config | `mcp.json` or `.mcp.json` declares servers, commands, args, or env keys. | Review each server before editing local agent config. |
| Shell/process | Commands mention shells, subprocesses, terminals, or process execution. | Require human approval, timeouts, allowlists, and a narrow working directory. |
| Browser/session | Browser automation or profile/cookie state appears. | Use a clean profile; do not reuse personal logged-in sessions. |
| Network/listener | Fetch, HTTP clients, local listeners, or all-interface binds appear. | Prefer localhost, auth, documented ports, and outbound allowlists. |
| Filesystem | Filesystem MCPs or broad paths such as home/root/system paths appear. | Mount only the project directory and start read-only. |
| Install scripts | Package scripts can run during dependency setup. | Review scripts before install; avoid running untrusted setup code. |
| Cloud/database credentials | Env key names refer to cloud, repo, or database credentials. | Pass scoped credentials by reference only; never expose values to model context. |
| Container/cluster control | Docker socket or Kubernetes config references appear. | Treat as host or cluster control; keep out of untrusted agent tools. |
| Prompt override text | Repo text tries to override system/developer instructions. | Treat as untrusted data until reviewed by a human. |

The public rule catalog is intentionally generic. It does not publish private bug classes, target-specific research, exploit chains, or bounty workflow details.
