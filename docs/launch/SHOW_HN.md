# Show HN post

## Title (pick one — HN title rules: no hype, ≤80 chars)

**Primary:**
> Show HN: mcp-sentinel – Static security linter for MCP servers (catches tool poisoning)

**Alternates:**
> Show HN: Lint your MCP config for tool poisoning, leaked secrets, risky tools
> Show HN: mcp-sentinel – Scan MCP servers before your AI agent trusts them

## URL
https://github.com/Danush-Aries/mcp-sentinel

## Body (first comment — post immediately after submitting)

I kept adding MCP servers to Claude/Cursor and realized I had no idea what I was actually trusting. An MCP server's tool *descriptions* get injected verbatim into the model's context, and its tools routinely wrap `exec`, the filesystem, and the network. So a malicious or sloppy server is a real attack surface — and none of my existing scanners (gitleaks, semgrep, npm audit) understand an `mcpServers` block at all.

mcp-sentinel is a static linter for exactly that. You point it at a `settings.json` or an MCP manifest and it flags:

- **Tool poisoning** — instruction-override phrases, and (the one I care most about) **invisible/bidi unicode smuggled into a tool description** — an injection channel you can't see reading the JSON.
- **Dangerous capabilities** — shell/exec tools, arbitrary file write/delete, unbounded egress, direct credential access.
- **Exposed secrets** in `env` blocks (provider keys + high-entropy generic), evidence masked by default.
- **Supply-chain risk** — unpinned `npx`/`uvx`, `@latest`, `http://` sources, unknown publishers.
- **Scope creep** — a "read-only" server that ships an exec tool.

17 rules, rule-as-data, offline (no key, no network), and it emits **SARIF** so it drops into GitHub code-scanning. Exit codes are CI-friendly (0 clean / 1 findings / 2 critical / 3 error).

```
pipx install mcp-sentinel
mcp-sentinel scan ~/.claude/settings.json
```

It's v0.1.0 and deliberately small. I'd love feedback on: (1) rules you'd want added, (2) real MCP config shapes across clients (Cursor/VS Code/Zed) I should normalize, (3) whether the false-positive rate on the heuristic rules is acceptable in your setup. Repo has the full rule catalog and a `rules` subcommand that prints exactly what it checks.

## Timing / mechanics (honest)
- Post **Tue–Thu, ~8–10am ET** (HN peak). Avoid weekends.
- Submit, then IMMEDIATELY add the body as the first comment.
- Do NOT ask friends to upvote (HN penalizes voting rings — it can bury you). Just reply thoughtfully to every comment for the first 2 hours; engagement is what ranks you.
- If it doesn't catch the first time, you can resubmit once after a couple weeks with a real changelog.
