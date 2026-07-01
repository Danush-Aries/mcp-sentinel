# Distribution — remaining channels + launch checklist

## awesome-mcp list PRs (highest ROI for sustained stars)

Target lists (search GitHub for "awesome mcp" / "awesome model context protocol"):
- `punkpeye/awesome-mcp-servers`
- `modelcontextprotocol/servers` (community/related sections)
- `appcypher/awesome-mcp-servers`
- any "awesome-mcp-security" list (create one if it doesn't exist — that itself gets stars)

**Entry to add** (match the list's format/category — usually a "Security/Tooling" section):

```markdown
- [mcp-sentinel](https://github.com/Danush-Aries/mcp-sentinel) — Static security linter for the MCP trust boundary: flags tool poisoning (incl. invisible-unicode injection), dangerous tool capabilities, leaked secrets, and supply-chain risk in `mcpServers` configs and manifests. Offline, SARIF output.
```

**PR title:** `Add mcp-sentinel (security linter for MCP configs)`
**PR body:** one honest paragraph — what it does, why it belongs in the list, that it's MIT/offline. Don't overclaim. Maintainers merge tools that are real and documented.

## Reddit

- **r/LocalLLaMA** and **r/mcp** — best fit. Post the *threat* framing, link second.
  - Title: `MCP tool descriptions are injected into your model's context — I built a linter that scans them for poisoning/secrets`
- **r/netsec** — only if you frame it as security research; they're allergic to self-promo. Lead with the invisible-unicode-in-tool-description technique, tool as the artifact.
- Follow subreddit self-promo rules (many require a ratio of non-promo participation). Comment genuinely for a week first.

## Other

- **PyPI publish** (do this — `pipx install` in every post assumes it): `python -m build && twine upload dist/*`. Reserve the name early.
- **Hacker News** — see SHOW_HN.md.
- **LinkedIn** — short post for the professional/recruiter audience (ties to your job hunt): the threat + the repo. This one is more about *your* visibility than stars.
- **MCP Discord / community channels** — share in the relevant #tools or #security channel, conversationally.

## Launch sequence (don't fire everything at once)

| Day | Action |
|---|---|
| 0 | Publish to PyPI. Add a demo GIF to the README (record `mcp-sentinel scan poisoned.json`). Tag `v0.1.0` GitHub Release. |
| 1 | Post the X thread (screenshot attached). Reply to everyone. |
| 2 | Show HN (Tue–Thu am ET). Add body as first comment. Reply for 2h. |
| 3 | dev.to article (set `published: true`, add cover image). Cross-link from the X thread. |
| 4–7 | awesome-mcp PRs (2–4 lists). Reddit r/mcp + r/LocalLLaMA. |
| ongoing | Answer every issue fast. Ship a v0.1.1 with a requested rule — "actively maintained" converts stars. |

## Honest expectations

- A timely, well-executed tool + this sequence realistically lands **tens to low-hundreds** of stars; a HN/Reddit hit can spike it higher. "Thousands" needs a genuine viral moment — possible here because MCP-security is hot, but don't bank on it.
- The single biggest multiplier is the **demo GIF** in the README and the **screenshot** on tweet 1. Record them before launching.
- Stars follow *use*. The fastest way to sustained stars is a second person finding a real poisoned/secret config with it and saying so publicly. Make it trivially easy to run (PyPI + one command).

## Assets in this folder
- `SHOW_HN.md` — HN title + body + mechanics
- `X_THREAD.md` — 6-tweet thread
- `DEVTO_ARTICLE.md` — full article (set published:true)
- this file — channels + sequence
