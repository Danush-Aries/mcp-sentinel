"""mcp-sentinel — a static security linter for the Model Context Protocol trust boundary.

Reads the exact artifacts an AI agent trusts — the `mcpServers` config block and MCP
tool manifests — and flags tool poisoning, dangerous capabilities, exposed secrets, and
supply-chain risk. Offline, free, SARIF-emitting, rule-as-data.
"""
__version__ = "0.1.0"
