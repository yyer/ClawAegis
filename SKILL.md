---
name: clawaegisex
description: Minimal safety guard plugin for OpenClaw prompt, tool, and tool-result flows. Provides configurable defenses for high-risk commands, sensitive-path protection, memory integrity, and outbound access control.
---

# Claw Aegis Ex — Safety Guard

Claw Aegis Ex is a defense plugin that inspects OpenClaw prompt, tool-call, and
tool-result flows and blocks or observes high-risk activity. Behavior is driven
entirely by `user_config.json`, which the SecPlane control plane (ClawManager)
compiles and dispatches.

## Defenses

### Command blocking
Block clear high-risk shell patterns such as `rm -rf /` and `curl | sh`.

### Sensitive-path protection
Block reads, writes, deletes, and searches that target protected paths,
important skills, or attempts to delete files outside the current workspace.

### Memory guard
Reject suspicious or oversized writes to `memory_store`, `MEMORY.md`,
`SOUL.md`, and `memory/`.

### Outbound access control
Restrict network egress to a trusted allowlist dispatched by the control plane.

## Configuration

All defenses are toggled via `user_config.json` at the skill root. Each
defense supports `enforce` (block), `observe` (log only), and `off` modes.
The patched loader merges `user_config.json` on top of the plugin defaults at
startup.
