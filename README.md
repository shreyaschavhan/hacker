## Hacker fork

This repository is Shreyas Chavhan's personalized `hacker` fork of Every Code (`https://github.com/just-every/code`). 

Local builds can be exposed as:

```bash
hacker
```

or through any existing `coder` shim that points at the rebuilt `code-rs/target/release/code` binary.

Personal fork additions:

- **ProcessProbe review** - selectively launches a read-only process review agent for high-risk final conclusions, failed-tool-followed-by-confidence cases, security closure claims, and manual phrases such as `force probe`, `probe this`, or `review my reasoning`.
- **Not security-only** - ProcessProbe has general, security, and debugging profiles, so it can review unsupported confidence in ordinary coding, research, debugging, and report-writing tasks too.
- **Cheap trigger gate first** - the probe is not run on every turn. It uses the final answer plus process signals such as tool failures, validation signals, file changes, and agent events before escalating to a full review.
- **Post-turn correction loop** - when ProcessProbe says resolution is required, the TUI injects a follow-up developer instruction so the main assistant must resolve or downgrade the prior conclusion before treating it as stable.
- **Epistemic status tagging** - normal assistant responses tag substantive claims as `[OBSERVED]`, `[MEMORY]`, `[INFERRED - <confidence>, uncertainty: <reason>]`, or `[ASSUMED]` so direct evidence is separated from recall, reasoning, and working premises.
- **Working-state visibility** - the responding/thinking/tool-use status now includes elapsed time and escalates to "Still working" messaging on long runs.
- **Compact checkpoint prompt** - the default compaction prompt now asks for a concise, factual handoff with decisions, constraints, next steps, blockers, and validation needs.

ProcessProbe is configured in `~/.code/config.toml`:

```toml
[probe_review]
enabled = true
mode = "high_risk"              # high_risk | manual | always
default_profile = "general"     # general | security | debugging
cheap_gate = true
full_probe_threshold = "high"   # low | medium | high
auto_resolve = true
use_chat_model = false
model = ""                      # empty: auto-review/review/chat fallback
model_reasoning_effort = "high"
```

&ensp;
