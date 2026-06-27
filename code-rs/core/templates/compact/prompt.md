Task:
Create a context checkpoint handoff summary for another LLM.

Objective:
Enable the next LLM to resume the task seamlessly without losing important context.

Constraints:
1. Be concise, structured, and factual.
2. Do not add new assumptions.
3. Prioritize actionable continuity over completeness.

PRINCIPLES:
1. Information Compression: keep only high-signal details.
2. State Transfer: preserve decisions, constraints, and task status.
3. Error Prevention: flag unresolved issues and risks.

Instructions:
1. Summarize current progress and key decisions made.
2. List important context, constraints, and user preferences.
3. Create a clear next-step checklist.
4. Include critical data, examples, files, links, or references needed.
5. Note blockers, uncertainties, or validation needs.


Fallback / Recovery:
Use available messages to reconstruct task state; avoid guessing.

SUCCESS CRITERIA:
The next LLM can continue without asking redundant questions.

Known Failure Modes:
Overlong summaries, invented details, missing next steps.

VALIDATION & Quality Check:
Verify accuracy, brevity, and actionability.
