# context-xray

A check-in for someone managing a coding agent: it shows what the agent has in front of it and what it believes its job is, so the manager can decide what to do next.

## Language

**Manager**:
The person directing a coding agent day to day and reading its check-in.
_Avoid_: User (when the role matters), operator

**Check-in**:
A pause during a live session to see what the agent knows before handing it more work. A post-mortem is the same check run after something went wrong.
_Avoid_: Audit, scan

**Context**:
The text loaded into the agent's session. It can be measured and verified from the session log. Readers see this called the agent's memory.
_Avoid_: What's in its head

**Understanding**:
What the agent believes its job, rules and constraints are. It can only be self-reported.
_Avoid_: Context, knowledge

**Brief-back**:
The agent's own statement of its job, next step, assumptions and conflicts, written before it sees any evidence.
_Avoid_: Self-report (for this specific artifact), recap

**Knowledge map**:
A list, by subject rather than size, of what the agent has been told, has seen, has changed, and has lost.
_Avoid_: Context map, token breakdown

**Told**:
The manager's requests and the instruction sources loaded into the session.

**Seen**:
The files, command output and pages the agent has read.

**Changed**:
What the agent has altered during the session.
_Avoid_: Decided

**Lost**:
Turns that now survive only as a compaction summary.
_Avoid_: Forgotten

**Saved notes**:
Notes the agent keeps for itself across chats and loads automatically.
_Avoid_: Memory file

**Next move**:
The decision a check-in supports: continue, correct, or reset. The check-in recommends one, and the manager decides.
_Avoid_: Verdict, action

**Continue**:
Give the agent its next task.

**Correct**:
Tell the agent something it has wrong or is missing.

**Reset**:
Compact the session or start a fresh one.
_Avoid_: Clear

**Setup audit**:
An occasional review of what installed tools, servers and plugins cost. It is separate from a check-in.
_Avoid_: Check-in
