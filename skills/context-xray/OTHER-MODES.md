# Other modes

## Setup

Run `python3 <skill-folder>/scripts/context_xray.py --setup`, skip the brief-back, and reply with its stdout exactly.

## No log found

Exit code 3 means this agent has no readable session log, so everything here is unverified. Say that first.

1. Add one heading per part of your context you can perceive: system prompt, tool definitions, instruction files, memory, skills, and each user message with what arrived alongside it.
2. Run `python3 <skill-folder>/scripts/context_xray.py --self-report-only <file>`, which redacts it, saves it and labels it unverified.
3. Reply with its stdout, and state that a model's recall of its own context can be incomplete or wrong.
