# context-xray

See exactly what your coding agent has in its head.

Working with a coding agent is managing. A good manager avoids handing an employee a pile of unrelated, contradictory information, yet most of us have no idea what our agent is holding: which instruction files loaded, what was slipped in beside each message, what got compacted away. `context-xray` shows you.

Run the `context-xray` skill (`/context-xray` in Claude Code, or just ask "what's in your context?") and you get:

- **A first screen that answers the question**: used, available and percent of the window, a keep-going or compact verdict, and a plain breakdown of what the agent is holding.
- **Ranked suggestions**: loaded tools and plugins that were never used, repeated injections, re-read files and oversized outputs, each with the tokens involved.
- **A job check**: what you actually asked beside what the agent says its job is, written before it sees the report.
- **A Q&A timeline**: each message, tokens added, the running total, and the single biggest thing that turn added. Compaction appears as its own event.
- **The full detail**: every section with its evidence label, tools by server, skills by source, a manager's view of repeats and forgotten turns, and a local Markdown report with the verbatim text of everything still in context.

## How it compares to `/context`

Claude Code's `/context` is a good size gauge. It tells you how full the window is. `context-xray` tells you what the agent actually read and how it got there.

| | `/context` | `context-xray` |
|---|---|---|
| Token totals by category | Yes | Yes, and it splits "Messages" into your words, hidden injections, thinking, tool calls and tool results |
| Used, available and % of window | Yes | Yes, overall, per section and per turn |
| Autocompact buffer | Yes | No, the log doesn't record it. It shows when compaction actually fired |
| Tokens per tool and server | Yes | Yes |
| Size of deferred tool schemas | Yes | No, the log has only their names. It does count what listing those names costs |
| Tokens per skill | Yes | Yes |
| The verbatim text of every section | No | Yes |
| What was injected with each message | No | Yes |
| Tokens added by each message, and the biggest cause | No | Yes |
| What compaction dropped | No | Yes |
| Ranked suggestions for what to cut | No | Yes |
| Repeated injections, re-read files, mixed work areas | No | Yes |
| The agent's own account of its job | No | Yes, labeled unverified |
| Past sessions and Codex | No | Yes |

## Why a script instead of asking the agent

An agent asked to recite its context re-types it, which costs tokens, can drift, and cannot show what was compacted away. So the report is built from the session log on disk, and every section is labeled:

| Label | Meaning |
|---|---|
| `request log` | Recorded as part of the API request the agent sent |
| `session log` | Recorded in the session log, not checked against a request |
| `self-reported` | The agent said so. Unverified |
| `not recorded` | The log does not contain it |

Running totals come from the provider's usage numbers in the log, and so do thinking and the agent's own output on recent Claude Code versions. Other sections are estimated from text length. Across 84 real sessions, those estimates accounted for 74% to 100% of the provider's first-request total, with a median of 93%, so treat them as approximate. Whatever they miss gets its own row instead of being spread across the others.

## Support

| Agent | Evidence |
|---|---|
| Claude Code | Rebuilds the last request from the log and matches messages by hash, including system prompt and tool definitions. Request records appear from about v2.1.280 on. Older logs fall back to the transcript, with no system prompt or tool breakdown, so update Claude Code first if the report says "not recorded" |
| Codex | Base instructions, `AGENTS.md`, injected messages, tools, turns and real token counts. Built-in tool schemas are not logged and reasoning is encrypted, and the report marks both |
| Anything else that reads `SKILL.md` | Self-report only, clearly labeled unverified |

These logs are internal formats that can change between versions. The script reports how much it could match rather than guessing.

## Install

Python 3.9+ with no dependencies.

```bash
git clone https://github.com/PieLord757/context-xray.git
cp -r context-xray/skills/context-xray ~/.claude/skills/        # Claude Code
cp -r context-xray/skills/context-xray ~/.codex/skills/         # Codex
```

You can also run it directly on any log:

```bash
python3 skills/context-xray/scripts/context_xray.py --log path/to/session.jsonl
```

## Privacy

Everything runs locally and nothing is sent anywhere. Reports are written to `~/.context-xray/reports/`, readable only by you. Common secret patterns (API keys, tokens, private keys, credentials in URLs, `password=` style assignments) are redacted by default.

Redaction is pattern-based and will miss things. Reports contain your instruction files and tool output, so read one before sharing it. Base64 images are always left out.

## Limits

- The report is a snapshot of the last logged request, so the turn that runs it is not included.
- Window size comes from the Codex log or Claude Code's cached model catalog. It is the listed limit for the model, and `--window` overrides it.
- Running the skill adds its own output to the session's context.
- The verdict is a rule of thumb: compact soon at 60% of the window, compact or start fresh at 85%.
- "Never used" means in this session's main thread, so a tool may still matter elsewhere.
- Subagents have separate contexts and are excluded.
- Thinking text is usually encrypted or omitted from logs. Recent Claude Code versions still record its token count; on older logs the size is a low-confidence estimate.
- Built-in tool definitions read higher here than in `/context` (28.3k vs 17.3k in one test session). The text comes from the recorded request, the reason for the gap is unknown, and it does not change the real total.
- On Codex, text-length estimates often exceed the real total and are scaled down to match, so per-section shares are rougher than on Claude Code.

## Development

```bash
python3 -m unittest discover -s tests
```

## License

MIT
