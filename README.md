# context-xray

See exactly what your coding agent has in its head.

Working with a coding agent is managing. A good manager avoids handing an employee a pile of unrelated, contradictory information, yet most of us have no idea what our agent is holding. `context-xray` is a check-in: before you hand your agent its next task, it shows what the agent knows and whether it has the right picture of the job.

Run `/context-xray` and you get one easy screen. This example is illustrative:

> **Context X-ray**
>
> `███░░░░░░░░░░░░░░░░░░░░░` **The agent's memory is 10.6% full** (106,361 of 1,000,000 tokens)
>
> **Tell it one thing before it continues.** It thinks the tests should stay unchanged. If that's wrong, say so now.
>
> **What it thinks it's doing**
> - **You asked:** Fix the login bug
> - **It thinks its job is:** Fix session expiry in `auth.py`
> - **It plans to:** Add a refresh check, then run the auth tests
>
> **What it knows**
> - **You told it:** 3 messages
> - **Instructions it loaded:** your `CLAUDE.md`, plus notes saved from earlier chats
> - **It has read:** `auth.py`, `session.py`, 4 command results, 1 web page
> - **It has changed:** `auth.py`
> - **It has forgotten:** nothing
>
> **Why it's that full:** Almost all of it (97%) is built-in instructions and tools that load before you type anything. Only 3% is from this chat.
>
> Ask me to show anything it read, or open the full report.

The agent says back its job, plan and assumptions before it sees any evidence, so you can catch a wrong plan before work happens.

- **Ask for anything in plain words**, such as "show me what it read from `auth.py`". You get that item's exact text and nothing else.
- **Run `/context-xray setup`** to see which installed tools and plugins are taking up room without being used.
- **Open the local report** for every item's exact text, plus token tables, tools by server and a turn-by-turn timeline.

A check-in is built to stay small, because reporting on context shouldn't fill it up.

## How it compares to `/context`

Claude Code's `/context` is a good size gauge. It tells you how full the window is. `context-xray` tells you what the agent actually read and how it got there.

| | `/context` | `context-xray` |
|---|---|---|
| Token totals by category | Yes | Yes, and it splits "Messages" into your words, hidden injections, thinking, tool calls and tool results |
| Used, available and % of window | Yes | Yes, overall, per section and per turn |
| Autocompact buffer | Yes | No, the log doesn't record it. It shows when compaction actually fired |
| Tokens per tool and server | Yes | Yes, in the report and `setup` |
| Size of deferred tool schemas | Yes | No, the log has only their names. It does count what listing those names costs |
| Tokens per skill | Yes | Yes, in the report |
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
- The recommendation is a rule of thumb: start a new chat soon at 60% full, start fresh or compact at 85%, and check anything the agent says it is guessing.
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
