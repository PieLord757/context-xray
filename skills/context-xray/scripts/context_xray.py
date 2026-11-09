#!/usr/bin/env python3
"""context-xray: show what is in a coding agent's context, from its session log.

Standard library only. Runs locally and makes no network calls.
"""
import argparse
import collections
import datetime as dt
import glob
import hashlib
import json
import os
import re
import sys

# Fitted against provider usage on 62 real first requests (2.6-3.1 chars per token).
# Section sizes are still scaled to the real total when the log has one.
CHARS_PER_TOKEN = 3.0
IMAGE_TOKENS = 1700  # Fitted the same way; the log has no image dimensions.
THINKING_SIG_CHARS_PER_TOKEN = 14.0  # Low confidence: thinking text is encrypted or omitted.

EV_REQUEST = "request log"
EV_SESSION = "session log"
EV_SELF = "self-reported"
EV_NONE = "not recorded"

BEFORE = "before"
CONVO = "convo"

NOT_IN_LOG = "Not in the log"
UNATTRIBUTED = "Unattributed"
STANDING_GAP = "Standing context not visible as text"
GAP_SECTIONS = (NOT_IN_LOG, UNATTRIBUTED, STANDING_GAP)

SECTION_ORDER = [
    "System prompt", "Built-in tools", "MCP tools", "CLAUDE.md / AGENTS.md", "Memory",
    "Skills available", "MCP server instructions", "Subagents available",
    "Deferred tool list", "Output style", "Harness instructions",
    "Environment and session info", STANDING_GAP, NOT_IN_LOG,
    "Your messages", "Compaction summary", "Hidden injections", "Skills loaded",
    "Files attached", "Assistant text", "Thinking", "Tool calls", "Tool results", UNATTRIBUTED,
]

# ---------------------------------------------------------------- redaction

SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S)),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{16,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}")),
    ("stripe-key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}")),
    ("slack-token", re.compile(r"\bxox[abeoprs]-[A-Za-z0-9\-]{10,}")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[A-Za-z0-9_\-]{30,}")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{30,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
    ("bearer-token", re.compile(r"(?i)(\bbearer\s+)[A-Za-z0-9._~+/\-]{16,}=*")),
    ("url-credentials", re.compile(r"(\b[a-z][a-z0-9+.\-]*://[^\s/:@'\"]+:)[^\s/@'\"]+(@)")),
    ("secret-assignment", re.compile(
        r"(?i)((?:[\w.\-]*(?:password|passwd|pwd|secret|api[_\-]?key|access[_\-]?key|auth[_\-]?token|access[_\-]?token|private[_\-]?key|client[_\-]?secret)[\w.\-]*)"
        r"[\"']?\s*[:=]\s*[\"']?)([^\s\"'`,;&|)}\]]{6,})")),
]


def redact(text):
    """Return (redacted_text, Counter of redactions by kind)."""
    counts = collections.Counter()
    for kind, pattern in SECRET_PATTERNS:
        def sub(match):
            value = match.group(0)
            if "[REDACTED:" in value:
                return value
            counts[kind] += 1
            if kind in ("bearer-token",):
                return match.group(1) + "[REDACTED:%s]" % kind
            if kind == "url-credentials":
                return match.group(1) + "[REDACTED:%s]" % kind + match.group(2)
            if kind == "secret-assignment":
                return match.group(1) + "[REDACTED:%s]" % kind
            return "[REDACTED:%s]" % kind
        text = pattern.sub(sub, text)
    return text, counts


# ------------------------------------------------------------------ helpers

def read_jsonl(path):
    rows = []
    with open(path, errors="replace") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


def wire_hash(message):
    canonical = json.dumps(message, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8", "surrogatepass")).hexdigest()


def estimate(text):
    return int(len(text) / CHARS_PER_TOKEN)


def one_line(text, limit=110):
    text = re.sub(r"\s+", " ", text or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def cell(text):
    return (text or "").replace("|", "\\|")


def fmt(number):
    return "{:,}".format(int(number)) if number is not None else "n/a"


def as_blocks(content):
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    return [b for b in content or [] if isinstance(b, dict)]


def block_text(block):
    kind = block.get("type")
    if kind == "text" or kind in ("input_text", "output_text"):
        return block.get("text") or ""
    if kind == "tool_use" or kind == "server_tool_use":
        return json.dumps(block.get("input"), ensure_ascii=False, indent=1)
    if kind in ("tool_result", "advisor_tool_result", "web_search_tool_result"):
        return tool_result_text(block)[0]
    return ""


def tool_result_text(block):
    """Return (text, image_count) for a tool result block."""
    content = block.get("content")
    if isinstance(content, str):
        return content, 0
    if isinstance(content, dict):
        return json.dumps(content, ensure_ascii=False), 0
    parts, images = [], 0
    for item in content or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "text":
            parts.append(item.get("text") or "")
        elif item.get("type") == "image":
            images += 1
            parts.append("[image omitted]")
        else:
            parts.append("[%s]" % item.get("type"))
    return "\n".join(parts), images


class Session(object):
    def __init__(self, agent, path):
        self.agent = agent
        self.path = path
        self.session_id = os.path.splitext(os.path.basename(path))[0]
        self.version = self.model = self.cwd = None
        self.blocks = []
        self.turns = []
        self.events = []  # turns and compactions, in order
        self.real_total = None
        self.window = None
        self.scale = None
        self.partial = False
        self.window_source = None  # "log", "catalog", "inferred" or "flag"
        self.live = True  # False when reading a past session through --log
        self.standing_gap = 0
        self.first_total = None
        self.skills = collections.OrderedDict()  # name -> estimated tokens
        self.deferred = collections.OrderedDict()  # tool name -> True
        self.unavailable_servers = []
        self.notes = []
        self.coverage = None  # (matched, total) messages against the request log
        self.signals = {}

    def add(self, section, label, text, evidence, group=BEFORE, tokens=None, role=None, detail=None):
        self.blocks.append({
            "detail": detail,
            "section": section, "label": label, "text": text, "evidence": evidence,
            "group": group, "est": estimate(text) if tokens is None else tokens,
            "tokens": None, "role": role, "basis": "estimate",
        })

    def apply_output_usage(self, output_tokens, thinking_tokens):
        """Replace estimates for the assistant's own output with the provider's counts."""
        if not thinking_tokens:
            return
        thinking = [b for b in self.blocks if b["section"] == "Thinking"]
        for block in thinking:
            block["est"] = float(thinking_tokens) / len(thinking)
            block["basis"] = "usage"
        visible = [b for b in self.blocks if b["section"] in ("Tool calls", "Assistant text")]
        estimated = sum(b["est"] for b in visible)
        target = output_tokens - thinking_tokens
        if estimated and target > 0:
            for block in visible:
                block["est"] = block["est"] * float(target) / estimated
                block["basis"] = "usage"

    def finalize(self):
        """Keep measured and estimated sizes as they are; show any gap instead of hiding it."""
        total = sum(b["est"] for b in self.blocks)
        self.partial = any(b["evidence"] == EV_NONE for b in self.blocks)
        if self.real_total and self.real_total >= total:
            gap = self.real_total - total
            if self.partial:
                self.add(NOT_IN_LOG, "Real total minus everything the log shows", "(tokens the provider counted that the log has no text for)", EV_NONE, BEFORE, tokens=gap)
            else:
                standing = min(gap, self.standing_gap)
                if standing:
                    self.add(STANDING_GAP, "First-request total minus its text", "(tokens the provider counted on the first request beyond what its text accounts for: formatting the log does not show, plus estimation error)", EV_NONE, BEFORE, tokens=standing)
                if gap - standing:
                    self.add(UNATTRIBUTED, "Real total minus everything measured", "(messages the log could not recover, plus estimation error)", EV_NONE, CONVO, tokens=gap - standing)
        elif self.real_total and total:
            self.scale = float(self.real_total) / total
        for block in self.blocks:
            block["tokens"] = int(round(block["est"] * (self.scale or 1.0)))


def new_turn(number, prompt, kind, timestamp=None):
    return {
        "event": "turn", "n": number, "prompt": prompt, "kind": kind, "ts": timestamp,
        "hidden": [], "steps": [], "answer": [], "thinking": 0,
        "tokens_end": None, "tokens_added": None, "in_context": True, "thinking_by_id": {},
    }


def apply_running_totals(session):
    previous = session.first_total
    for event in session.events:
        if event["event"] == "compaction":
            previous = event.get("post")
            continue
        if event["tokens_end"] is not None:
            if previous is not None:
                event["tokens_added"] = event["tokens_end"] - previous
            previous = event["tokens_end"]


# -------------------------------------------------------------- Claude Code

ATTACHMENT_SECTIONS = {
    "skill_listing": ("Skills available", "Skill listing"),
    "mcp_instructions_delta": ("MCP server instructions", "MCP instructions"),
    "deferred_tools_delta": ("Deferred tool list", "Deferred tool names"),
    "deferred_tools_record": ("Deferred tool list", "Deferred tool names"),
    "agent_listing_delta": ("Subagents available", "Subagent listing"),
    "output_style": ("Output style", "Output style"),
    "output_style_instructions": ("Output style", "Output style instructions"),
    "environment": ("Environment and session info", "Environment"),
    "model": ("Environment and session info", "Model identity"),
    "date": ("Environment and session info", "Date"),
    "session_context": ("Environment and session info", "Session context"),
    "credential_org": ("Environment and session info", "Credential org"),
    "remote_session_change": ("Environment and session info", "Remote session"),
    "auto_mode": ("Environment and session info", "Auto mode"),
    "advisor_tool": ("Environment and session info", "Advisor tool"),
    "invoked_skills": ("Skills loaded", "Skill body"),
    "skill_mention": ("Skills loaded", "Skill mention"),
    "file": ("Files attached", "File attachment"),
    "at_mention_reference": ("Files attached", "@ mention"),
    "compact_file_reference": ("Files attached", "File reference after compaction"),
    "edited_text_file": ("Files attached", "File changed outside the agent"),
}
STATIC_GROUP_SECTIONS = {
    "CLAUDE.md / AGENTS.md", "Memory", "Skills available", "MCP server instructions",
    "Subagents available", "Deferred tool list", "Output style", "Harness instructions",
    "Environment and session info",
}
INSTRUCTION_NAMES = {"User": "user", "Project": "project", "Local": "local", "Managed": "managed"}


def tool_summary(name, tool_input):
    if isinstance(tool_input, str):
        return one_line(tool_input, 90)
    if not isinstance(tool_input, dict):
        return ""
    for key in ("file_path", "path", "description", "pattern", "query", "command", "url", "prompt", "cmd"):
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return one_line(value, 90)
    for value in tool_input.values():
        if isinstance(value, str) and value:
            return one_line(value, 90)
    return ""


def find_int(value, key):
    if isinstance(value, dict):
        if isinstance(value.get(key), int):
            return value[key]
        value = list(value.values())
    if isinstance(value, list):
        for item in value:
            found = find_int(item, key)
            if found:
                return found
    return None


def catalog_window(model):
    """Look up a model's input limit in Claude Code's cached model catalog."""
    if not model:
        return None
    wanted = model.split("[", 1)[0]
    files = glob.glob(os.path.join(claude_home(), "cache", "model-catalog", "*.json"))
    for path in sorted(files, key=os.path.getmtime, reverse=True):
        try:
            with open(path, errors="replace") as handle:
                data = json.load(handle)
            models = data["catalog"]["config"]["models"]
        except (ValueError, KeyError, TypeError, OSError):
            continue
        for entry in models:
            if isinstance(entry, dict) and entry.get("id") == wanted:
                found = find_int(entry, "max_input_tokens")
                if found:
                    return found
    return None


def tool_section(name):
    return "MCP tools" if name.startswith("mcp__") else "Built-in tools"


def tool_server(name):
    if name.startswith("mcp__") and "__" in name[5:]:
        return name[5:].split("__", 1)
    return "built-in", name


def active_path(rows):
    """Follow parent links from the newest main-thread entry; file order if links break."""
    main = [r for r in rows if r.get("uuid") and not r.get("isSidechain")]
    if not main:
        return [], False
    index = {r["uuid"]: r for r in rows if r.get("uuid")}
    path, seen, broken = [], set(), False
    current = main[-1]
    while current is not None and current["uuid"] not in seen:
        seen.add(current["uuid"])
        path.append(current)
        parent = current.get("parentUuid") or current.get("logicalParentUuid")
        if parent and parent not in index:
            broken = True
        current = index.get(parent) if parent else None
    if broken:
        return main, True
    path.reverse()
    return path, False


def is_tool_result_line(row):
    content = row.get("message", {}).get("content")
    return isinstance(content, list) and any(
        isinstance(b, dict) and b.get("type") in ("tool_result", "advisor_tool_result") for b in content)


EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
PATCH_FILE = re.compile(r"\*\*\* (?:Update|Add|Delete) File: ([^\n\"\\]+)")
LOCAL_COMMAND_TAGS = ("<command-name>", "<local-command-", "<command-message>")


def starts_with_command(text):
    return (text or "").lstrip().startswith(LOCAL_COMMAND_TAGS)


def command_prompt(text):
    """Show a slash command the way the user typed it."""
    name = re.search(r"<command-name>\s*(.*?)\s*</command-name>", text, re.S)
    args = re.search(r"<command-args>\s*(.*?)\s*</command-args>", text, re.S)
    if not name:
        return text
    return ("%s %s" % (name.group(1), args.group(1) if args else "")).strip()


def local_command_rows(path_rows):
    """Slash commands answered by the app itself never reach the agent as a request."""
    local = set()
    for index, row in enumerate(path_rows):
        if row.get("type") != "user" or not isinstance(row.get("message"), dict) or is_tool_result_line(row):
            continue
        text = prompt_of(row)
        if not starts_with_command(text):
            continue
        following = path_rows[index + 1:index + 4]
        answered = any(r.get("type") == "system" and r.get("subtype") == "local_command" for r in following)
        answered = answered or any(r.get("type") == "user" and isinstance(r.get("message"), dict) and prompt_of(r).lstrip().startswith("<local-command-") for r in following)
        if answered or text.lstrip().startswith("<local-command-"):
            local.add(row.get("uuid"))
    return local


def is_reminder(text):
    stripped = (text or "").strip()
    return stripped.startswith("<system-reminder>") and stripped.endswith("</system-reminder>")


def unwrap_reminder(text):
    match = re.match(r"\s*<system-reminder>\s*(.*?)\s*</system-reminder>\s*\Z", text, re.S)
    return match.group(1) if match else text


def prompt_of(row):
    texts = [b.get("text", "") for b in as_blocks(row["message"].get("content")) if b.get("type") == "text"]
    typed = [t for t in texts if not is_reminder(t)]
    return "\n".join(typed or texts)


def attachment_text(row):
    rendered = row.get("rendered") or []
    parts = [r.get("content") for r in rendered if isinstance(r, dict) and isinstance(r.get("content"), str)]
    return "\n".join(parts)


def parse_claude(path):
    rows = read_jsonl(path)
    session = Session("Claude Code", path)
    path_rows, used_file_order = active_path(rows)
    if used_file_order:
        session.notes.append("Parent links in this log were broken, so turns are in file order. Rewound branches may appear.")
    sidechain = sum(1 for r in rows if r.get("isSidechain"))
    if sidechain:
        session.notes.append("Excluded %s subagent log entries: subagents have their own separate contexts." % fmt(sidechain))

    for row in path_rows:
        session.version = row.get("version") or session.version
        session.cwd = row.get("cwd") or session.cwd

    shapes, blobs, requests = {}, {}, []
    for row in rows:
        kind = row.get("type")
        if kind == "api-request-shape":
            shapes[row.get("shapeHash")] = row.get("shape") or {}
        elif kind == "api-request-blob":
            blobs[row.get("hash")] = row.get("message")
        elif kind == "api-request":
            requests.append(row)
    sources = collections.Counter(r.get("querySource") for r in requests)
    main_source = "sdk" if "sdk" in sources else (sources.most_common(1)[0][0] if sources else None)
    requests = [r for r in requests if r.get("querySource") == main_source]

    # Index transcript messages under the hash the request log uses.
    transcript, merged = {}, None
    usage_by_id, last_usage = {}, None
    for row in rows:
        if row.get("type") not in ("user", "assistant") or not isinstance(row.get("message"), dict):
            continue
        message = row["message"]
        wire = {"role": message.get("role"), "content": as_blocks(message.get("content"))}
        transcript[wire_hash(wire)] = wire
        if row["type"] == "assistant":
            if merged and merged["id"] == message.get("id"):
                merged["wire"]["content"] = merged["wire"]["content"] + wire["content"]
            else:
                merged = {"id": message.get("id"), "wire": {"role": "assistant", "content": list(wire["content"])}}
            transcript[wire_hash(merged["wire"])] = json.loads(json.dumps(merged["wire"]))
            if isinstance(message.get("usage"), dict) and not row.get("isSidechain"):
                usage_by_id[message.get("id")] = message["usage"]
                last_usage = message["usage"]
            session.model = message.get("model") or session.model

    def usage_total(usage):
        return (usage.get("input_tokens") or 0) + (usage.get("cache_read_input_tokens") or 0) + (usage.get("cache_creation_input_tokens") or 0)

    if last_usage:
        session.real_total = usage_total(last_usage)

    first_assistant = next((i for i, r in enumerate(path_rows) if r.get("type") == "assistant"), len(path_rows))
    rendered_map, prompt_texts, summary_texts = {}, set(), set()
    local_rows = local_command_rows(path_rows)
    attachment_counts = collections.Counter()
    for index, row in enumerate(path_rows):
        if row.get("type") == "attachment" and isinstance(row.get("attachment"), dict):
            text = attachment_text(row)
            if text:
                entry = {"row": row, "static": index < first_assistant}
                rendered_map[text] = entry
                for part in row.get("rendered") or []:
                    content = part.get("content") if isinstance(part, dict) else None
                    if isinstance(content, str) and content:
                        rendered_map[content] = entry
                        # Some requests fold reminders into one block without their wrapper.
                        rendered_map[unwrap_reminder(content)] = entry
        elif row.get("type") == "user" and not is_tool_result_line(row):
            for block in as_blocks(row["message"].get("content")):
                if block.get("type") != "text":
                    continue
                origin = row.get("origin") if isinstance(row.get("origin"), dict) else {}
                if row.get("isCompactSummary"):
                    summary_texts.add(block.get("text", ""))
                elif not row.get("isMeta") and origin.get("kind") in (None, "human") and not is_reminder(block.get("text")) and row.get("uuid") not in local_rows:
                    prompt_texts.add(block.get("text", ""))

    def add_attachment(row, static, text, evidence):
        attachment = row["attachment"]
        kind = attachment.get("type")
        if kind == "skill_listing":
            for line in re.split(r"(?m)^- ", attachment.get("content") or ""):
                if line.strip():
                    session.skills[re.split(r":\s", line, maxsplit=1)[0].strip()] = estimate(line)
        if kind in ("deferred_tools_delta", "deferred_tools_record"):
            for name in attachment.get("addedNames") or []:
                session.deferred[name] = True
            for name in attachment.get("removedNames") or []:
                session.deferred.pop(name, None)
            names = list(attachment.get("needsAuthMcpServers") or []) + [f.get("name") if isinstance(f, dict) else f for f in attachment.get("failedMcpServers") or []]
            session.unavailable_servers = [n for n in names if n] or session.unavailable_servers
        if kind == "instructions":
            remaining = len(text)
            for item in attachment.get("files") or []:
                content = item.get("content") or ""
                remaining -= len(content)
                section = "Memory" if item.get("type") == "AutoMem" else "CLAUDE.md / AGENTS.md"
                who = INSTRUCTION_NAMES.get(item.get("type"), item.get("type") or "")
                session.add(section, "%s (%s)" % (item.get("path"), who), content, evidence, BEFORE, role="user")
            if remaining > 0:
                session.add("Harness instructions", "Wrapper around instruction files", "(framing text around the files above)", evidence, BEFORE, tokens=int(remaining / CHARS_PER_TOKEN), role="user")
            return
        section, label = ATTACHMENT_SECTIONS.get(kind, ("Hidden injections", kind or "attachment"))
        if kind == "invoked_skills":
            names = ", ".join(s.get("name", "?") for s in attachment.get("skills") or [])
            label = "Skill bodies: %s" % names
        filename = attachment.get("filename") or attachment.get("displayPath")
        if filename:
            label = "%s: %s" % (label, filename)
        group = BEFORE if section in STATIC_GROUP_SECTIONS else CONVO
        if static and section == "Hidden injections":
            group = BEFORE
        session.add(section, label, text, evidence, group, role="user")

    tool_details = {}

    def classify(message, evidence, tool_names):
        role = message.get("role")
        for block in as_blocks(message.get("content")):
            kind = block.get("type")
            if kind == "text":
                text = block.get("text") or ""
                if role == "assistant":
                    session.add("Assistant text", "Assistant", text, evidence, CONVO, role=role)
                elif text in rendered_map:
                    hit = rendered_map[text]
                    add_attachment(hit["row"], hit["static"], text, evidence)
                elif text in summary_texts:
                    session.add("Compaction summary", "Summary written at compaction", text, evidence, CONVO, role=role)
                elif text in prompt_texts and not is_reminder(text):
                    session.add("Your messages", "User message", text, evidence, CONVO, role=role)
                else:
                    remainder = text
                    for known in sorted(rendered_map, key=len, reverse=True):
                        if len(known) >= 20 and known in remainder:
                            hit = rendered_map[known]
                            add_attachment(hit["row"], hit["static"], known, evidence)
                            remainder = remainder.replace(known, "", 1)
                    for prompt in sorted(prompt_texts, key=len, reverse=True):
                        if len(prompt) >= 20 and prompt in remainder:
                            session.add("Your messages", "User message", prompt, evidence, CONVO, role=role)
                            remainder = remainder.replace(prompt, "", 1)
                    if remainder.strip():
                        label = re.match(r"\s*<([\w-]+)", remainder)
                        section = "Skills loaded" if remainder.lstrip().startswith("Base directory for this skill") else "Hidden injections"
                        session.add(section, label.group(1) if label else "Injected text", remainder.strip(), evidence, CONVO, role=role)
            elif kind in ("tool_use", "server_tool_use"):
                tool_names[block.get("id")] = block.get("name")
                tool_details[block.get("id")] = tool_summary(block.get("name"), block.get("input"))
                session.add("Tool calls", block.get("name") or "tool", json.dumps(block.get("input"), ensure_ascii=False, indent=1), evidence, CONVO, role=role)
            elif kind in ("tool_result", "advisor_tool_result", "web_search_tool_result"):
                text, images = tool_result_text(block)
                name = tool_names.get(block.get("tool_use_id"), "tool")
                session.add("Tool results", name, text, evidence, CONVO, tokens=estimate(text) + images * IMAGE_TOKENS, role=role, detail=tool_details.get(block.get("tool_use_id")))
            elif kind == "thinking":
                visible = block.get("thinking") or ""
                body = visible or "[thinking text not recorded; only an encrypted signature is in the log]"
                session.add("Thinking", "Thinking", body, evidence, CONVO, tokens=estimate(visible) + int(len(block.get("signature") or "") / THINKING_SIG_CHARS_PER_TOKEN), role=role)
            elif kind == "redacted_thinking":
                session.add("Thinking", "Thinking", "[redacted by the provider]", evidence, CONVO, tokens=int(len(block.get("data") or "") / THINKING_SIG_CHARS_PER_TOKEN), role=role)
            elif kind == "image":
                session.add("Your messages" if role == "user" else "Assistant text", "Image", "[image omitted]", evidence, CONVO, tokens=IMAGE_TOKENS, role=role)

    tool_names = {}
    if requests:
        last = requests[-1]
        shape = shapes.get(last.get("shapeHash")) or {}
        for index, block in enumerate(shape.get("system") or []):
            session.add("System prompt", "System block %d" % (index + 1), block.get("text") or "", EV_REQUEST, BEFORE, role="system")
        deferred = 0
        for tool in shape.get("tools") or []:
            if tool.get("defer_loading"):
                deferred += 1
                continue
            name = tool.get("name") or "tool"
            session.add(tool_section(name), name, json.dumps(tool, ensure_ascii=False, indent=1), EV_REQUEST, BEFORE, role="system")
        if deferred:
            session.notes.append("%s tools in the request are deferred, so their schemas are not counted here." % fmt(deferred))
        sequence = []
        for request in requests:
            sequence = sequence[: request.get("keep", 0)] + list(request.get("tail") or [])
        matched = 0
        for digest in sequence:
            message = blobs.get(digest) or transcript.get(digest)
            if message is None:
                continue
            matched += 1
            classify(message, EV_REQUEST, tool_names)
        session.coverage = (matched, len(sequence))
        missing = len(sequence) - matched
        if missing:
            session.notes.append("%s of %s messages in the last request could not be recovered from the log, so their text is missing here. Their tokens are in the Unattributed row." % (fmt(missing), fmt(len(sequence))))
    else:
        session.add("System prompt", "Not in this log", "(this Claude Code version did not record the system prompt)", EV_NONE, BEFORE, tokens=0)
        session.add("Built-in tools", "Not in this log", "(this Claude Code version did not record tool definitions)", EV_NONE, BEFORE, tokens=0)
        session.notes.append("This log has no recorded API requests, so the report is built from the transcript. System prompt and tool definitions are not recorded.")
        boundary = 0
        for index, row in enumerate(path_rows):
            if row.get("type") == "system" and row.get("subtype") == "compact_boundary":
                boundary = index
        merged_row = None
        for row in path_rows[boundary:]:
            if row.get("type") == "attachment" and isinstance(row.get("attachment"), dict):
                text = attachment_text(row)
                if text:
                    add_attachment(row, rendered_map.get(text, {}).get("static", False), text, EV_SESSION)
            elif row.get("type") in ("user", "assistant") and isinstance(row.get("message"), dict):
                classify({"role": row["message"].get("role"), "content": as_blocks(row["message"].get("content"))}, EV_SESSION, tool_names)
        del merged_row

    boundary = max([i for i, r in enumerate(path_rows) if r.get("type") == "system" and r.get("subtype") == "compact_boundary"] or [0])
    output_by_id, thinking_by_id, peak = {}, {}, 0
    for index, row in enumerate(path_rows):
        usage = row.get("message", {}).get("usage") if row.get("type") == "assistant" else None
        if not isinstance(usage, dict):
            continue
        peak = max(peak, usage_total(usage))
        if index >= boundary:
            key = row["message"].get("id")
            details = usage.get("output_tokens_details") or {}
            output_by_id[key] = max(output_by_id.get(key, 0), usage.get("output_tokens") or 0)
            thinking_by_id[key] = max(thinking_by_id.get(key, 0), details.get("thinking_tokens") or 0)
    session.apply_output_usage(sum(output_by_id.values()), sum(thinking_by_id.values()))
    listed = catalog_window(session.model)
    if listed:
        session.window, session.window_source = listed, "catalog"
    elif peak > 200000:
        session.window, session.window_source = 1000000, "inferred"
    if requests:
        first = requests[0]
        shape = shapes.get(first.get("shapeHash")) or {}
        first_estimate = sum(estimate(b.get("text") or "") for b in shape.get("system") or [])
        first_estimate += sum(estimate(json.dumps(t, ensure_ascii=False, indent=1)) for t in shape.get("tools") or [] if not t.get("defer_loading"))
        for digest in first.get("tail") or []:
            message = blobs.get(digest) or transcript.get(digest)
            if message:
                first_estimate += sum(estimate(block_text(b)) for b in as_blocks(message.get("content")))
        first_usage = next((r["message"]["usage"] for r in path_rows if r.get("type") == "assistant" and isinstance(r.get("message", {}).get("usage"), dict)), None)
        if first_usage:
            session.first_total = usage_total(first_usage)
            session.standing_gap = max(0, session.first_total - first_estimate)

    # Turn-by-turn view.
    turn, number, last_boundary_turn, tool_lookup = None, 0, 0, {}
    pending_hidden = []
    counted_usage, read_counts, injected_hashes = set(), collections.Counter(), collections.Counter()
    injected_labels, external_edits = {}, []
    work_areas, errors = set(), 0
    for index, row in enumerate(path_rows):
        kind = row.get("type")
        if row.get("cwd"):
            work_areas.add((row.get("cwd"), row.get("gitBranch")))
        if kind == "system" and row.get("subtype") == "compact_boundary":
            meta = row.get("compactMetadata") or {}
            session.events.append({
                "event": "compaction", "trigger": meta.get("trigger"), "pre": meta.get("preTokens"),
                "post": meta.get("postTokens"), "dropped": meta.get("cumulativeDroppedTokens"),
                "turns_before": number,
            })
            last_boundary_turn = number
            continue
        if kind == "system" and row.get("subtype") == "local_command":
            text = row.get("content") if isinstance(row.get("content"), str) else ""
            tag = re.match(r"\s*<([\w-]+)", text)
            pending_hidden.append((tag.group(1) if tag else "slash command", estimate(text)))
            continue
        if kind == "attachment" and isinstance(row.get("attachment"), dict):
            text = attachment_text(row)
            attachment = row["attachment"]
            if attachment.get("type") == "edited_text_file" and attachment.get("filename"):
                external_edits.append(attachment["filename"])
            if text:
                digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
                injected_hashes[digest] += 1
                injected_labels[digest] = (attachment.get("type"), estimate(text))
                if index >= first_assistant and turn is not None:
                    turn["hidden"].append((attachment.get("type"), estimate(text)))
            continue
        if kind not in ("user", "assistant") or not isinstance(row.get("message"), dict):
            continue
        message = row["message"]
        if kind == "user":
            if is_tool_result_line(row):
                for block in as_blocks(message.get("content")):
                    if block.get("type") in ("tool_result", "advisor_tool_result"):
                        text, images = tool_result_text(block)
                        step = tool_lookup.get(block.get("tool_use_id"))
                        if step is not None:
                            step["result_tokens"] = estimate(text) + images * IMAGE_TOKENS
                            step["error"] = bool(block.get("is_error"))
                            errors += 1 if block.get("is_error") else 0
                continue
            if row.get("isCompactSummary"):
                continue
            if row.get("isMeta"):
                if turn is not None:
                    turn["hidden"].append(("hidden message", estimate(prompt_of(row))))
                continue
            origin = (row.get("origin") or {}).get("kind") if isinstance(row.get("origin"), dict) else None
            if row.get("uuid") in local_rows:
                # Slash-command echoes are not requests to the agent, but they do use context.
                tag = re.match(r"\s*<([\w-]+)", prompt_of(row))
                pending_hidden.append((tag.group(1), estimate(prompt_of(row))))
                continue
            number += 1
            shown = command_prompt(prompt_of(row)) if starts_with_command(prompt_of(row)) else prompt_of(row)
            turn = new_turn(number, shown, "you" if origin in (None, "human") else origin, row.get("timestamp"))
            turn["hidden"].extend(pending_hidden)
            pending_hidden = []
            for block in as_blocks(message.get("content")):
                if block.get("type") == "text" and is_reminder(block.get("text")) and prompt_of(row) != block.get("text"):
                    turn["hidden"].append(("system-reminder", estimate(block.get("text"))))
            session.turns.append(turn)
            session.events.append(turn)
            continue
        if turn is None:
            continue
        for block in as_blocks(message.get("content")):
            block_kind = block.get("type")
            if block_kind == "text":
                turn["answer"].append(block.get("text") or "")
            elif block_kind == "thinking":
                turn["thinking"] += 1
            elif block_kind in ("tool_use", "server_tool_use"):
                step = {"name": block.get("name"), "summary": tool_summary(block.get("name"), block.get("input")), "result_tokens": None, "error": False, "input_tokens": estimate(json.dumps(block.get("input"), ensure_ascii=False))}
                turn["steps"].append(step)
                tool_lookup[block.get("id")] = step
                tool_input = block.get("input") if isinstance(block.get("input"), dict) else {}
                step["path"] = tool_input.get("file_path") or tool_input.get("notebook_path")
                step["command"] = tool_input.get("command") if isinstance(tool_input.get("command"), str) else ""
                step["changed"] = [step["path"]] if step["path"] and block.get("name") in EDIT_TOOLS else []
                if block.get("name") == "Read" and tool_input.get("file_path"):
                    read_counts[tool_input["file_path"]] += 1
        usage = message.get("usage")
        if isinstance(usage, dict):
            turn["tokens_end"] = usage_total(usage)
            details = usage.get("output_tokens_details") or {}
            key = message.get("id")
            turn["thinking_by_id"][key] = max(turn["thinking_by_id"].get(key, 0), details.get("thinking_tokens") or 0)
    for turn_item in session.turns:
        turn_item["in_context"] = turn_item["n"] > last_boundary_turn
    apply_running_totals(session)

    repeats = [(injected_labels[d][0], count, injected_labels[d][1]) for d, count in injected_hashes.items() if count >= 2]
    session.signals.update({
        "repeats": sorted(repeats, key=lambda r: -(r[1] * r[2])),
        "rereads": sorted(((p, c) for p, c in read_counts.items() if c >= 2), key=lambda x: -x[1]),
        "external_edits": collections.Counter(external_edits).most_common(),
        "work_areas": sorted({"%s (%s)" % (a or "?", b or "no branch") for a, b in work_areas}),
        "errors": errors,
    })
    session.finalize()
    return session


# -------------------------------------------------------------------- Codex

CODEX_SECTIONS = {
    "skills_instructions": "Skills available", "recommended_plugins": "Skills available",
    "environment_context": "Environment and session info", "permissions": "Harness instructions",
    "collaboration_mode": "Harness instructions", "tools": "Harness instructions",
    "multi_agent_role": "Harness instructions", "multi_agent_mode": "Harness instructions",
    "model_instructions": "Harness instructions", "app-context": "Harness instructions",
}


def codex_output_text(output):
    if isinstance(output, str):
        return output, 0
    parts, images = [], 0
    for item in output if isinstance(output, list) else []:
        if not isinstance(item, dict):
            continue
        if item.get("type") in ("input_text", "output_text", "text"):
            parts.append(item.get("text") or "")
        elif item.get("type") in ("input_image", "image"):
            images += 1
            parts.append("[image omitted]")
    return "\n".join(parts), images


def codex_message_text(payload):
    parts, images = [], 0
    for item in payload.get("content") or []:
        if item.get("type") in ("input_text", "output_text", "text"):
            parts.append(item.get("text") or "")
        elif item.get("type") == "input_image":
            images += 1
    return "\n".join(parts), images


def codex_kind(role, text):
    """Classify a message into (section, label, is_real_user_prompt)."""
    stripped = text.lstrip()
    if role == "user" and stripped.startswith("# AGENTS.md"):
        return "CLAUDE.md / AGENTS.md", "AGENTS.md", False
    tag = re.match(r"<([\w-]+)", stripped)
    if tag:
        name = tag.group(1)
        if name == "image":
            return "Your messages", "Image", False
        return CODEX_SECTIONS.get(name, "Hidden injections"), name, False
    if role == "developer":
        return "Harness instructions", "Developer message", False
    if stripped.startswith("# Files") or stripped.startswith("# Response"):
        return "Hidden injections", "Injected heading", False
    return "Your messages", "User message", True


def parse_codex(path):
    rows = read_jsonl(path)
    session = Session("Codex", path)
    context, number, turn = [], 0, None
    tool_lookup, seen_assistant, hashes, labels, errors = {}, False, collections.Counter(), {}, 0
    last_input = None
    is_subagent, own_address = False, None
    for row in rows:
        kind = row.get("type")
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        if kind == "session_meta":
            session.session_id = payload.get("id") or session.session_id
            session.version = payload.get("cli_version")
            session.cwd = payload.get("cwd")
            is_subagent = isinstance(payload.get("source"), dict) and "subagent" in payload["source"]
            base = payload.get("base_instructions")
            if isinstance(base, dict) and base.get("text"):
                session.add("System prompt", "Base instructions", base["text"], EV_SESSION, BEFORE, role="system")
        elif kind == "turn_context":
            session.model = payload.get("model") or session.model
            session.cwd = payload.get("cwd") or session.cwd
        elif kind == "event_msg" and payload.get("type") == "token_count" and isinstance(payload.get("info"), dict):
            info = payload["info"]
            usage = info.get("last_token_usage") or {}
            if info.get("model_context_window"):
                session.window, session.window_source = info["model_context_window"], "log"
            if usage.get("input_tokens") is not None:
                last_input = usage["input_tokens"]
                if turn is not None:
                    turn["tokens_end"] = last_input
        elif kind == "compacted":
            usage = ((payload.get("latest_token_usage_record") or {}).get("usage") or {})
            replacement = payload.get("replacement_history") or []
            session.events.append({"event": "compaction", "trigger": "auto or manual", "pre": usage.get("input_tokens"), "post": None, "dropped": None, "turns_before": number})
            for done in session.turns:
                done["in_context"] = False
            context = list(replacement)
            if not replacement and payload.get("message"):
                context = [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": payload["message"]}], "_summary": True}]
        elif kind == "response_item":
            item_type = payload.get("type")
            context.append(payload)
            if item_type == "message":
                text, _ = codex_message_text(payload)
                role = payload.get("role")
                if role == "assistant":
                    seen_assistant = True
                    if turn is not None:
                        turn["answer"].append(text)
                    continue
                section, label, real = codex_kind(role, text)
                if real:
                    number += 1
                    turn = new_turn(number, text, "you", row.get("timestamp"))
                    session.turns.append(turn)
                    session.events.append(turn)
                else:
                    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
                    hashes[digest] += 1
                    labels[digest] = (label, estimate(text))
                    if seen_assistant and turn is not None:
                        turn["hidden"].append((label, estimate(text)))
            elif item_type == "agent_message" and is_subagent:
                own_address = own_address or payload.get("recipient")
                if payload.get("recipient") == own_address:
                    number += 1
                    turn = new_turn(number, codex_message_text(payload)[0], "parent agent", row.get("timestamp"))
                    session.turns.append(turn)
                    session.events.append(turn)
            elif item_type in ("function_call", "custom_tool_call"):
                raw = payload.get("arguments") if item_type == "function_call" else payload.get("input")
                try:
                    parsed = json.loads(raw) if isinstance(raw, str) else raw
                except ValueError:
                    parsed = raw
                step = {"name": payload.get("name"), "summary": tool_summary(payload.get("name"), parsed), "result_tokens": None, "error": False, "input_tokens": estimate(raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False))}
                raw_text = raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False)
                step["path"], step["command"], step["changed"] = None, raw_text, PATCH_FILE.findall(raw_text or "")
                tool_lookup[payload.get("call_id")] = step
                if turn is not None:
                    turn["steps"].append(step)
            elif item_type in ("function_call_output", "custom_tool_call_output"):
                text, images = codex_output_text(payload.get("output"))
                step = tool_lookup.get(payload.get("call_id"))
                if step is not None:
                    step["result_tokens"] = estimate(text) + images * IMAGE_TOKENS
            elif item_type == "reasoning" and turn is not None:
                turn["thinking"] += 1

    if not any(b["section"] == "System prompt" for b in session.blocks):
        session.add("System prompt", "Not in this log", "(not recorded)", EV_NONE, BEFORE, tokens=0)
    calls, details = {}, {}
    first_prompt_seen = False
    for item in context:
        item_type = item.get("type")
        if item_type == "message":
            text, images = codex_message_text(item)
            role = item.get("role")
            image_tokens = images * IMAGE_TOKENS
            if role == "assistant":
                session.add("Assistant text", "Assistant", text, EV_SESSION, CONVO, role=role)
                first_prompt_seen = True
                continue
            if item.get("_summary"):
                session.add("Compaction summary", "Summary written at compaction", text, EV_SESSION, CONVO, role=role)
                continue
            section, label, real = codex_kind(role, text)
            if real:
                first_prompt_seen = True
            group = BEFORE if section in STATIC_GROUP_SECTIONS else CONVO
            if section == "Hidden injections" and not first_prompt_seen:
                group = BEFORE
            session.add(section, label, text, EV_SESSION, group, tokens=estimate(text) + image_tokens, role=role)
        elif item_type == "agent_message":
            text, _ = codex_message_text(item)
            session.add("Hidden injections", "Message between agents", text, EV_SESSION, CONVO, role="agent")
        elif item_type == "additional_tools":
            for tool in item.get("tools") or []:
                name = tool.get("name") or tool.get("type") or "tool"
                session.add(tool_section(name), name, json.dumps(tool, ensure_ascii=False, indent=1), EV_SESSION, BEFORE, role="system")
        elif item_type in ("function_call", "custom_tool_call"):
            raw = item.get("arguments") if item_type == "function_call" else item.get("input")
            calls[item.get("call_id")] = item.get("name")
            details[item.get("call_id")] = one_line(raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False), 90)
            session.add("Tool calls", item.get("name") or "tool", raw if isinstance(raw, str) else json.dumps(raw, ensure_ascii=False), EV_SESSION, CONVO, role="assistant")
        elif item_type in ("function_call_output", "custom_tool_call_output"):
            text, images = codex_output_text(item.get("output"))
            session.add("Tool results", calls.get(item.get("call_id"), "tool"), text, EV_SESSION, CONVO, tokens=estimate(text) + images * IMAGE_TOKENS, role="tool", detail=details.get(item.get("call_id")))
        elif item_type == "reasoning":
            session.add("Thinking", "Reasoning", "[encrypted by the provider; not recoverable]", EV_SESSION, CONVO, tokens=int(len(item.get("encrypted_content") or "") / 8), role="assistant")
    session.add("Built-in tools", "Built-in tool schemas", "(Codex logs only hashes of its built-in tools, not their text)", EV_NONE, BEFORE, tokens=0)
    session.notes.append("Codex logs conversation items, not the literal API request, so nothing here is byte-checked against a request. Built-in tool schemas are not recorded, and reasoning is encrypted.")
    if not session.turns:
        session.notes.append("No typed user message was found in this log, so the timeline is empty.")
    session.real_total = last_input
    apply_running_totals(session)
    repeats = [(labels[d][0], count, labels[d][1]) for d, count in hashes.items() if count >= 2]
    session.signals.update({
        "repeats": sorted(repeats, key=lambda r: -(r[1] * r[2])), "rereads": [], "external_edits": [],
        "work_areas": ["%s" % session.cwd] if session.cwd else [], "errors": errors,
    })
    session.finalize()
    return session


# --------------------------------------------------------- session discovery

def claude_home():
    return os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")


def codex_home():
    return os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex")


def newest(paths):
    paths = [p for p in paths if os.path.isfile(p)]
    return max(paths, key=os.path.getmtime) if paths else None


def logged_cwd(path):
    for row in read_jsonl(path):
        if row.get("cwd"):
            return os.path.realpath(row["cwd"])
    return None


def find_claude(session_id, cwd):
    projects = os.path.join(claude_home(), "projects")
    wanted = session_id or os.environ.get("CLAUDE_CODE_SESSION_ID")
    if wanted:
        hit = newest(glob.glob(os.path.join(projects, "*", wanted + "*.jsonl")))
        if hit:
            return hit
    real = os.path.realpath(cwd)
    encoded = re.sub(r"[^A-Za-z0-9]", "-", real)
    hit = newest(glob.glob(os.path.join(projects, glob.escape(encoded), "*.jsonl")))
    if hit:
        return hit
    # Very long paths get a shortened folder name with a hash, so confirm by the logged cwd.
    candidates = glob.glob(os.path.join(projects, glob.escape(encoded[:150]) + "*", "*.jsonl"))
    return newest([f for f in candidates if logged_cwd(f) == real])


def codex_meta_cwd(path):
    with open(path, errors="replace") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except ValueError:
                return None
            if row.get("type") == "session_meta":
                return row.get("payload", {}).get("cwd")
            return None
    return None


def find_codex(session_id, cwd):
    pattern = os.path.join(codex_home(), "sessions", "**", "*.jsonl")
    wanted = session_id or os.environ.get("CODEX_THREAD_ID") or os.environ.get("CODEX_SESSION_ID")
    files = glob.glob(pattern, recursive=True)
    if wanted:
        hit = newest([f for f in files if wanted in os.path.basename(f)])
        if hit:
            return hit
    real = os.path.realpath(cwd)
    for path in sorted((f for f in files if os.path.isfile(f)), key=os.path.getmtime, reverse=True)[:300]:
        logged = codex_meta_cwd(path)
        if logged and os.path.realpath(logged) == real:
            return path
    return None


def detect(args):
    """Return (agent, path); either may be None."""
    if args.log:
        agent = args.agent if args.agent != "auto" else ("codex" if "rollout-" in os.path.basename(args.log) else "claude")
        return agent, args.log
    cwd = args.cwd or os.getcwd()
    if args.agent == "claude":
        return "claude", find_claude(args.session, cwd)
    if args.agent == "codex":
        return "codex", find_codex(args.session, cwd)
    if os.environ.get("CLAUDECODE") or os.environ.get("CLAUDE_CODE_SESSION_ID"):
        return "claude", find_claude(args.session, cwd)
    if any(k.startswith("CODEX_") and k not in ("CODEX_HOME",) for k in os.environ):
        return "codex", find_codex(args.session, cwd)
    candidates = [("claude", find_claude(args.session, cwd)), ("codex", find_codex(args.session, cwd))]
    candidates = [c for c in candidates if c[1]]
    if not candidates:
        return None, None
    return max(candidates, key=lambda c: os.path.getmtime(c[1]))


# --------------------------------------------------------------- rendering

def section_rows(session):
    grouped = collections.OrderedDict()
    for name in SECTION_ORDER:
        members = [b for b in session.blocks if b["section"] == name]
        if members:
            grouped[name] = members
    return grouped


def evidence_of(members):
    kinds = {m["evidence"] for m in members}
    return " + ".join(sorted(kinds))


def size_tag(session):
    return "est." if session.real_total else "rough est."


def map_table(session, heading="Section"):
    total = sum(b["tokens"] for b in session.blocks) or 1
    lines = ["| %s | Tokens | %% of used | %% of window | Size from | Text from |" % heading, "|---|---:|---:|---:|---|---|"]
    before = sum(b["tokens"] for b in session.blocks if b["group"] == BEFORE)
    for group, title, subtotal in ((BEFORE, "**Before your first message**", before), (CONVO, "**The conversation**", total - before)):
        rows = [(name, [m for m in members if m["group"] == group]) for name, members in section_rows(session).items()]
        rows = [(name, members) for name, members in rows if members]
        if not rows:
            continue
        lines.append("| %s | **%s** | **%d%%** | **%s** | | |" % (title, fmt(subtotal), round(100.0 * subtotal / total), percent_of_window(session, subtotal)))
        for name, members in rows:
            tokens = sum(m["tokens"] for m in members)
            label = DISPLAY_NAMES.get(name, name)
            basis = "provider usage" if any(m["basis"] == "usage" for m in members) else ("provider total minus the rest" if name in GAP_SECTIONS else "text length")
            lines.append("| %s | %s | %d%% | %s | %s | %s |" % (label, fmt(tokens), round(100.0 * tokens / total), percent_of_window(session, tokens), basis, evidence_of(members)))
    return "\n".join(lines)


PLAIN_GROUPS = [
    ("Setup it starts with", ["System prompt", "Built-in tools", "MCP tools", "CLAUDE.md / AGENTS.md", "Memory", "Skills available", "MCP server instructions", "Subagents available", "Deferred tool list", "Output style", "Harness instructions", "Environment and session info", STANDING_GAP, NOT_IN_LOG]),
    ("What it did (thinking, tool calls, replies)", ["Assistant text", "Thinking", "Tool calls"]),
    ("What it read (tool results, files, skills)", ["Tool results", "Files attached", "Skills loaded"]),
    ("Summary of earlier work", ["Compaction summary"]),
    ("What you said", ["Your messages"]),
    ("Injected without you seeing", ["Hidden injections"]),
    ("Could not be identified", [UNATTRIBUTED]),
]
DISPLAY_NAMES = {
    "Harness instructions": "Instructions from the agent app",
    "Deferred tool list": "Names of tools not loaded yet",
    "Hidden injections": "Injected text",
}
FRIENDLY_LABELS = {
    "local-command-stdout": "slash command output",
    "local-command-caveat": "slash command note",
    "command-name": "slash command",
    "command-message": "slash command",
    "output_style": "output style reminder",
    "task-notification": "background task notification",
    "system-reminder": "system reminder",
    "invoked_skills": "skill instructions",
    "skill_mention": "skill mention",
    "edited_text_file": "file changed outside the agent",
    "deferred_tools_delta": "tool name list",
    "mcp_instructions_delta": "MCP instructions",
    "skill_listing": "skill list",
    "Injected text": "injected text",
}


def friendly(label):
    return FRIENDLY_LABELS.get(label, (label or "injected text").replace("_", " "))


def short_tokens(tokens):
    return "%.1fk" % (tokens / 1000.0) if tokens >= 1000 else str(int(tokens))


def plain_table(session):
    total = sum(b["tokens"] for b in session.blocks) or 1
    lines = ["| | Tokens | % of used | % of window |", "|---|---:|---:|---:|"]
    for title, sections in PLAIN_GROUPS:
        tokens = sum(b["tokens"] for b in session.blocks if b["section"] in sections)
        if tokens:
            lines.append("| %s | %s | %d%% | %s |" % (title, fmt(tokens), round(100.0 * tokens / total), percent_of_window(session, tokens)))
    return "\n".join(lines)


def verdict_line(session):
    """A rule-of-thumb recommendation built only from numbers in the log."""
    compactions = sum(1 for e in session.events if e["event"] == "compaction")
    gone = sum(1 for t in session.turns if not t["in_context"])
    share = float(session.real_total) / session.window if session.window and session.real_total else None
    used = "%.1f%% of the window is used" % (100 * share) if share is not None else "The window size is unknown"
    memory = "nothing has been compacted" if not compactions else "%d of %d turns now exist only as a summary" % (gone, len(session.turns))
    if share is not None and share >= 0.85:
        call = "Start fresh or compact now"
    elif share is not None and share >= 0.6:
        call = "Compact soon"
    elif compactions >= 2:
        call = "Consider starting fresh"
    elif compactions == 1:
        call = "Keep going, but check what it forgot"
    else:
        call = "Keep going"
    return "**Verdict: %s.** %s and %s. *(Rule of thumb, not a measurement.)*" % (call, used, memory)


def worth_doing(session):
    """Ranked (tokens, sentence) suggestions. Each one names something the user can act on."""
    items = []
    used = {step["name"] for turn in session.turns for step in turn["steps"]}
    tools = [b for b in session.blocks if b["section"] in ("Built-in tools", "MCP tools") and b["evidence"] != EV_NONE]
    if session.agent == "Claude Code":
        servers = collections.OrderedDict()
        for block in tools:
            if block["section"] == "MCP tools":
                servers.setdefault(tool_server(block["label"])[0], []).append(block)
        for server, members in servers.items():
            tokens = sum(m["tokens"] for m in members)
            if tokens >= 500 and not any(m["label"] in used for m in members):
                sample = ", ".join(tool_server(m["label"])[1] for m in members[:2])
                items.append((tokens, "MCP server `%s` (%s) has %d loaded tools and none were used. Disable it for sessions that don't need it." % (server, one_line(sample, 50), len(members))))
        used_skills = {step["summary"] for turn in session.turns for step in turn["steps"] if step["name"] == "Skill"}
        sources = collections.OrderedDict()
        for name, tokens in session.skills.items():
            sources.setdefault(skill_source(name), []).append((name, tokens))
        for source, members in sources.items():
            tokens = sum(m[1] for m in members)
            if source != "user or built-in" and tokens >= 500 and not any(m[0] in used_skills for m in members):
                items.append((tokens, "The `%s` plugin lists %d skills and none were used. Disable it for sessions that don't need it." % (source, len(members))))
    reads = collections.defaultdict(list)
    for turn in session.turns:
        if turn["in_context"]:
            for step in turn["steps"]:
                if step["name"] == "Read" and step["result_tokens"]:
                    reads[step["summary"]].append(step["result_tokens"])
    for path, sizes in reads.items():
        extra = sum(sizes) - max(sizes)
        if len(sizes) >= 2 and extra >= 500:
            items.append((extra, "`%s` was read %d times, so the agent is holding repeat copies." % (one_line(path, 70), len(sizes))))
    for label, count, tokens in session.signals.get("repeats") or []:
        extra = (count - 1) * tokens
        if extra >= 1000:
            items.append((extra, "The %s was injected %d times with identical text." % (friendly(label), count)))
    large = collections.defaultdict(list)
    for block in session.blocks:
        if block["section"] == "Hidden injections" and block["tokens"] >= 3000:
            large[("injected", friendly(block["label"]))].append(block["tokens"])
        elif block["section"] == "Tool results" and block["tokens"] >= 5000:
            large[("result", block["label"])].append(block["tokens"])
        elif block["section"] == "Tool calls" and block["tokens"] >= 5000:
            large[("call", block["label"])].append(block["tokens"])
        elif block["section"] in ("CLAUDE.md / AGENTS.md", "Memory") and block["tokens"] >= 2000:
            items.append((block["tokens"], "`%s` is loaded in every session. Trim anything that isn't needed every time." % one_line(block["label"], 70)))
    for (kind, label), sizes in large.items():
        count, what = len(sizes), "%d %s" % (len(sizes), label if kind == "injected" else "`%s` %s" % (label, kind))
        plural = "s" if count > 1 else ""
        if kind == "injected":
            items.append((sum(sizes), "%s%s from outside the conversation. Run /compact once you no longer need %s." % (what, plural, "them" if count > 1 else "it")))
        elif kind == "result":
            items.append((sum(sizes), "%s%s over 5,000 tokens%s. Limit that output next time, or run /compact once you're done with it." % (what, plural, " each" if count > 1 else "")))
        else:
            items.append((sum(sizes), "%s%s the agent wrote, over 5,000 tokens%s. Run /compact once that work is finished." % (what, plural, " each" if count > 1 else "")))
    return sorted(items, key=lambda item: -item[0])


def tool_use_fact(session):
    if session.agent != "Claude Code":
        return ""
    tools = [b for b in session.blocks if b["section"] in ("Built-in tools", "MCP tools") and b["evidence"] != EV_NONE]
    if not tools:
        return ""
    used = {step["name"] for turn in session.turns for step in turn["steps"]}
    unused = [b for b in tools if b["label"] not in used]
    return "Of %d loaded tools, %d were never used in this session, about %s tokens. Built-in tools come with the agent, so only MCP servers can usually be removed." % (len(tools), len(unused), fmt(sum(b["tokens"] for b in unused)))


def worth_doing_text(session, limit=None):
    items = worth_doing(session)
    shown = items[:limit] if limit else items
    lines = ["%d. **About %s tokens:** %s" % (i + 1, fmt(tokens), text) for i, (tokens, text) in enumerate(shown)]
    if not lines:
        lines = ["Nothing large enough to act on."]
    if len(items) > len(shown):
        lines.append("\n%d more in the full report." % (len(items) - len(shown)))
    fact = tool_use_fact(session)
    if fact:
        lines.append("\n" + fact)
    return "\n".join(lines)


def brief_section(text, name):
    match = re.search(r"(?ims)^#{1,6}\s*%s\s*$\n(.*?)(?=^#{1,6}\s|\Z)" % re.escape(name), text)
    return match.group(1).strip() if match else ""


def brief_comparison(session, brief):
    """Put the agent's stated job beside what the user actually asked."""
    if not brief or not brief.strip():
        return ""
    job = brief_section(brief, "Current job") or brief.strip()
    asks = [t for t in session.turns if t["kind"] == "you"]
    shown = asks[-5:]
    left = "<br>".join("%d. %s" % (t["n"], cell(one_line(t["prompt"], 130))) for t in shown) or "(no typed messages found)"
    if len(asks) > len(shown):
        left = "*(%d earlier messages omitted)*<br>%s" % (len(asks) - len(shown), left)
    lines = ["| What you asked (from the log) | What it says its job is (self-reported) |", "|---|---|", "| %s | %s |" % (left, cell(one_line(job, 400)))]
    count = lambda name: len(brief_items(brief_section(brief, name)))
    lines += ["", "It lists %d assumption(s) and %d conflict(s) in the full brief-back below." % (count("Unclear or assumed"), count("Conflicts"))]
    return "\n".join(lines)


def biggest_addition(event):
    candidates = [(estimate(event["prompt"]), "your message")]
    candidates += [(tokens, friendly(label)) for label, tokens in event["hidden"]]
    for step in event["steps"]:
        what = "%s: %s" % (step["name"], step["summary"]) if step["summary"] else step["name"]
        candidates.append((step.get("input_tokens") or 0, "%s (input)" % what))
        candidates.append((step.get("result_tokens") or 0, "%s (result)" % what))
    thinking = sum(event["thinking_by_id"].values())
    if thinking:
        candidates.append((thinking, "thinking"))
    answer = estimate("\n".join(event["answer"]))
    if answer:
        candidates.append((answer, "its reply"))
    tokens, what = max(candidates, key=lambda c: c[0])
    return "%s: %s" % (short_tokens(tokens), cell(one_line(what, 60)))


def percent_of_window(session, tokens):
    if not session.window or tokens is None:
        return "n/a"
    return "%.1f%%" % (100.0 * tokens / session.window)


WINDOW_SOURCES = {
    "log": "stated in the session log",
    "catalog": "listed for this model in Claude Code's model catalog",
    "inferred": "inferred because usage passed 200,000 tokens",
    "flag": "set with --window",
}


def window_gauge(session):
    """The headline: used, available, and percent of the context window."""
    used = session.real_total
    if used is None:
        return "**Context window:** no usage numbers in this log."
    if not session.window:
        return "**Context window:** %s tokens used. The window size is not known for this model, so pass --window to see the percentage." % fmt(used)
    filled = min(24, int(round(24.0 * used / session.window)))
    bar = "█" * filled + "░" * (24 - filled)
    source = WINDOW_SOURCES.get(session.window_source, "")
    if used > session.window:
        return "`%s` **%s used, over the listed %s window** (%s). This session grew past the listed limit." % (bar, fmt(used), fmt(session.window), source)
    return "`%s` **%s of %s tokens used (%s)** · %s free · window size %s" % (bar, fmt(used), fmt(session.window), percent_of_window(session, used), fmt(session.window - used), source)


def tools_table(session, limit=None):
    servers = collections.OrderedDict()
    for block in session.blocks:
        if block["section"] in ("Built-in tools", "MCP tools") and block["evidence"] != EV_NONE:
            server, tool = tool_server(block["label"])
            entry = servers.setdefault(server, {"loaded": 0, "tokens": 0, "deferred": 0, "names": []})
            entry["loaded"] += 1
            entry["tokens"] += block["tokens"]
            entry["names"].append(tool)
    for name in session.deferred:
        server, tool = tool_server(name)
        entry = servers.setdefault(server, {"loaded": 0, "tokens": 0, "deferred": 0, "names": []})
        entry["deferred"] += 1
        entry["names"].append(tool)
    if not servers:
        return ""
    ordered = sorted(servers.items(), key=lambda item: (-item[1]["tokens"], -item[1]["deferred"]))
    loaded = [item for item in ordered if item[1]["loaded"]]
    shown = (loaded[:limit] if limit else ordered)
    lines = ["| Server | Tools loaded | Tokens | Not loaded yet | Includes |", "|---|---:|---:|---:|---|"]
    for server, entry in shown:
        lines.append("| %s | %d | %s | %d | %s |" % (cell(server), entry["loaded"], fmt(entry["tokens"]), entry["deferred"], cell(one_line(", ".join(entry["names"][:4]), 70))))
    hidden = len(ordered) - len(shown)
    if hidden:
        lines.append("| *%d more servers are in the report* | | | | |" % hidden)
    return "\n".join(lines)


def tools_detail(session):
    tools = sorted((b for b in session.blocks if b["section"] in ("Built-in tools", "MCP tools") and b["evidence"] != EV_NONE), key=lambda b: -b["tokens"])
    lines = ["| Tool | Server | Tokens |", "|---|---|---:|"]
    lines += ["| %s | %s | %s |" % (cell(b["label"]), cell(tool_server(b["label"])[0]), fmt(b["tokens"])) for b in tools]
    return "\n".join(lines)


def skill_source(name):
    return name.split(":", 1)[0] if ":" in name else "user or built-in"


def skills_table(session, limit=None):
    if not session.skills:
        return ""
    sources = collections.OrderedDict()
    for name, tokens in session.skills.items():
        entry = sources.setdefault(skill_source(name), [0, 0])
        entry[0] += 1
        entry[1] += tokens
    ordered = sorted(sources.items(), key=lambda item: -item[1][1])
    shown = ordered[:limit] if limit else ordered
    lines = ["| Source | Skills listed | Tokens |", "|---|---:|---:|"]
    lines += ["| %s | %d | %s |" % (cell(source), count, fmt(tokens)) for source, (count, tokens) in shown]
    if len(ordered) > len(shown):
        lines.append("| *%d more sources are in the report* | | |" % (len(ordered) - len(shown)))
    return "\n".join(lines)


def skills_detail(session):
    lines = ["| Skill | Source | Tokens |", "|---|---|---:|"]
    for name, tokens in sorted(session.skills.items(), key=lambda item: -item[1]):
        lines.append("| %s | %s | %s |" % (cell(name), cell(skill_source(name)), fmt(tokens)))
    return "\n".join(lines)


def breakdown_parts(session, limit=None, detail=False):
    parts = []
    table = tools_table(session, limit)
    if table:
        parts += ["## Tools by server", "", table, ""]
        if detail:
            parts += ["### Every loaded tool", "", tools_detail(session), ""]
        if session.deferred:
            parts += ["%s deferred tools appear to the agent by name only. Their schemas load when it searches for them, so they use no schema tokens until then. The cost of listing them is the \"Names of tools not loaded yet\" row in the full map." % fmt(len(session.deferred)), ""]
        if session.unavailable_servers:
            parts += ["**Servers the agent was told are unavailable:** %s" % cell(", ".join(session.unavailable_servers)), ""]
    table = skills_table(session, limit)
    if table:
        parts += ["## Skills the agent can see", "", table, ""]
        if detail:
            parts += ["### Every listed skill", "", skills_detail(session), ""]
    return parts


def manager_view(session, limit=5):
    """Mechanical facts about how coherent the agent's brief is. No judgment calls."""
    total = sum(b["tokens"] for b in session.blocks) or 1
    lines = []
    instructions = [b for b in session.blocks if b["section"] in ("CLAUDE.md / AGENTS.md", "Memory")]
    lines.append("- **Standing briefs:** %d instruction or memory source(s), about %s tokens." % (len(instructions), fmt(sum(b["tokens"] for b in instructions))))
    for block in sorted(instructions, key=lambda b: -b["tokens"])[:limit]:
        lines.append("  - %s: about %s tokens" % (block["label"], fmt(block["tokens"])))
    task = sum(b["tokens"] for b in session.blocks if b["section"] == "Your messages")
    harness = sum(b["tokens"] for b in session.blocks if b["section"] in ("System prompt", "Built-in tools", "MCP tools", "Skills available", "MCP server instructions", "Subagents available", "Deferred tool list", "Harness instructions", "Output style", "Environment and session info"))
    lines.append("- **Your words vs the harness:** your messages are about %d%% of context; harness text and tool definitions are about %d%%." % (round(100.0 * task / total), round(100.0 * harness / total)))
    real_turns = [t for t in session.turns if t["kind"] == "you"]
    other_turns = len(session.turns) - len(real_turns)
    lines.append("- **Asks in this session:** %d from you%s." % (len(real_turns), ", %d automated" % other_turns if other_turns else ""))
    areas = session.signals.get("work_areas") or []
    if len(areas) > 1:
        lines.append("- **Work areas mixed in one session:** %d folder/branch combinations." % len(areas))
        for area in areas[:limit]:
            lines.append("  - %s" % area)
    compactions = [e for e in session.events if e["event"] == "compaction"]
    if compactions:
        gone = sum(1 for t in session.turns if not t["in_context"])
        lines.append("- **Forgotten:** %d compaction(s), the last at %s tokens. The original text of %d of %d turns is gone; only the summary remains." % (len(compactions), fmt(compactions[-1].get("pre")), gone, len(session.turns)))
    repeats = session.signals.get("repeats") or []
    if repeats:
        lines.append("- **Told more than once:** %d identical injection(s) were repeated." % len(repeats))
        for label, count, tokens in repeats[:limit]:
            lines.append("  - %s: %d times, about %s tokens each" % (label, count, fmt(tokens)))
    rereads = session.signals.get("rereads") or []
    if rereads:
        lines.append("- **Files read more than once:** %d." % len(rereads))
        for path, count in rereads[:limit]:
            lines.append("  - %s: %d times" % (path, count))
    edits = session.signals.get("external_edits") or []
    if edits:
        lines.append("- **Changed outside the agent:** %d file(s) were edited by someone else mid-session." % len(edits))
        for path, count in edits[:limit]:
            lines.append("  - %s: %d time(s)" % (path, count))
    if session.signals.get("errors"):
        lines.append("- **Failed tool calls:** %d." % session.signals["errors"])
    biggest = sorted((b for b in session.blocks if b["section"] not in GAP_SECTIONS), key=lambda b: -b["tokens"])[:limit]
    lines.append("- **Biggest single items:**")
    for block in biggest:
        lines.append("  - %s (%s): about %s tokens" % (block["section"], one_line(block["label"], 70), fmt(block["tokens"])))
    return "\n".join(lines)


def timeline_table(session, limit=None):
    lines = ["| Turn | You asked | Added | Running total | % of window | Biggest addition |", "|---:|---|---:|---:|---:|---|"]
    events = session.events
    skipped = 0
    if limit:
        turn_events = [e for e in events if e["event"] == "turn"]
        if len(turn_events) > limit:
            first_kept = turn_events[-limit]
            skipped = len(turn_events) - limit
            events = events[events.index(first_kept):]
    if skipped:
        lines.append("| | *%d earlier turns are in the report* | | | | |" % skipped)
    for event in events:
        if event["event"] == "compaction":
            lines.append("| | **Compaction**: %s → %s tokens | | | | |" % (fmt(event.get("pre")), fmt(event.get("post"))))
            continue
        ask = cell(one_line(event["prompt"], 70))
        if event["kind"] != "you":
            ask = "*(%s)* %s" % (cell(event["kind"]), ask)
        if not event["in_context"]:
            ask += " *(compacted away)*"
        added = event["tokens_added"]
        added_text = ("+" + fmt(added) if added >= 0 else "-" + fmt(-added) + " (shrank)") if added is not None else "n/a"
        lines.append("| %d | %s | %s | %s | %s | %s |" % (event["n"], ask, added_text, fmt(event["tokens_end"]), percent_of_window(session, event["tokens_end"]), biggest_addition(event)))
    return "\n".join(lines)


def evidence_line(session):
    if session.coverage:
        matched, count = session.coverage
        return "%s of %s messages were matched by hash to the recorded API request. System prompt and tools come from the same record." % (fmt(matched), fmt(count))
    if session.agent == "Codex":
        return "Text comes from the Codex session log. It is the recorded history, not a byte-checked API request."
    return "Text comes from the session transcript. This log has no recorded API request."


def size_note(session):
    if session.scale:
        return "Totals and per-turn numbers come from the log. Section sizes are estimates that came to more than the real total, so they are scaled by %.2f to match it." % session.scale
    if session.real_total:
        return "Totals and per-turn numbers come from the log. The \"Size from\" column shows how each section was measured. Any gap to the real total has its own row instead of being spread across the others."
    return "No usage numbers were found, so all sizes are rough estimates from text length."


SNAPSHOT_NOTE = "This is a snapshot of the last logged request. The turn that ran this report is not included."


def first_screen(session, self_report):
    parts = [window_gauge(session), "", verdict_line(session), "",
             "**Agent:** %s %s · **Model:** %s · **Session:** `%s`" % (session.agent, session.version or "", session.model or "unknown", session.session_id), "",
             "## What is in its head", "", plain_table(session), "",
             "## Worth doing", "", worth_doing_text(session, limit=5), ""]
    comparison = brief_comparison(session, self_report)
    if comparison:
        parts += ["## Does it understand the job?", "", comparison, ""]
    return parts


def how_sure(session):
    parts = ["## How sure is this?", "", evidence_line(session), "", size_note(session), "", SNAPSHOT_NOTE, ""]
    if session.notes:
        parts += ["- " + n for n in session.notes] + [""]
    return parts


def build_summary(session, self_report, report_path, redactions):
    parts = ["# Context X-ray", ""] + first_screen(session, self_report)
    parts += ["## How the messages built this context", "", timeline_table(session, limit=30), "",
              "## Full context map", "", map_table(session), ""]
    parts += breakdown_parts(session, limit=8)
    parts += ["## Manager's view", "", manager_view(session), ""]
    if self_report:
        parts += ["## Brief-back (self-reported, not verified)", "", self_report.strip(), ""]
    parts += how_sure(session)
    parts += ["**Full report with verbatim text:** `%s`" % report_path, "",
              "Secrets redacted: %s. Reports can still contain private content, so review before sharing." % (redaction_text(redactions))]
    return "\n".join(parts) + "\n"


def redaction_text(counts):
    if counts is None:
        return "redaction was turned off"
    if not counts:
        return "0 matches for known patterns"
    return ", ".join("%d %s" % (v, k) for k, v in counts.most_common())


BASE64_PATTERNS = [
    re.compile(r"data:[\w/+.\-]+;base64,[A-Za-z0-9+/=_\-]{64,}"),
    re.compile(r"(?:iVBORw0KGgo|/9j/4AAQ|R0lGOD|UklGR)[A-Za-z0-9+/=]{64,}"),
    re.compile(r"[A-Za-z0-9+/]{2000,}={0,2}"),
]


def strip_base64(text):
    for pattern in BASE64_PATTERNS:
        text = pattern.sub("[base64 omitted]", text)
    return text


def fence(text):
    runs = re.findall(r"`{3,}", text)
    return "`" * (max([len(r) for r in runs] + [2]) + 1)


def verbatim(block):
    text = block["text"]
    tick = fence(text)
    summary = "%s · about %s tokens · %s" % (one_line(block["label"], 90).replace("<", "&lt;"), fmt(block["tokens"]), block["evidence"])
    return "<details><summary>%s</summary>\n\n%stext\n%s\n%s\n\n</details>\n" % (summary, tick, text, tick)


def turn_detail(event):
    if event["event"] == "compaction":
        return "### Compaction\n\nTrigger: %s. Context went from %s to %s tokens. Turns before this point now exist only as the compaction summary.\n" % (event.get("trigger"), fmt(event.get("pre")), fmt(event.get("post")))
    lines = ["### Turn %d%s" % (event["n"], "" if event["in_context"] else " (compacted away)"), ""]
    who = "You" if event["kind"] == "you" else "Automated (%s)" % event["kind"]
    tick = fence(event["prompt"])
    lines += ["**%s asked:**" % who, "", "%stext\n%s\n%s" % (tick, event["prompt"], tick), ""]
    if event["hidden"]:
        lines.append("**Injected with it (you did not see these):**")
        lines += ["- %s: about %s tokens" % (label, fmt(tokens)) for label, tokens in event["hidden"]]
        lines.append("")
    if event["steps"]:
        lines.append("**Tool calls and results:**")
        for step in event["steps"]:
            result = "about %s tokens back" % fmt(step["result_tokens"]) if step["result_tokens"] is not None else "no result logged"
            lines.append("- `%s` %s → %s%s" % (step["name"], step["summary"], result, " **(error)**" if step["error"] else ""))
        lines.append("")
    if event["thinking"]:
        lines += ["**Thinking blocks:** %d (text not recoverable from the log unless shown in the appendix)." % event["thinking"], ""]
    answer = "\n\n".join(a for a in event["answer"] if a.strip())
    if answer:
        tick = fence(answer)
        lines += ["**Agent answered:**", "", "%stext\n%s\n%s" % (tick, answer, tick), ""]
    added = "n/a" if event["tokens_added"] is None else fmt(event["tokens_added"])
    lines += ["**Tokens added:** %s · **Running total:** %s" % (added, fmt(event["tokens_end"])), ""]
    return "\n".join(lines)


def build_report(session, self_report, redactions_placeholder="{{REDACTIONS}}"):
    parts = ["# Context X-ray report", ""] + checkin_lines(session, self_report)
    parts += ["- **Agent:** %s %s" % (session.agent, session.version or ""),
              "- **Model:** %s" % (session.model or "unknown"),
              "- **Session:** `%s`" % session.session_id,
              "- **Working directory:** `%s`" % (session.cwd or "unknown"),
              "- **Log file:** `%s`" % session.path,
              "- **Generated:** %s" % dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
              "- **Secrets redacted:** %s" % redactions_placeholder, "",
              "> This report can contain private content such as instruction files and tool output. Pattern-based redaction misses things, so review before sharing.", ""]
    if self_report:
        parts += ["## What it said back (self-reported, not verified)", "", "The agent wrote this before seeing any of this report.", "", self_report.strip(), ""]
    story, story_ids = story_parts(session)
    parts += story
    parts += ["# Appendix", "", "## Size figures include this check-in", "", "The gauge at the top is measured from before this check-in began. The tables below use the last logged request.", "",
              "## All suggestions", "", worth_doing_text(session), "",
              "## How the messages built this context", "", timeline_table(session), "",
              "## Full context map", "", map_table(session), ""]
    parts += breakdown_parts(session, detail=True)
    parts += ["## Manager's view", "", "These are mechanical facts from the log, not a score.", "", manager_view(session, limit=15), ""]
    parts += how_sure(session)
    parts += ["### What the labels mean", "",
              "- **request log:** text recorded as part of the API request the agent sent.",
              "- **session log:** text recorded in the session log, not checked against a request.",
              "- **self-reported:** the agent said this about itself. It cannot be verified.",
              "- **not recorded:** the log does not contain it.", "",
              "## Turn by turn", ""]
    parts += [turn_detail(event) for event in session.events]
    parts += ["## Verbatim: everything else it loaded", ""]
    grouped = section_rows(session)
    for name, members in grouped.items():
        standing = [m for m in members if m["group"] == BEFORE and id(m) not in story_ids]
        if standing:
            parts += ["### %s" % name, ""] + [verbatim(m) for m in standing]
    parts += ["## Verbatim: the rest of the conversation", ""]
    parts += ["**%s** (%s)\n\n%s" % (b["section"], b["role"] or "?", verbatim(b)) for b in session.blocks if b["group"] == CONVO and id(b) not in story_ids]
    return "\n".join(parts) + "\n"


# ------------------------------------------------------------- the check-in

ACK_LINE = re.compile(r"^(\d+[.)]\s*)?(yes|yep|yeah|ok|okay|sure|no|nope|continue|go ahead|do it|sounds good|thanks|thank you|agreed|great|perfect|looks good|please do|your recommendation)\b", re.I)
APP_SERVERS = ("ccd_", "Claude_")
INTERNAL_TOOLS = ("TodoWrite", "ToolSearch", "Skill", "AskUserQuestion", "advisor", "ExitPlanMode", "EnterPlanMode")
WRITE_COMMAND = re.compile(r"(>|\bsed -i|\bmv\b|\bcp\b|\brm\b|\bmkdir\b|\btouch\b|\btee\b|\bgit (commit|apply|checkout|switch|merge)|<<|\bnpm (install|i)\b|\bpip install\b)")
SELF_RUN = "context_xray.py"


def is_acknowledgement(text):
    """Short replies such as 'Yes, build it' say nothing about what the job is."""
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return bool(lines) and all(ACK_LINE.match(line) for line in lines) and all(len(line) < 90 for line in lines[:1] if len(lines) == 1)


def is_checkin_turn(turn):
    if turn["prompt"].lstrip().startswith("/context-xray"):
        return True
    for step in turn["steps"]:
        if step["name"] == "Skill" and "context-xray" in (step["summary"] or ""):
            return True
        if SELF_RUN in (step.get("command") or ""):
            return True
    return False


def work_turns(session):
    """Turns before this check-in, so the report does not describe itself."""
    turns = session.turns
    for index in range(len(turns) - 1, -1, -1):
        if is_checkin_turn(turns[index]):
            return turns[:index]
    return turns


def checkin_total(session):
    """Context size as it was before this check-in began."""
    work = work_turns(session)
    if len(work) == len(session.turns):
        return session.real_total
    ended = [t["tokens_end"] for t in work if t["tokens_end"] is not None]
    if ended:
        return ended[-1]
    return session.first_total or session.real_total


def plural(count, word):
    return "%d %s%s" % (count, word, "" if count == 1 else "s")


def brief_items(text):
    """Read a brief-back section as a list, whether it is bullets, numbers or prose."""
    if not text.strip():
        return []
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if any(re.match(r"([-*]|\d+[.)])\s", line) for line in lines):
        items = [re.sub(r"^([-*]|\d+[.)])\s+", "", line) for line in lines if re.match(r"([-*]|\d+[.)])\s", line)]
    else:
        items = [" ".join(lines)]
    return [i for i in items if not re.match(r"^(none|n/?a|nothing)\b", i, re.I)]


def parse_brief(brief):
    if not brief or not brief.strip():
        return None
    job = brief_section(brief, "Job") or brief_section(brief, "Current job")
    if not job:
        first = next((line.strip() for line in brief.splitlines() if line.strip() and not line.lstrip().startswith("#")), "")
        job = first
    return {
        "job": one_line(job, 150),
        "plan": one_line(brief_section(brief, "Next step"), 150),
        "assumptions": brief_items(brief_section(brief, "Assumptions") or brief_section(brief, "Unclear or assumed")),
        "conflicts": brief_items(brief_section(brief, "Conflicts")),
    }


def no_task(parsed):
    return bool(parsed) and re.match(r"^no task", parsed["job"], re.I) is not None


def memory_share(session):
    total = checkin_total(session)
    return float(total) / session.window if total and session.window else None


def checkin_gauge(session):
    total = checkin_total(session)
    if total is None:
        return "**The log has no size numbers for this chat.**"
    if not session.window:
        return "**The agent is holding %s tokens.** I can't tell how much room it has left." % fmt(total)
    filled = min(24, int(round(24.0 * total / session.window)))
    bar = "`%s%s`" % ("█" * filled, "░" * (24 - filled))
    percent = 100.0 * total / session.window
    if total > session.window:
        return "%s **The agent's memory is over its listed limit** (%s of %s tokens)" % (bar, fmt(total), fmt(session.window))
    return "%s **The agent's memory is %.1f%% full** (%s of %s tokens)" % (bar, percent, fmt(total), fmt(session.window))


def next_move(session, parsed):
    """Return the headline. Priority: start fresh, then fix its picture, then carry on."""
    share = memory_share(session)
    compactions = sum(1 for e in session.events if e["event"] == "compaction")
    lost = sum(1 for t in session.turns if not t["in_context"] and t["kind"] == "you")
    if (share is not None and share >= 0.85) or compactions >= 2:
        reasons = []
        if share is not None and share >= 0.85:
            reasons.append("It's %d%% full" % round(100 * share))
        if lost:
            reasons.append("has forgotten %s" % plural(lost, "of your earlier message").replace("message", "messages", 1) if lost != 1 else "has forgotten 1 of your earlier messages")
        reason = " and ".join(reasons) or "It has been through several rounds of forgetting"
        reason = reason[0].upper() + reason[1:]
        return "**Start a new chat, or run `/compact`.** %s." % reason, "reset"
    if parsed and not no_task(parsed):
        concerns = parsed["conflicts"] + parsed["assumptions"]
        if concerns:
            first = one_line(concerns[0], 170).rstrip(".")
            if len(concerns) == 1:
                return "**Tell it one thing before it continues.** %s. If that's wrong, say so now." % first, "correct"
            return "**Check %d things before it continues.** %s. Also: %s. If either is wrong, say so now." % (min(len(concerns), 2), first, one_line(concerns[1], 170).rstrip(".")), "correct"
    if parsed is None and not session.live:
        return "**This is a past chat, so it can't say what it was thinking.** Below is what the log shows it knew.", "past"
    if parsed is None:
        return "**It didn't say back its job, so check its work before giving it more.**", "unknown"
    if no_task(parsed):
        return "**You can give it the next task.** It hasn't been given one yet and has plenty of room.", "continue"
    if share is not None and share >= 0.6:
        return "**You can give it the next task, but start a new chat soon.** It's %d%% full." % round(100 * share), "continue"
    if compactions:
        return "**You can give it the next task, but check what it forgot.** %s can't be read in full anymore." % plural(lost, "earlier message"), "continue"
    return "**You can give it the next task.** It has the right picture of the job and plenty of room left.", "continue"


def display_path(session, path):
    if session.cwd and path.startswith(session.cwd.rstrip("/") + "/"):
        return path[len(session.cwd.rstrip("/")) + 1:]
    return os.path.basename(path)


def format_items(items, limit=8):
    """At most `limit` names, grouped by folder when that fits, always saying what was left out."""
    if len(items) <= limit:
        return ["`%s`" % i for i in items]
    folders = collections.OrderedDict()
    for item in items:
        folders[os.path.dirname(item) or "."] = folders.get(os.path.dirname(item) or ".", 0) + 1
    if 1 < len(folders) <= limit or (len(folders) == 1 and "." not in folders):
        return ["`%s/` (%s)" % (folder, plural(count, "file")) if folder != "." else plural(count, "other file") for folder, count in folders.items()]
    return ["`%s`" % i for i in items[:limit]] + ["+%d more" % (len(items) - limit)]


def knowledge_map(session):
    work = work_turns(session)
    current = [t for t in work if t["in_context"]]
    reads, changed, commands, maybe_changed, web, other, skills = [], [], [], 0, 0, 0, []
    steps = [step for turn in reversed(current) for step in reversed(turn["steps"])]
    for step in steps:
        name = step["name"] or ""
        command = step.get("command") or ""
        for path in step.get("changed") or []:
            shown = display_path(session, path)
            if shown not in changed:
                changed.append(shown)
        if name == "Skill":
            skills.append(one_line(step["summary"], 40))
        elif name == "Read" and step.get("path"):
            shown = display_path(session, step["path"])
            if shown not in reads:
                reads.append(shown)
        elif name in ("WebFetch", "WebSearch"):
            web += 1
        elif name == "Bash" or "shell" in name.lower() or "exec" in name.lower() and not step.get("changed"):
            commands.append(one_line(step["summary"] or command, 40))
            maybe_changed += 1 if WRITE_COMMAND.search(command) else 0
        elif not (name in EDIT_TOOLS or name in INTERNAL_TOOLS or name.startswith("mcp__ccd_") or step.get("changed")):
            other += 1
    for block in session.blocks:
        if block["section"] == "Files attached" and block["label"].startswith(("File attachment", "@ mention")) and ": " in block["label"]:
            shown = display_path(session, block["label"].split(": ", 1)[1])
            if shown not in reads:
                reads.append(shown)

    told = [t for t in current if t["kind"] == "you"]
    instructions = []
    for block in session.blocks:
        if block["section"] == "CLAUDE.md / AGENTS.md":
            name = "AGENTS.md" if "AGENTS" in block["label"] else "CLAUDE.md"
            owner = "the project's" if "(project)" in block["label"] else "your"
            entry = "%s `%s`" % (owner, name)
            if entry not in instructions:
                instructions.append(entry)
        elif block["section"] == "Memory" and "notes saved from earlier chats" not in instructions:
            instructions.append("notes saved from earlier chats")
    unique_skills = list(dict.fromkeys(skills))
    instructions += ["the `%s` skill" % s for s in unique_skills[:3]]
    if len(unique_skills) > 3:
        instructions.append("%d more skills" % (len(unique_skills) - 3))

    read_parts = format_items(reads)
    if commands:
        if session.agent == "Codex":
            read_parts.append("%s (latest: %s)" % (plural(len(commands), "command"), ", ".join("`%s`" % c for c in commands[:3])))
        else:
            read_parts.append(plural(len(commands), "command result"))
    if web:
        read_parts.append(plural(web, "web page"))
    if other:
        read_parts.append(plural(other, "result") + " from other tools")
    changed_parts = format_items(changed)
    if maybe_changed:
        changed_parts.append(plural(maybe_changed, "command") + " that may have changed files")

    lost = [t for t in session.turns if not t["in_context"] and t["kind"] == "you"]
    return {
        "told": plural(len(told), "message") if told else "nothing yet",
        "instructions": ", ".join(instructions) or "none",
        "read": ", ".join(read_parts) or "nothing yet",
        "changed": ", ".join(changed_parts) or "nothing yet",
        "lost": "%s (only a summary remains)" % plural(len(lost), "of your earlier message").replace("message", "messages", 1) if len(lost) > 1 else ("1 of your earlier messages (only a summary remains)" if lost else "nothing"),
    }


def last_request(session):
    """The most recent message that actually asks for something."""
    asks = [t for t in work_turns(session) if t["kind"] == "you"]
    later = 0
    for turn in reversed(asks):
        if not is_acknowledgement(turn["prompt"]):
            return one_line(turn["prompt"], 130), later
        later += 1
    return (one_line(asks[-1]["prompt"], 130), 0) if asks else ("", 0)


def why_full(session):
    total = sum(b["tokens"] for b in session.blocks) or 1
    setup = sum(b["tokens"] for b in session.blocks if b["section"] in PLAIN_GROUPS[0][1])
    share = int(round(100.0 * setup / total))
    if share >= 90:
        return "**Why it's that full:** Almost all of it (%d%%) is built-in instructions and tools that load before you type anything. Only %d%% is from this chat." % (share, 100 - share)
    if share >= 50:
        return "**Why it's that full:** Most of it (%d%%) is built-in instructions and tools that load before you type anything. The other %d%% is from this chat." % (share, 100 - share)
    return "**Why it's that full:** Most of it (%d%%) is from this chat. The other %d%% is built-in instructions and tools that load before you type anything." % (100 - share, share)


def server_names(session):
    """Turn opaque server ids into names, using the first words of their instructions."""
    names = {}
    for block in session.blocks:
        if block["section"] == "MCP server instructions":
            for server, line in re.findall(r"(?m)^## (\S+)\n+(.+)", block["text"]):
                match = re.match(r"(?:(?:The|An?|Official|official)\s+)*([A-Z][\w-]*(?:\s+[A-Z][\w-]*)*)", line)
                if match and not match.group(1).startswith("Use"):
                    names[server] = re.sub(r"\s+(MCP|Server|Proxy)\b.*$", "", match.group(1))
    return names


def setup_items(session):
    """Removable tools and plugins nobody used in this chat, biggest first."""
    if session.agent != "Claude Code":
        return []
    used = {step["name"] for turn in session.turns for step in turn["steps"]}
    named = server_names(session)
    servers = collections.OrderedDict()
    for block in session.blocks:
        if block["section"] == "MCP tools" and block["evidence"] != EV_NONE:
            servers.setdefault(tool_server(block["label"])[0], []).append(block)
    items = []
    for server, members in servers.items():
        tokens = sum(m["tokens"] for m in members)
        if tokens >= 500 and not server.startswith(APP_SERVERS) and not any(m["label"] in used for m in members):
            items.append((tokens, named.get(server, server), plural(len(members), "tool")))
    used_skills = {step["summary"] for turn in session.turns for step in turn["steps"] if step["name"] == "Skill"}
    sources = collections.OrderedDict()
    for name, tokens in session.skills.items():
        sources.setdefault(skill_source(name), []).append((name, tokens))
    for source, members in sources.items():
        tokens = sum(m[1] for m in members)
        if tokens >= 500 and source != "user or built-in" and not any(m[0] in used_skills for m in members):
            items.append((tokens, source, plural(len(members), "skill")))
    return sorted(items, key=lambda item: -item[0])


def setup_pointer(session):
    used = checkin_total(session) or 0
    spare = sum(item[0] for item in setup_items(session))
    if used and spare >= max(0.10 * used, 5000):
        return "**You could free up space:** about %d%% of this is tools you aren't using. Run `/context-xray setup` to see which." % round(100.0 * spare / used)
    return ""


def incomplete_note(session):
    if session.agent != "Claude Code":
        return ""
    if not session.coverage:
        return "**Heads up:** this version of Claude Code doesn't record everything it loads, so some of this is missing. Updating it should fix that."
    matched, count = session.coverage
    if count and float(matched) / count < 0.9:
        return "**Heads up:** %d of %d messages couldn't be recovered from the log, so some of this is missing." % (count - matched, count)
    return ""


def checkin_lines(session, brief):
    parsed = parse_brief(brief)
    headline, move = next_move(session, parsed)
    lines = [checkin_gauge(session), "", headline, ""]
    if move == "reset":
        keep = (parsed["job"] if parsed else last_request(session)[0]).replace("`", "")
        lines += ["**Paste this:** `/compact Keep: %s`" % one_line(keep, 110), ""]
    if parsed and not no_task(parsed):
        asked, later = last_request(session)
        lines += ["**What it thinks it's doing**"]
        if asked:
            lines.append("- **You asked:** %s%s" % (asked, " (plus %s)" % plural(later, "later reply").replace("replys", "replies") if later else ""))
        lines.append("- **It thinks its job is:** %s" % parsed["job"])
        if parsed["plan"]:
            lines.append("- **It plans to:** %s" % parsed["plan"])
        lines.append("")
    known = knowledge_map(session)
    lines += ["**What it knows**",
              "- **You told it:** %s" % known["told"],
              "- **Instructions it loaded:** %s" % known["instructions"],
              "- **It has read:** %s" % known["read"],
              "- **It has changed:** %s" % known["changed"],
              "- **It has forgotten:** %s" % known["lost"], "",
              why_full(session), ""]
    for extra in (setup_pointer(session), incomplete_note(session)):
        if extra:
            lines += [extra, ""]
    return lines


def build_checkin(session, brief):
    lines = ["**Context X-ray**", ""] + checkin_lines(session, brief)
    lines += ["Ask me to show anything it read, or open the [full report]({{REPORT}})."]
    return "\n".join(lines) + "\n"


def memory_cost(session, tokens):
    if session.window:
        return "%.1f%% of its memory" % (100.0 * tokens / session.window)
    return "about %s" % short_tokens(tokens)


def build_setup(session):
    items = setup_items(session)
    lines = ["**Context X-ray: your setup**", ""]
    if items:
        lines += ["**Loaded in this chat but never used**"]
        lines += ["- **%s** (%s): %s" % (name, what, memory_cost(session, tokens)) for tokens, name, what in items[:10]]
        if len(items) > 10:
            lines.append("- +%d more" % (len(items) - 10))
        lines += ["", "Turn these off for chats that don't need them.", ""]
    else:
        lines += ["Nothing removable stands out in this chat.", ""]
    built_in = sum(b["tokens"] for b in session.blocks if b["section"] == "Built-in tools")
    if built_in:
        lines += ["Built-in tools take up %s. They come with the agent and usually can't be removed." % memory_cost(session, built_in), ""]
    for block in session.blocks:
        if block["section"] in ("CLAUDE.md / AGENTS.md", "Memory") and block["tokens"] >= 2000:
            lines += ["`%s` takes up %s and loads in every chat, so trim anything you don't need every time." % (os.path.basename(block["label"].split(" (")[0]), memory_cost(session, block["tokens"])), ""]
    return "\n".join(lines).rstrip() + "\n"


SHOW_LIMIT = 3000
SHOW_SECTIONS = ("Tool results", "Files attached", "CLAUDE.md / AGENTS.md", "Memory", "Your messages", "Skills loaded", "Compaction summary", "Assistant text")


def build_show(session, query):
    """Print one item's exact text, capped, so a follow-up never loads the whole report."""
    wanted = query.lower()
    candidates = [b for b in reversed(session.blocks) if b["section"] in SHOW_SECTIONS]
    by_name = [b for b in candidates if wanted in (b["label"] + " " + (b.get("detail") or "")).lower()]
    matches = (by_name or [b for b in candidates if wanted in b["text"].lower()])[:2]
    if not matches:
        return "Nothing it currently holds matches \"%s\". It may have been forgotten, so check the full report.\n" % query
    parts = []
    for block in matches:
        text = block["text"]
        shown = text[:SHOW_LIMIT]
        tick = fence(shown)
        parts.append("**%s**\n\n%stext\n%s\n%s" % (one_line(block.get("detail") or block["label"], 90), tick, shown, tick))
        if len(text) > SHOW_LIMIT:
            parts.append("Showing the first %s of %s characters. The rest is in the full report." % (fmt(SHOW_LIMIT), fmt(len(text))))
    return "\n\n".join(parts) + "\n"


def story_parts(session):
    """The report's main body: the same order as the check-in, with exact text."""
    told = [b for b in session.blocks if b["section"] == "Your messages"]
    instructions = [b for b in session.blocks if b["section"] in ("CLAUDE.md / AGENTS.md", "Memory", "Skills loaded")]
    read = [b for b in session.blocks if b["section"] in ("Tool results", "Files attached")]
    changed = [b for b in session.blocks if b["section"] == "Tool calls" and b["label"] in EDIT_TOOLS]
    summaries = [b for b in session.blocks if b["section"] == "Compaction summary"]
    parts = []
    for title, members in (("You told it", told), ("Instructions it loaded", instructions), ("It has read", read), ("It has changed", changed)):
        parts += ["## %s" % title, ""]
        parts += [verbatim(dict(m, label=m.get("detail") or m["label"])) for m in members] or ["Nothing.", ""]
    parts += ["## It has forgotten", ""]
    lost = [t for t in session.turns if not t["in_context"]]
    parts += ["- %s" % one_line(t["prompt"], 200) for t in lost] + ([""] if lost else ["Nothing.", ""])
    parts += [verbatim(m) for m in summaries]
    story = {id(m) for group in (told, instructions, read, changed, summaries) for m in group}
    return parts, story


def default_out(session_id):
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return os.path.join(os.path.expanduser("~/.context-xray/reports"), "%s-%s.md" % (stamp, re.sub(r"[^\w-]", "_", session_id)[:40]))


def write_private(path, text):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, mode=0o700, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", errors="replace") as handle:
        handle.write(text)


def read_self_report(path):
    if not path:
        return None
    with open(path, errors="replace") as handle:
        return handle.read()


NO_LOG_HELP = """context-xray found no session log for this agent.

Nothing here can be verified. Follow the "No log found" section of SKILL.md: write a
self-report, then re-run with --self-report-only FILE so it is redacted, saved and
labeled as unverified.
"""


def self_report_only(args):
    text = read_self_report(args.self_report_only)
    body = "# Context X-ray report (self-reported only)\n\n> **Nothing in this report is verified.** No session log was available, so everything below is the agent describing its own context from memory. It may be incomplete or wrong.\n\n- **Secrets redacted:** {{REDACTIONS}}\n\n" + text.strip() + "\n"
    return finish(body, body, args, "self-report")


def finish(report, summary, args, session_id):
    out = args.out or default_out(session_id)
    report, summary = strip_base64(report), strip_base64(summary)
    summary = summary.replace("{{REPORT}}", out)
    if args.no_redact:
        counts = None
        report = report.replace("{{REDACTIONS}}", "redaction was turned off")
        summary = summary.replace("{{REDACTIONS}}", "redaction was turned off")
    else:
        report, counts = redact(report)
        summary, _ = redact(summary)
        report = report.replace("{{REDACTIONS}}", redaction_text(counts))
        summary = summary.replace("{{REDACTIONS}}", redaction_text(counts))
    write_private(out, report)
    sys.stdout.write(summary)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Show what is in a coding agent's context, from its session log.")
    parser.add_argument("--agent", choices=["auto", "claude", "codex"], default="auto")
    parser.add_argument("--session", help="Session id (defaults to the current session)")
    parser.add_argument("--log", help="Path to a session log file")
    parser.add_argument("--cwd", help="Project directory used to find the session")
    parser.add_argument("--out", help="Report path (default: ~/.context-xray/reports/)")
    parser.add_argument("--self-report", help="File with the agent's brief-back, included and labeled unverified")
    parser.add_argument("--self-report-only", help="No log available: save this file as an unverified report")
    parser.add_argument("--setup", action="store_true", help="Show what installed tools and plugins cost")
    parser.add_argument("--show", help="Print the exact text of one item the agent holds")
    parser.add_argument("--full", action="store_true", help="Print the long detailed summary instead of the check-in")
    parser.add_argument("--window", type=int, help="Context window size in tokens, if the log does not state it")
    parser.add_argument("--no-redact", action="store_true", help="Turn off secret redaction")
    args = parser.parse_args(argv)

    if args.self_report_only:
        return self_report_only(args)
    agent, path = detect(args)
    if not path:
        sys.stderr.write(NO_LOG_HELP)
        return 3
    session = parse_claude(path) if agent == "claude" else parse_codex(path)
    if args.window:
        session.window, session.window_source = args.window, "flag"
    session.live = not args.log
    if args.setup or args.show:
        text = build_setup(session) if args.setup else build_show(session, args.show)
        text = strip_base64(text)
        sys.stdout.write(text if args.no_redact else redact(text)[0])
        return 0
    brief = read_self_report(args.self_report)
    report = build_report(session, brief)
    if args.full:
        summary = build_summary(session, brief, "{{REPORT}}", collections.Counter())
        summary = re.sub(r"Secrets redacted: .*?\. Reports", "Secrets redacted: {{REDACTIONS}}. Reports", summary)
    else:
        summary = build_checkin(session, brief)
    return finish(report, summary, args, session.session_id)


if __name__ == "__main__":
    sys.exit(main())
