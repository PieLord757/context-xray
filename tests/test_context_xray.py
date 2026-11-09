import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "skills", "context-xray", "scripts"))
import context_xray as cx  # noqa: E402

# Built at runtime so secret scanners do not flag this file.
FAKE_GITHUB = "ghp_" + "a1B2" * 9
FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
FAKE_ANTHROPIC = "sk-ant-" + "abcDEF123456" * 3


def write_jsonl(directory, name, rows):
    path = os.path.join(directory, name)
    with open(path, "w") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
        handle.write("not json at all\n")
    return path


def claude_rows(with_requests=True, compaction=False):
    user_one = {"role": "user", "content": [{"type": "text", "text": "Fix the login bug please"}]}
    assistant = {"role": "assistant", "id": "m1", "model": "claude-test", "content": [{"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "/repo/a.py"}}], "usage": {"input_tokens": 10, "cache_read_input_tokens": 900, "cache_creation_input_tokens": 90}}
    result = {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "print('hello') token=" + FAKE_GITHUB}]}
    answer = {"role": "assistant", "id": "m2", "model": "claude-test", "content": [{"type": "text", "text": "Fixed it."}], "usage": {"input_tokens": 5, "cache_read_input_tokens": 1000, "cache_creation_input_tokens": 195}}
    instructions = {"type": "instructions", "files": [{"path": "/home/x/.claude/CLAUDE.md", "type": "User", "content": "Always write tests."}, {"path": "/home/x/.claude/memory/MEMORY.md", "type": "AutoMem", "content": "User likes short answers."}]}
    rendered = "<system-reminder>Always write tests.\nUser likes short answers.</system-reminder>"
    rows = [
        {"type": "user", "uuid": "u1", "parentUuid": None, "message": user_one, "cwd": "/repo", "gitBranch": "main", "version": "9.9.9", "origin": {"kind": "human"}},
        {"type": "attachment", "uuid": "a1", "parentUuid": "u1", "attachment": instructions, "rendered": [{"content": rendered}]},
        {"type": "assistant", "uuid": "as1", "parentUuid": "a1", "message": assistant},
        {"type": "attachment", "uuid": "a2", "parentUuid": "as1", "attachment": {"type": "output_style"}, "rendered": [{"content": "<system-reminder>Be concise</system-reminder>"}]},
        {"type": "user", "uuid": "u2", "parentUuid": "a2", "message": result},
        {"type": "attachment", "uuid": "a3", "parentUuid": "u2", "attachment": {"type": "output_style"}, "rendered": [{"content": "<system-reminder>Be concise</system-reminder>"}]},
        {"type": "assistant", "uuid": "as2", "parentUuid": "a3", "message": answer},
        {"type": "user", "uuid": "side", "parentUuid": "as2", "isSidechain": True, "message": {"role": "user", "content": "subagent private task"}},
    ]
    last = "as2"
    if with_requests:
        rows.insert(7, {"type": "user", "uuid": "meta", "parentUuid": "as2", "isMeta": True, "message": {"role": "user", "content": "Base directory for this skill: /x"}})
        rows.insert(8, {"type": "user", "uuid": "bot", "parentUuid": "meta", "origin": {"kind": "task-notification"}, "message": {"role": "user", "content": "<task-notification>agent finished</task-notification>"}})
    if compaction:
        rows += [
            {"type": "system", "subtype": "compact_boundary", "uuid": "cb", "parentUuid": None, "logicalParentUuid": last, "compactMetadata": {"trigger": "auto", "preTokens": 1200, "postTokens": 200}},
            {"type": "user", "uuid": "cs", "parentUuid": "cb", "isCompactSummary": True, "message": {"role": "user", "content": "Summary: fixed login."}},
            {"type": "user", "uuid": "u3", "parentUuid": "cs", "message": {"role": "user", "content": "Now add a test"}, "origin": {"kind": "human"}},
            {"type": "assistant", "uuid": "as3", "parentUuid": "u3", "message": {"role": "assistant", "id": "m3", "model": "claude-test", "content": [{"type": "text", "text": "Added."}], "usage": {"input_tokens": 1, "cache_read_input_tokens": 300, "cache_creation_input_tokens": 9}}},
        ]
    if with_requests:
        wire = lambda m: {"role": m["role"], "content": m["content"]}
        first = {"role": "user", "content": [{"type": "text", "text": rendered}, {"type": "text", "text": "Fix the login bug please"}]}
        skill = {"role": "user", "content": [{"type": "text", "text": "Base directory for this skill: /x"}]}
        note = {"role": "user", "content": [{"type": "text", "text": "<task-notification>agent finished</task-notification>"}]}
        hashes = [cx.wire_hash(first), cx.wire_hash(wire(assistant)), cx.wire_hash(wire(result)), cx.wire_hash(wire(answer)), cx.wire_hash(skill), cx.wire_hash(note)]
        rows += [
            {"type": "api-request-shape", "shapeHash": "s1", "shape": {"system": [{"type": "text", "text": "You are a coding agent."}], "tools": [{"name": "Read", "description": "Reads", "input_schema": {}}, {"name": "Later", "description": "Deferred", "defer_loading": True, "input_schema": {}}]}},
            {"type": "api-request-blob", "hash": hashes[0], "message": first},
            {"type": "api-request", "id": "r1", "querySource": "sdk", "shapeHash": "s1", "keep": 0, "tail": hashes[:1]},
            {"type": "api-request", "id": "r2", "querySource": "sdk", "shapeHash": "s1", "keep": 1, "tail": hashes[1:] + ["0" * 64]},
            {"type": "api-request-blob", "hash": hashes[4], "message": skill},
            {"type": "api-request-blob", "hash": hashes[5], "message": note},
            {"type": "api-request", "id": "t", "querySource": "title", "shapeHash": "s1", "keep": 0, "tail": []},
        ]
    return rows


def codex_rows():
    item = lambda payload: {"type": "response_item", "payload": payload}
    message = lambda role, text: item({"type": "message", "role": role, "content": [{"type": "input_text" if role != "assistant" else "output_text", "text": text}]})
    return [
        {"type": "session_meta", "payload": {"id": "abc", "cli_version": "1.2.3", "cwd": "/repo", "base_instructions": {"text": "You are Codex."}}},
        {"type": "turn_context", "payload": {"model": "gpt-test", "cwd": "/repo"}},
        message("developer", "<permissions>sandboxed</permissions>"),
        message("user", "# AGENTS.md instructions\nUse pnpm."),
        message("user", "Add a health check"),
        item({"type": "function_call", "name": "shell", "arguments": json.dumps({"cmd": "ls"}), "call_id": "c1"}),
        item({"type": "function_call_output", "call_id": "c1", "output": "a.py"}),
        item({"type": "reasoning", "encrypted_content": "x" * 80}),
        {"type": "event_msg", "payload": {"type": "token_count", "info": {"last_token_usage": {"input_tokens": 5000}, "model_context_window": 100000}}},
        message("assistant", "Done."),
        message("developer", "<permissions>sandboxed</permissions>"),
    ]


class Redaction(unittest.TestCase):
    def test_known_secrets_removed(self):
        text = "a %s b %s c %s password=hunter2hunter Authorization: Bearer abcdefghijklmnopqrstuvwx https://me:pass1234@host/x" % (FAKE_GITHUB, FAKE_AWS, FAKE_ANTHROPIC)
        out, counts = cx.redact(text)
        for secret in (FAKE_GITHUB, FAKE_AWS, FAKE_ANTHROPIC, "hunter2hunter", "abcdefghijklmnopqrstuvwx", "pass1234"):
            self.assertNotIn(secret, out)
        self.assertGreaterEqual(sum(counts.values()), 6)

    def test_private_key_block(self):
        out, _ = cx.redact("-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----")
        self.assertNotIn("abc", out)

    def test_ordinary_text_untouched(self):
        text = "Run the tests and keep the token budget small. The secret to good code is review."
        self.assertEqual(cx.redact(text)[0], text)


class Base64(unittest.TestCase):
    def test_embedded_image_removed(self):
        text = "x data:image/png;base64," + "QUJD" * 40 + " y"
        self.assertEqual(cx.strip_base64(text), "x [base64 omitted] y")


class Claude(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def sections(self, session):
        return {b["section"] for b in session.blocks}

    def test_rebuilds_request_with_labels(self):
        session = cx.parse_claude(write_jsonl(self.tmp.name, "s.jsonl", claude_rows()))
        self.assertEqual(session.real_total, 1200)
        self.assertAlmostEqual(sum(b["tokens"] for b in session.blocks), 1200, delta=60)
        self.assertLessEqual({"System prompt", "Built-in tools", "CLAUDE.md / AGENTS.md", "Memory", "Your messages"}, self.sections(session))
        self.assertEqual({b["evidence"] for b in session.blocks if b["section"] not in cx.GAP_SECTIONS}, {cx.EV_REQUEST})
        self.assertEqual(sum(1 for b in session.blocks if b["section"] == "Built-in tools"), 1)

    def test_only_typed_text_counts_as_your_messages(self):
        session = cx.parse_claude(write_jsonl(self.tmp.name, "s.jsonl", claude_rows()))
        yours = [b["text"] for b in session.blocks if b["section"] == "Your messages"]
        self.assertEqual(yours, ["Fix the login bug please"])
        skills = [b["text"] for b in session.blocks if b["section"] == "Skills loaded"]
        self.assertEqual(skills, ["Base directory for this skill: /x"])
        hidden = [b["label"] for b in session.blocks if b["section"] == "Hidden injections"]
        self.assertIn("task-notification", hidden)

    def test_standing_sections_are_not_inflated_to_fill_the_total(self):
        session = cx.parse_claude(write_jsonl(self.tmp.name, "s.jsonl", claude_rows()))
        system = next(b for b in session.blocks if b["section"] == "System prompt")
        self.assertIsNone(session.scale)
        self.assertEqual(system["tokens"], cx.estimate("You are a coding agent."))
        gaps = sum(b["tokens"] for b in session.blocks if b["section"] in cx.GAP_SECTIONS)
        self.assertEqual(gaps, 1200 - sum(b["tokens"] for b in session.blocks if b["section"] not in cx.GAP_SECTIONS))

    def test_gap_on_first_request_is_standing_context(self):
        wire = {"role": "user", "content": [{"type": "text", "text": "OK please"}]}
        digest = cx.wire_hash(wire)
        path = write_jsonl(self.tmp.name, "s.jsonl", [
            {"type": "user", "uuid": "u", "parentUuid": None, "origin": {"kind": "human"}, "message": wire},
            {"type": "assistant", "uuid": "a", "parentUuid": "u", "message": {"role": "assistant", "id": "m", "content": [], "usage": {"input_tokens": 500}}},
            {"type": "api-request-shape", "shapeHash": "s", "shape": {"system": [{"type": "text", "text": "x" * 300}], "tools": []}},
            {"type": "api-request-blob", "hash": digest, "message": wire},
            {"type": "api-request", "id": "r", "querySource": "sdk", "shapeHash": "s", "keep": 0, "tail": [digest]},
        ])
        session = cx.parse_claude(path)
        gap = next(b for b in session.blocks if b["section"] == cx.STANDING_GAP)
        self.assertEqual(gap["group"], cx.BEFORE)
        self.assertFalse(any(b["section"] == cx.UNATTRIBUTED for b in session.blocks))
        self.assertGreater(gap["tokens"], 300)

    def test_output_usage_replaces_estimates(self):
        session = cx.Session("Claude Code", "x.jsonl")
        session.add("Thinking", "Thinking", "[hidden]", cx.EV_REQUEST, cx.CONVO, tokens=5)
        session.add("Tool calls", "Read", "x" * 300, cx.EV_REQUEST, cx.CONVO)
        session.apply_output_usage(300, 200)
        session.real_total = 300
        session.finalize()
        tokens = {b["section"]: b["tokens"] for b in session.blocks}
        self.assertEqual((tokens["Thinking"], tokens["Tool calls"]), (200, 100))
        self.assertIn("provider usage", cx.map_table(session))

    def test_tool_and_skill_breakdowns(self):
        session = cx.Session("Claude Code", "x.jsonl")
        session.add("MCP tools", "mcp__gmail__send", "x" * 300, cx.EV_REQUEST)
        session.add("Built-in tools", "Read", "x" * 150, cx.EV_REQUEST)
        session.deferred["mcp__gmail__label"] = True
        session.skills.update({"tdd": 10, "figma:use": 20, "figma:spec": 5})
        session.finalize()
        table = cx.tools_table(session)
        self.assertIn("| gmail | 1 | 100 | 1 | send, label |", table)
        self.assertIn("| built-in | 1 | 50 | 0 | Read |", table)
        skills = cx.skills_table(session)
        self.assertIn("| figma | 2 | 25 |", skills)
        self.assertIn("| user or built-in | 1 | 10 |", skills)

    def test_skill_listing_keeps_plugin_names(self):
        path = write_jsonl(self.tmp.name, "s.jsonl", [
            {"type": "user", "uuid": "u", "parentUuid": None, "message": {"role": "user", "content": "hi"}},
            {"type": "attachment", "uuid": "a", "parentUuid": "u", "attachment": {"type": "skill_listing", "content": "- tdd: Test first\n- figma:figma-use: Use it\n- engineering:debug"}, "rendered": [{"content": "listing"}]},
        ])
        session = cx.parse_claude(path)
        self.assertEqual(list(session.skills), ["tdd", "figma:figma-use", "engineering:debug"])

    def test_local_command_is_not_an_ask(self):
        path = write_jsonl(self.tmp.name, "s.jsonl", [
            {"type": "user", "uuid": "u", "parentUuid": None, "origin": {"kind": "human"}, "message": {"role": "user", "content": "<command-name>/context</command-name>"}},
            {"type": "system", "subtype": "local_command", "uuid": "c", "parentUuid": "u", "content": "<local-command-stdout>hi</local-command-stdout>"},
            {"type": "user", "uuid": "v", "parentUuid": "c", "origin": {"kind": "human"}, "message": {"role": "user", "content": "Real question"}},
        ])
        session = cx.parse_claude(path)
        self.assertEqual([t["prompt"] for t in session.turns], ["Real question"])

    def test_skill_command_is_an_ask(self):
        text = "<command-message>context-xray</command-message>\n<command-name>/context-xray</command-name>\n<command-args>now</command-args>"
        path = write_jsonl(self.tmp.name, "s.jsonl", [
            {"type": "user", "uuid": "u", "parentUuid": None, "origin": {"kind": "human"}, "message": {"role": "user", "content": text}},
            {"type": "user", "uuid": "m", "parentUuid": "u", "isMeta": True, "message": {"role": "user", "content": "Skill body"}},
            {"type": "assistant", "uuid": "a", "parentUuid": "m", "message": {"role": "assistant", "id": "x", "content": [{"type": "tool_use", "id": "t", "name": "Bash", "input": {"command": "ls"}}]}},
        ])
        session = cx.parse_claude(path)
        self.assertEqual([t["prompt"] for t in session.turns], ["/context-xray now"])
        self.assertEqual(len(session.turns[0]["steps"]), 1)
        self.assertEqual(session.turns[0]["hidden"][0][0], "hidden message")

    def test_window_gauge(self):
        session = cx.Session("Claude Code", "x.jsonl")
        session.real_total, session.window, session.window_source = 250000, 1000000, "catalog"
        gauge = cx.window_gauge(session)
        self.assertIn("250,000 of 1,000,000 tokens used (25.0%)", gauge)
        self.assertIn("750,000 free", gauge)
        session.real_total = 1500000
        self.assertIn("over the listed", cx.window_gauge(session))
        session.window = None
        self.assertIn("pass --window", cx.window_gauge(session))

    def test_window_from_model_catalog(self):
        env = dict(os.environ)
        os.environ["CLAUDE_CONFIG_DIR"] = self.tmp.name
        folder = os.path.join(self.tmp.name, "cache", "model-catalog")
        os.makedirs(folder)
        with open(os.path.join(folder, "a.json"), "w") as handle:
            json.dump({"catalog": {"config": {"models": [{"id": "claude-x", "capabilities": {"max_input_tokens": 200000}}]}}}, handle)
        with open(os.path.join(folder, "broken.json"), "w") as handle:
            handle.write("{}")
        try:
            self.assertEqual(cx.catalog_window("claude-x[1m]"), 200000)
            self.assertIsNone(cx.catalog_window("claude-unknown"))
        finally:
            os.environ.clear()
            os.environ.update(env)

    def test_unresolved_message_is_disclosed(self):
        session = cx.parse_claude(write_jsonl(self.tmp.name, "s.jsonl", claude_rows()))
        self.assertLess(session.coverage[0], session.coverage[1])
        self.assertTrue(any("could not be recovered" in n for n in session.notes))

    def test_subagent_excluded(self):
        session = cx.parse_claude(write_jsonl(self.tmp.name, "s.jsonl", claude_rows()))
        self.assertFalse(any("subagent private task" in b["text"] for b in session.blocks))
        self.assertFalse(any("subagent private task" in t["prompt"] for t in session.turns))

    def test_fallback_without_request_log(self):
        session = cx.parse_claude(write_jsonl(self.tmp.name, "s.jsonl", claude_rows(with_requests=False)))
        self.assertIsNone(session.coverage)
        evidence = {b["section"]: b["evidence"] for b in session.blocks}
        self.assertEqual(evidence["System prompt"], cx.EV_NONE)
        self.assertEqual(evidence["Your messages"], cx.EV_SESSION)
        self.assertIsNone(session.scale)
        self.assertEqual(sum(b["tokens"] for b in session.blocks), 1200)
        self.assertIn(cx.NOT_IN_LOG, evidence)

    def test_compaction_event(self):
        session = cx.parse_claude(write_jsonl(self.tmp.name, "s.jsonl", claude_rows(with_requests=False, compaction=True)))
        kinds = [e["event"] for e in session.events]
        self.assertEqual(kinds, ["turn", "compaction", "turn"])
        self.assertFalse(session.turns[0]["in_context"])
        self.assertTrue(session.turns[1]["in_context"])
        self.assertEqual(session.turns[1]["tokens_added"], 110)
        self.assertIn("Compaction summary", self.sections(session))
        self.assertFalse(any("Fix the login" in b["text"] for b in session.blocks))

    def test_repeat_signal(self):
        session = cx.parse_claude(write_jsonl(self.tmp.name, "s.jsonl", claude_rows()))
        self.assertEqual(session.signals["repeats"][0][:2], ("output_style", 2))
        self.assertEqual(session.signals["rereads"], [])


class Codex(unittest.TestCase):
    def test_sections_turns_and_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = cx.parse_codex(write_jsonl(tmp, "rollout-x.jsonl", codex_rows()))
        by = {b["section"]: b for b in session.blocks}
        self.assertEqual(by["System prompt"]["evidence"], cx.EV_SESSION)
        self.assertIn("Use pnpm", by["CLAUDE.md / AGENTS.md"]["text"])
        self.assertEqual(len(session.turns), 1)
        self.assertEqual(session.turns[0]["tokens_end"], 5000)
        self.assertEqual(session.window, 100000)
        self.assertEqual(session.signals["repeats"][0][:2], ("permissions", 2))
        self.assertTrue(any("encrypted" in b["text"] for b in session.blocks if b["section"] == "Thinking"))


class MapTable(unittest.TestCase):
    def test_each_group_header_appears_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = cx.parse_codex(write_jsonl(tmp, "rollout-x.jsonl", codex_rows()))
        session.add("Hidden injections", "early", "x" * 30, cx.EV_SESSION, cx.BEFORE)
        session.add("Hidden injections", "late", "x" * 30, cx.EV_SESSION, cx.CONVO)
        session.finalize()
        table = cx.map_table(session)
        self.assertEqual(table.count("Before your first message"), 1)
        self.assertEqual(table.count("The conversation"), 1)


class Discovery(unittest.TestCase):
    def test_long_path_uses_shortened_folder(self):
        with tempfile.TemporaryDirectory() as home:
            cwd = os.path.join(os.path.realpath(home), "w" * 220)
            os.makedirs(cwd)
            encoded = cx.re.sub(r"[^A-Za-z0-9]", "-", cwd)
            folder = os.path.join(home, "projects", encoded[:200] + "-abc123")
            os.makedirs(folder)
            log = write_jsonl(folder, "s.jsonl", [{"type": "user", "cwd": cwd, "uuid": "u"}])
            env = dict(os.environ)
            os.environ["CLAUDE_CONFIG_DIR"] = home
            os.environ.pop("CLAUDE_CODE_SESSION_ID", None)
            try:
                self.assertEqual(cx.find_claude(None, cwd), log)
            finally:
                os.environ.clear()
                os.environ.update(env)


def turn(n=1, prompt="Do it", **extra):
    event = cx.new_turn(n, prompt, "you")
    event.update(extra)
    return event


class FirstScreen(unittest.TestCase):
    def session(self, used=100000, window=1000000):
        session = cx.Session("Claude Code", "x.jsonl")
        session.real_total, session.window, session.window_source = used, window, "catalog"
        return session

    def test_verdict_thresholds(self):
        self.assertIn("Keep going.", cx.verdict_line(self.session()))
        self.assertIn("Compact soon", cx.verdict_line(self.session(used=600000)))
        self.assertIn("Start fresh or compact now", cx.verdict_line(self.session(used=850000)))
        two = self.session()
        two.events = [{"event": "compaction"}, {"event": "compaction"}]
        self.assertIn("Consider starting fresh", cx.verdict_line(two))

    def test_verdict_without_window(self):
        self.assertIn("window size is unknown", cx.verdict_line(self.session(window=None)))

    def test_plain_groups_cover_every_section(self):
        grouped = {name for _, sections in cx.PLAIN_GROUPS for name in sections}
        self.assertEqual(set(cx.SECTION_ORDER), grouped)

    def test_unused_server_ranked_used_server_skipped(self):
        session = self.session()
        session.add("MCP tools", "mcp__idle__a", "x" * 3000, cx.EV_REQUEST)
        session.add("MCP tools", "mcp__busy__b", "x" * 3000, cx.EV_REQUEST)
        event = turn()
        event["steps"].append({"name": "mcp__busy__b", "summary": "", "result_tokens": 1, "error": False, "input_tokens": 1})
        session.turns = [event]
        session.finalize()
        text = cx.worth_doing_text(session)
        self.assertIn("`idle`", text)
        self.assertNotIn("`busy`", text)
        self.assertIn("Of 2 loaded tools, 1 were never used", text)

    def test_no_unused_claim_for_codex(self):
        session = self.session()
        session.agent = "Codex"
        session.add("MCP tools", "mcp__idle__a", "x" * 3000, cx.EV_SESSION)
        session.finalize()
        self.assertEqual(cx.worth_doing(session), [])

    def test_reread_counts_only_repeat_copies(self):
        session = self.session()
        event = turn()
        for size in (2000, 1500):
            event["steps"].append({"name": "Read", "summary": "/a.py", "result_tokens": size, "error": False, "input_tokens": 1})
        session.turns = [event]
        session.finalize()
        self.assertEqual(cx.worth_doing(session)[0][0], 1500)

    def test_large_calls_collapse_into_one_suggestion(self):
        session = self.session()
        for _ in range(3):
            session.add("Tool calls", "Bash", "x" * 30000, cx.EV_REQUEST, cx.CONVO)
        session.finalize()
        items = cx.worth_doing(session)
        self.assertEqual(len(items), 1)
        self.assertIn("3 `Bash` calls", items[0][1])

    def test_logged_slash_command_output_is_counted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_jsonl(tmp, "s.jsonl", [
                {"type": "system", "subtype": "local_command", "uuid": "c", "parentUuid": None, "content": "<local-command-stdout>" + "x" * 3000 + "</local-command-stdout>"},
                {"type": "user", "uuid": "v", "parentUuid": "c", "origin": {"kind": "human"}, "message": {"role": "user", "content": "Next"}},
            ])
            session = cx.parse_claude(path)
        self.assertIn("slash command output", cx.biggest_addition(session.turns[0]))

    def test_biggest_addition(self):
        event = turn(hidden=[("local-command-stdout", 21473)])
        event["steps"].append({"name": "Bash", "summary": "ls", "result_tokens": 10, "error": False, "input_tokens": 5})
        self.assertEqual(cx.biggest_addition(event), "21.5k: slash command output")
        event = turn(thinking_by_id={"m": 900})
        self.assertEqual(cx.biggest_addition(event), "900: thinking")

    def test_brief_comparison(self):
        session = self.session()
        session.turns = [turn(prompt="Fix the login | bug")]
        brief = "### Current job\nFixing login.\n\n### Conflicts\n- A vs B\n\n### Unclear or assumed\n- X\n- Y\n"
        text = cx.brief_comparison(session, brief)
        self.assertIn("1. Fix the login \\| bug", text)
        self.assertIn("| Fixing login. |", text)
        self.assertIn("2 assumption(s) and 1 conflict(s)", text)
        self.assertEqual(cx.brief_comparison(session, None), "")

    def test_slash_command_output_lands_on_next_turn(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_jsonl(tmp, "s.jsonl", [
                {"type": "user", "uuid": "u", "parentUuid": None, "origin": {"kind": "human"}, "message": {"role": "user", "content": "<local-command-stdout>" + "x" * 3000 + "</local-command-stdout>"}},
                {"type": "user", "uuid": "v", "parentUuid": "u", "origin": {"kind": "human"}, "message": {"role": "user", "content": "Next"}},
            ])
            session = cx.parse_claude(path)
        self.assertEqual(session.turns[0]["hidden"][0][0], "local-command-stdout")


class EndToEnd(unittest.TestCase):
    def run_cli(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cx.main(argv)
        return code, out.getvalue()

    def test_report_is_redacted_private_and_labeled(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = write_jsonl(tmp, "s.jsonl", claude_rows())
            brief = os.path.join(tmp, "b.md")
            with open(brief, "w") as handle:
                handle.write("My job is fixing login.")
            report = os.path.join(tmp, "out", "r.md")
            code, summary = self.run_cli(["--agent", "claude", "--log", log, "--out", report, "--self-report", brief])
            self.assertEqual(code, 0)
            with open(report) as handle:
                body = handle.read()
            mode = stat.S_IMODE(os.stat(report).st_mode)
        self.assertEqual(mode, 0o600)
        self.assertNotIn(FAKE_GITHUB, body)
        self.assertNotIn(FAKE_GITHUB, summary)
        self.assertIn("[REDACTED:github-token]", body)
        self.assertIn("self-reported, not verified", summary)
        self.assertIn("My job is fixing login.", summary)
        self.assertIn("What is in its head", summary)
        self.assertIn("Manager's view", summary)
        self.assertIn("How the messages built this context", summary)
        self.assertIn(report, summary)
        self.assertNotIn("{{", summary + body)

    def test_self_report_only_is_marked_unverified(self):
        with tempfile.TemporaryDirectory() as tmp:
            brief = os.path.join(tmp, "b.md")
            with open(brief, "w") as handle:
                handle.write("I remember a system prompt.")
            code, summary = self.run_cli(["--self-report-only", brief, "--out", os.path.join(tmp, "r.md")])
        self.assertEqual(code, 0)
        self.assertIn("Nothing in this report is verified", summary)

    def test_no_log_exits_three(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            os.environ["CLAUDE_CONFIG_DIR"] = tmp
            os.environ.pop("CLAUDE_CODE_SESSION_ID", None)
            err = io.StringIO()
            try:
                with contextlib.redirect_stderr(err):
                    code = cx.main(["--agent", "claude", "--cwd", tmp])
            finally:
                os.environ.clear()
                os.environ.update(env)
        self.assertEqual(code, 3)


if __name__ == "__main__":
    unittest.main()
