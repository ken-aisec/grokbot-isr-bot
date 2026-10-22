"""Batch 6 PR3, B8: an MCP server a package launcher runs is pinned only by an exact version, whichever launcher it is.

npx, uvx, bunx, `pnpm dlx` and `npm exec` (also behind /usr/bin/env) are read alike from each server's command and args; "@latest",
a range and a dist-tag are unpinned (decision 7). The old test ("an @ within 200 characters of the command") let
`npx -y @scope/pkg`, `pkg@latest` and an email in the args pass as pinned, and never looked at bunx behind env, pnpm or npm.

Tests marked "replay" fail on 1aed58a on their assertion (measured with 1aed58a's watchtower/ sources, this file in place);
"guard" ones keep what must not change. The box is a temp folder; every package name is an example."""
import json, os, sys, time, unittest
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_boxes import Box, wt


def server(command, *args):
    return {"mcpServers": {"tool": {"command": command, "args": list(args)}}}


class Pins(Box):
    def m001(self, configs):
        """{name: the WT-M001 evidence an audit gives for ~/<name>/mcp.json}, every config in one box and one audit."""
        for name, doc in configs.items():
            d = os.path.join(self.home, name)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "mcp.json"), "w") as f:
                f.write(doc if isinstance(doc, str) else json.dumps(doc, indent=2))
        self.audit("--budget", "0")
        snap = self.snap()
        fs = [f for k in ("findings", "suppressed") for f in snap.get(k) or [] if f.get("rule") == "WT-M001"]
        self.fixes = {f.get("fix") for f in fs}
        return {name: sorted(f["evidence"] for f in fs if f"/{name}/mcp.json" in f["where"]) for name in configs}

    def test_every_launcher_without_an_exact_version_is_unpinned(self):   # replay (1aed58a: none for each)
        got = self.m001({"scoped": server("npx", "-y", "@modelcontextprotocol/server-filesystem", "/data"),
                         "email": server("npx", "pkg", "--owner", "me@example.com"),
                         "latest": server("npx", "-y", "pkg@latest"),
                         "range": server("npx", "pkg@^1.2.0"),
                         "bunx": server("bunx", "pkg@next"),
                         "env": server("/usr/bin/env", "npx", "-y", "@scope/pkg"),
                         "pnpm": server("pnpm", "dlx", "pkg"),
                         "npmexec": server("npm", "exec", "--yes", "--", "pkg"),
                         "uvlatest": server("uvx", "pkg@latest"),
                         "oneline": {"mcpServers": {"tool": {"command": "npx -y @scope/pkg"}}}})
        self.assertEqual(got, {"scoped": ["npx @modelcontextprotocol/server-filesystem (no version)"],
                               "email": ["npx pkg (no version)"], "latest": ["npx pkg (@latest)"], "range": ["npx pkg (range ^1.2.0)"],
                               "bunx": ["bunx pkg (tag next)"], "env": ["npx @scope/pkg (no version)"], "pnpm": ["pnpm dlx pkg (no version)"],
                               "npmexec": ["npm exec pkg (no version)"], "uvlatest": ["uvx pkg (@latest)"],
                               "oneline": ["npx @scope/pkg (no version)"]})
        self.assertEqual(self.fixes, {"Pin an exact version (pkg@1.2.3) so an update can't change what runs."})

    def test_exact_versions_and_other_commands_are_not_flagged(self):   # replay (1aed58a: uvx pkg==1.2.3 flagged, no @ near it)
        got = self.m001({"npm": server("npx", "-y", "pkg@1.2.3"), "scoped": server("npx", "-y", "@scope/pkg@1.2.3", "--port", "8080"),
                         "uv": server("uvx", "pkg==1.2.3"), "from": server("uvx", "--from", "pkg==1.2.3", "pkg-server"),
                         "package": server("npx", "-p", "@scope/pkg@2.0.0", "tool"), "node": server("node", "server.js"),
                         "remote": {"mcpServers": {"tool": {"url": "https://mcp.example/sse"}}}})
        self.assertEqual(got, dict.fromkeys(("npm", "scoped", "uv", "from", "package", "node", "remote"), []))

    def test_uvx_without_a_version_and_a_file_that_isnt_json_stay_flagged(self):   # guard (the count; the wording is new)
        got = self.m001({"uvx": server("uvx", "pkg"),
                         "jsonc": '{\n  // my tools\n  "mcpServers": {"tool": {"command": "npx", "args": ["-y", "pkg"]},},\n}\n'})
        self.assertEqual({k: len(v) for k, v in got.items()}, {"uvx": 1, "jsonc": 1})   # (1aed58a's evidence was the command alone)
        self.assertEqual(got, {"uvx": ["uvx pkg (no version)"], "jsonc": ["npx pkg (no version)"]})

    def test_each_server_is_reported_at_its_own_line(self):   # the new parser (1aed58a has none)
        doc = {"mcpServers": {"a": {"command": "node", "args": ["x.js"]}, "b": {"command": "npx", "args": ["pkg"]}}}
        text = json.dumps(doc, indent=2)
        self.assertEqual(wt.mcp_unpinned(text), [(text[:text.index('"npx"')].count("\n") + 1, "npx pkg (no version)")])


class Scaling(unittest.TestCase):
    def test_a_big_config_reads_in_linear_time(self):   # timing guard for the new parser (1aed58a has none)
        doc = {"mcpServers": {f"s{i}": {"command": "npx", "args": ["-y", f"pkg{i}@" + "1." * 5 + "x"]} for i in range(2000)}}
        texts = (json.dumps(doc), json.dumps(doc).replace("{", "{ // c\n", 1),   # JSON, then the reading for a file that isn't
                 '{"mcpServers": {' + ",".join(f'"s{i}": {{"command": "\\u006epx"}}' for i in range(2000)) + "}}",
                 '"command": "npx", "args": ["' + "a==1." * 40000 + '!"]')
        for t in texts:
            s = time.monotonic()
            wt.mcp_unpinned(t)
            self.assertLess(time.monotonic() - s, 5.0)


if __name__ == "__main__":
    unittest.main()
