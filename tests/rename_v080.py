"""v0.8.0 rename: the reviewed name table (tests/golden_rename_v080.json) for tests and harness lines that need an old spelling.
Nothing here builds an old name by hand: every old value comes from the table."""
import json, os, re

TABLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "golden_rename_v080.json")
with open(TABLE_PATH, encoding="utf-8") as _f:
    TABLE = json.load(_f)
OLD, NEW = TABLE["layouts"]["old"], TABLE["layouts"]["new"]


def old_rule(new_id):
    """The rule ID a finding had before 0.8.0: ISR-X004 -> its old-prefix form."""
    if not new_id.startswith(NEW["rule_prefix"]):
        raise ValueError(f"not a rule ID: {new_id!r}")
    return OLD["rule_prefix"] + new_id[len(NEW["rule_prefix"]):]


def old_display():
    """The v0.7.4 display strings (old, new) the table lists, in order."""
    return [tuple(p) for p in TABLE["v074_display"]]


def old_patterns():
    """What an old name looks like anywhere: the old product word in any case, and the old short name as a token of its own
    (wt.py, wt_parts, WT-X004, "wt")."""
    return [re.compile("(?i)" + re.escape(OLD["pkg"])),
            re.compile(r"(?i)(?<![a-z0-9])" + re.escape(OLD["main"][:-len(".py")]) + r"(?![a-z0-9])")]
