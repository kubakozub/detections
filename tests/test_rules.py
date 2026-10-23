"""Run every rule against the fixtures through pySigma's SQLite backend.

Nothing here re-implements Sigma matching: each rule is converted by the same backend a
user would convert it with, and the resulting SQL runs over the fixture events in an
in-memory SQLite table. Each fixture event lists in "expect" the rules (by file name)
that must match it, so every other rule must not. Correlation alerts are compared with
tests/fixtures/correlations.json.
"""
import json
import pathlib
import sqlite3
import unittest

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
FIXTURES = ROOT / "tests" / "fixtures"

# logsource -> fixture file holding events of that shape
SOURCES = {
    ("webserver", None, None): "webserver.jsonl",
    ("file_delete", "linux", None): "file_delete_linux.jsonl",
    (None, "linux", "auditd"): "auditd.jsonl",
}
META = ("id", "expect", "note")


def logsource_key(rule):
    ls = rule.logsource
    return (ls.category, ls.product, ls.service)


def load_events(name):
    lines = (FIXTURES / name).read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def database(events):
    """One table, `logs`, with a column per field seen in the fixture; rowid follows file order."""
    fields = []
    for event in events:
        for key in event:
            if key not in META and key not in fields:
                fields.append(key)
    db = sqlite3.connect(":memory:")
    cols = ", ".join(f'"{f}"' for f in fields)
    db.execute(f"CREATE TABLE logs ({cols})")
    marks = ", ".join("?" for _ in fields)
    for event in events:
        db.execute(f"INSERT INTO logs ({cols}) VALUES ({marks})", [event.get(f) for f in fields])
    return db


def rule_files():
    return sorted(RULES.rglob("*.yml"))


class RuleFixtures(unittest.TestCase):
    backend = sqliteBackend()

    def matched_ids(self, sql, events):
        db = database(events)
        rows = db.execute(sql.replace("SELECT *", "SELECT rowid", 1)).fetchall()
        return {events[rowid - 1]["id"] for (rowid,) in rows}

    def test_every_rule_has_fixtures(self):
        covered = set()
        for name in SOURCES.values():
            for event in load_events(name):
                covered.update(event["expect"])
        corr = json.loads((FIXTURES / "correlations.json").read_text(encoding="utf-8"))
        covered.update(corr)
        missing = {f.stem for f in rule_files()} - covered
        self.assertFalse(missing, f"rules without a positive fixture: {sorted(missing)}")

    def test_detection_rules(self):
        for path in rule_files():
            collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"), resolve_references=False)
            rule = collection.rules[0]
            if isinstance(rule, SigmaCorrelationRule):
                continue
            with self.subTest(rule=path.stem):
                fixture = SOURCES.get(logsource_key(rule))
                self.assertIsNotNone(fixture, f"no fixture for logsource {logsource_key(rule)}")
                events = load_events(fixture)
                (sql,) = self.backend.convert(collection)
                got = self.matched_ids(sql, events)
                want = {e["id"] for e in events if path.stem in e["expect"]}
                self.assertEqual(sorted(got - want), [], "matched events it should not")
                self.assertEqual(sorted(want - got), [], "missed events it should match")

    def test_correlation_rules(self):
        everything = SigmaCollection.load_ruleset([str(RULES)])
        expected = json.loads((FIXTURES / "correlations.json").read_text(encoding="utf-8"))
        correlations = [r for r in everything.rules if isinstance(r, SigmaCorrelationRule)]
        self.assertTrue(correlations)
        for rule in correlations:
            stem = rule.source.path.stem
            with self.subTest(rule=stem):
                inputs = {logsource_key(ref.rule) for ref in rule.rules}
                self.assertEqual(len(inputs), 1)
                events = load_events(SOURCES[inputs.pop()])
                # The backend converts the referenced rules first and the correlation on top of
                # them, so it needs them in one collection; referenced rules are not emitted.
                files = [ref.rule.source.path for ref in rule.rules] + [rule.source.path]
                text = "\n---\n".join(p.read_text(encoding="utf-8") for p in files)
                (sql,) = sqliteBackend().convert(SigmaCollection.from_yaml(text))
                db = database(events)
                db.row_factory = sqlite3.Row
                alerts = []
                for row in db.execute(sql):
                    rowids = [int(eid.split(":")[1]) for eid in json.loads(row["event_ids"])]
                    alerts.append({
                        "group": json.loads(row["group_keys"]),
                        "events": sorted(events[i - 1]["id"] for i in rowids),
                    })
                alerts.sort(key=lambda a: json.dumps(a, sort_keys=True))
                want = sorted(expected[stem], key=lambda a: json.dumps(a, sort_keys=True))
                self.assertEqual(alerts, want)


if __name__ == "__main__":
    unittest.main()
