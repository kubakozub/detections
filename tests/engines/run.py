#!/usr/bin/env python3
"""Run renderings/ on real query engines against the same fixtures the unit tests use.

    python tests/engines/run.py esql   # Elasticsearch 8.x   $ES_URL     (http://127.0.0.1:19200)
    python tests/engines/run.py kql    # Kusto emulator      $KUSTO_URL  (http://127.0.0.1:8080)
    python tests/engines/run.py spl    # Splunk              $SPLUNK_URL (https://127.0.0.1:18089),
                                       #   $SPLUNK_HEC_URL (https://127.0.0.1:18088),
                                       #   $SPLUNK_PASSWORD, $SPLUNK_HEC_TOKEN

Not part of CI, because it needs the engines; tests/engines/README.md has the docker
commands. Each fixture event is translated into the engine's schema with the field mapping
its rendering was generated with, loaded, and every rendering for that engine is run.
A rendering passes when it returns exactly the events whose "expect" list names its rule,
and a correlation when it returns exactly the expected client addresses.
"""
import base64
import csv
import io
import json
import os
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
RENDER = ROOT / "renderings"
PIPES = ROOT / "pipelines"
CORRELATION = "web_wordpress_media_finalize_then_delete"
# The SPL and ES|QL correlations that the backends generate count in fixed 15-minute
# buckets; a pair that straddles a bucket boundary is missed. The Sigma rule, the SQLite
# test and the KQL join use a sliding window and catch it.
BUCKETED_MISS = {"192.0.2.80"}


def load(name):
    text = (FIXTURES / name).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]


WEB = load("webserver.jsonl")
FILES = load("file_delete_linux.jsonl")
AUDIT = load("auditd.jsonl")
CORR = json.loads((FIXTURES / "correlations.json").read_text(encoding="utf-8"))[CORRELATION]
# a file event of another type: the event-type condition of each target must drop it
CREATED = {"id": "control-wp-config-created", "timestamp": "2026-08-11 13:00:01",
           "Image": "/usr/sbin/php-fpm8.2", "User": "www-data",
           "TargetFilename": "/var/www/html/wp-config.php", "expect": []}


def mapping(pipeline, transformation_id):
    doc = yaml.safe_load((PIPES / pipeline).read_text(encoding="utf-8"))
    (t,) = [t for t in doc["transformations"] if t["id"] == transformation_id]
    return t["mapping"]


def translate(event, fields):
    return {fields.get(k, k): v for k, v in event.items() if k not in ("id", "expect", "note", "timestamp")}


def epoch(ts):
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()


def expected(events, stem):
    return {e["id"] for e in events if stem in e["expect"]}


def http(method, url, body=None, headers=None, auth=None, insecure=False):
    data = None if body is None else (body if isinstance(body, bytes) else body.encode())
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    ctx = ssl._create_unverified_context() if insecure else None  # local self-signed engine only
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=120) as r:
            return r.read().decode()
    except urllib.error.HTTPError as e:
        raise SystemExit(f"{method} {url}: HTTP {e.code}\n{e.read().decode()[:2000]}")


class Report:
    def __init__(self, engine):
        self.engine, self.failed, self.passed = engine, 0, 0

    def check(self, name, got, want, note=""):
        ok = got == want
        self.passed += ok
        self.failed += not ok
        line = f"{'PASS' if ok else 'FAIL'}  {self.engine:5} {name}"
        if note:
            line += f"  ({note})"
        if not ok:
            line += f"\n        extra: {sorted(got - want)}\n        missing: {sorted(want - got)}"
        print(line)

    def done(self):
        print(f"{self.engine}: {self.passed} passed, {self.failed} failed")
        return 1 if self.failed else 0


# ------------------------------------------------------------------ Elasticsearch / ES|QL
def run_esql():
    es = os.environ.get("ES_URL", "http://127.0.0.1:19200")
    rep = Report("esql")
    web_map = mapping("ecs_web_file.yml", "ecs_web_fields")
    file_map = mapping("ecs_web_file.yml", "ecs_file_delete_fields")
    json_h = {"Content-Type": "application/json"}
    indices = {
        "fixtures-web": [dict(translate(e, web_map), **{"fixture.id": e["id"], "@timestamp": e["timestamp"]})
                         for e in WEB],
        "fixtures-file": [dict(translate(e, file_map), **{"fixture.id": e["id"], "@timestamp": e["timestamp"],
                                                          "event.category": "file",
                                                          "event.type": "creation" if e is CREATED else "deletion"})
                          for e in FILES + [CREATED]],
    }
    for index, docs in indices.items():
        http("DELETE", f"{es}/{index}?ignore_unavailable=true")
        props = {"@timestamp": {"type": "date", "format": "yyyy-MM-dd HH:mm:ss"},
                 "source.ip": {"type": "ip"}, "http.response.status_code": {"type": "long"}}
        http("PUT", f"{es}/{index}", json.dumps({"mappings": {
            "dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword"}}}],
            "properties": props}}), json_h)
        bulk = "".join(json.dumps({"index": {}}) + "\n" + json.dumps(d) + "\n" for d in docs)
        http("POST", f"{es}/{index}/_bulk?refresh=true", bulk, {"Content-Type": "application/x-ndjson"})

    def esql(query):
        out = json.loads(http("POST", f"{es}/_query", json.dumps({"query": query}), json_h))
        cols = [c["name"] for c in out["columns"]]
        return [dict(zip(cols, row)) for row in out["values"]]

    for path in sorted((RENDER / "esql").glob("*.esql")):
        stem = path.stem
        query = path.read_text(encoding="utf-8").strip()
        head = "from * metadata _id, _index, _version"
        assert query.startswith(head), path
        if stem == CORRELATION:
            rows = esql(query.replace(head, "from fixtures-web metadata _id", 1))
            got = {r["source.ip"] for r in rows}
            want = {a["group"]["c-ip"] for a in CORR} - BUCKETED_MISS
            rep.check(stem, got, want, "fixed buckets: the boundary-straddling pair is expected to be missed")
            continue
        index, events = ("fixtures-web", WEB) if stem.startswith("web_") else ("fixtures-file", FILES + [CREATED])
        rows = esql(query.replace(head, f"from {index} metadata _id", 1) + "\n| keep fixture.id")
        rep.check(stem, {r["fixture.id"] for r in rows}, expected(events, stem))
    return rep.done()


# ------------------------------------------------------------------ Kusto emulator / KQL
def run_kql():
    kusto = os.environ.get("KUSTO_URL", "http://127.0.0.1:8080")
    rep = Report("kql")
    json_h = {"Content-Type": "application/json"}

    def mgmt(cmd):
        http("POST", f"{kusto}/v1/rest/mgmt", json.dumps({"db": "NetDefaultDB", "csl": cmd}), json_h)

    def query(q):
        frames = json.loads(http("POST", f"{kusto}/v2/rest/query", json.dumps({"db": "NetDefaultDB", "csl": q}), json_h))
        (table,) = [f for f in frames if f.get("FrameType") == "DataTable" and f.get("TableKind") == "PrimaryResult"]
        cols = [c["ColumnName"] for c in table["Columns"]]
        return [dict(zip(cols, row)) for row in table["Rows"]]

    def ingest(table, columns, rows):
        buf = io.StringIO()
        csv.writer(buf, lineterminator="\n").writerows([[r.get(c, "") for c in columns] for r in rows])
        mgmt(f".ingest inline into table {table} <|\n{buf.getvalue()}")

    web_map = mapping("kql_appservice_http.yml", "appservice_http_fields")
    web_cols = ["TimeGenerated", "CIp", "CsUsername", "CsMethod", "CsUriStem", "CsUriQuery", "ScStatus", "FixtureId"]
    mgmt(".drop table AppServiceHTTPLogs ifexists")
    mgmt(".create table AppServiceHTTPLogs (TimeGenerated:datetime, CIp:string, CsUsername:string, CsMethod:string, "
         "CsUriStem:string, CsUriQuery:string, ScStatus:int, FixtureId:string)")
    ingest("AppServiceHTTPLogs", web_cols,
           [dict(translate(e, web_map), TimeGenerated=e["timestamp"].replace(" ", "T") + "Z", FixtureId=e["id"])
            for e in WEB])
    # Defender XDR column names, as the microsoft_xdr pipeline maps them
    file_cols = ["TimeGenerated", "ActionType", "FolderPath", "InitiatingProcessFolderPath", "FixtureId"]
    mgmt(".drop table DeviceFileEvents ifexists")
    mgmt(".create table DeviceFileEvents (TimeGenerated:datetime, ActionType:string, FolderPath:string, "
         "InitiatingProcessFolderPath:string, FixtureId:string)")
    ingest("DeviceFileEvents", file_cols,
           [{"TimeGenerated": e["timestamp"].replace(" ", "T") + "Z",
             "ActionType": "FileCreated" if e is CREATED else "FileDeleted",
             "FolderPath": e["TargetFilename"], "InitiatingProcessFolderPath": e["Image"], "FixtureId": e["id"]}
            for e in FILES + [CREATED]])

    for path in sorted((RENDER / "kql").glob("*.kql")):
        stem = path.stem
        q = path.read_text(encoding="utf-8").strip()
        if stem == CORRELATION:
            got = {r["CIp"] for r in query(q)}
            rep.check(stem, got, {a["group"]["c-ip"] for a in CORR}, "sliding window: catches the straddling pair")
            continue
        events = WEB if stem.startswith("web_") else FILES + [CREATED]
        rep.check(stem, {r["FixtureId"] for r in query(q + "\n| project FixtureId")}, expected(events, stem))
    return rep.done()


# ------------------------------------------------------------------ Splunk / SPL
def run_spl():
    mgmt_url = os.environ.get("SPLUNK_URL", "https://127.0.0.1:18089")
    hec_url = os.environ.get("SPLUNK_HEC_URL", "https://127.0.0.1:18088")
    auth = "admin:" + os.environ["SPLUNK_PASSWORD"]
    token = os.environ["SPLUNK_HEC_TOKEN"]
    rep = Report("spl")
    run_id = str(int(time.time()))           # a fresh source per run, so reruns never see old events

    def search(spl):
        body = urllib.parse.urlencode({"search": spl, "output_mode": "json", "earliest_time": "0",
                                       "latest_time": "now"})
        text = http("POST", f"{mgmt_url}/services/search/jobs/export", body,
                    {"Content-Type": "application/x-www-form-urlencoded"}, auth=auth, insecure=True)
        rows = []
        for line in text.splitlines():
            if line.strip():
                msg = json.loads(line)
                if "result" in msg and not msg.get("preview"):
                    rows.append(msg["result"])
        return rows

    web_map = mapping("splunk_access_combined.yml", "access_combined_fields")
    sets = {
        "web": [(e, translate(e, web_map)) for e in WEB],
        # Sysmon for Linux: FileDelete is event 23, file creation is 11
        "file": [(e, dict(translate(e, {}), EventID=11 if e is CREATED else 23)) for e in FILES + [CREATED]],
        "auditd": [(e, translate(e, {})) for e in AUDIT],
    }
    batch = []
    for name, pairs in sets.items():
        for e, fields in pairs:
            batch.append(json.dumps({"time": epoch(e["timestamp"]), "index": "main", "sourcetype": "_json",
                                     "source": f"fixture:{name}:{run_id}",
                                     "event": dict(fields, fixture_id=e["id"])}))
    http("POST", f"{hec_url}/services/collector/event", "\n".join(batch),
         {"Authorization": f"Splunk {token}"}, insecure=True)
    total = len(batch)
    for _ in range(60):
        rows = search(f'search index=main source="fixture:*:{run_id}" | stats count')
        if rows and int(rows[0]["count"]) >= total:
            break
        time.sleep(2)
    else:
        raise SystemExit("events never became searchable")

    def scope(name):
        return f'index=main source="fixture:{name}:{run_id}"'

    for path in sorted((RENDER / "splunk").glob("*.spl")):
        stem = path.stem
        spl = path.read_text(encoding="utf-8").strip()
        if stem == CORRELATION:
            assert spl.count("[ search ") == 2, path
            rows = search(spl.replace("[ search ", f"[ search {scope('web')} "))
            got = {r["clientip"] for r in rows}
            want = {a["group"]["c-ip"] for a in CORR} - BUCKETED_MISS
            rep.check(stem, got, want, "fixed buckets: the boundary-straddling pair is expected to be missed")
            continue
        name = "web" if stem.startswith("web_") else "auditd" if stem.startswith("lnx_auditd_") else "file"
        events = [e for e, _ in sets[name]]
        rows = search(f"search {scope(name)} ({spl}) | table fixture_id")
        rep.check(stem, {r["fixture_id"] for r in rows}, expected(events, stem))
    return rep.done()


if __name__ == "__main__":
    engines = {"esql": run_esql, "kql": run_kql, "spl": run_spl}
    if len(sys.argv) != 2 or sys.argv[1] not in engines:
        sys.exit(__doc__)
    sys.exit(engines[sys.argv[1]]())
