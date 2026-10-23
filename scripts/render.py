#!/usr/bin/env python3
"""Regenerate renderings/ from rules/ with the pinned pySigma backends.

    python scripts/render.py

Every query is produced by sigma-cli; the script only picks backends and pipelines,
writes one file per rule and target, and puts a table name in front of the Kusto
filters. The one exception is the KQL correlation: the Kusto backend does not convert
correlation rules, so it is assembled here from the two filters the backend generated.
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
OUT = ROOT / "renderings"
PIPES = ROOT / "pipelines"
SIGMA = str(pathlib.Path(sys.executable).with_name("sigma"))

CORRELATION = "web_wordpress_media_finalize_then_delete"
CORRELATION_INPUTS = ["web_wordpress_media_finalize_request", "web_wordpress_media_delete_request"]

# target -> (sigma-cli arguments, rules it applies to)
TARGETS = {
    "splunk": {
        "web": ["-t", "splunk", "-p", str(PIPES / "splunk_access_combined.yml")],
        "file_delete": ["-t", "splunk", "-p", str(PIPES / "splunk_sysmon_linux_file_delete.yml")],
        "auditd": ["-t", "splunk", "--without-pipeline"],
    },
    "esql": {
        "web": ["-t", "esql", "-p", str(PIPES / "ecs_web_file.yml")],
        "file_delete": ["-t", "esql", "-p", str(PIPES / "ecs_web_file.yml")],
    },
    "kql": {
        "web": ["-t", "kusto", "-p", str(PIPES / "kql_appservice_http.yml")],
        "file_delete": ["-t", "kusto", "-p", "microsoft_xdr", "-p", str(PIPES / "kql_xdr_file_delete.yml")],
    },
}
EXT = {"splunk": "spl", "esql": "esql", "kql": "kql"}

KQL_CORRELATION = """let window = 15m;
let finalize = AppServiceHTTPLogs
| where {finalize}
| project FinalizeTime = TimeGenerated, CIp, FinalizeUri = strcat(CsUriStem, "?", CsUriQuery);
let deletes = AppServiceHTTPLogs
| where {delete}
| project DeleteTime = TimeGenerated, CIp, DeleteUri = strcat(CsUriStem, "?", CsUriQuery);
finalize
| join kind=inner deletes on CIp
| where abs(DeleteTime - FinalizeTime) <= window
| summarize FirstSeen = min(min_of(FinalizeTime, DeleteTime)), LastSeen = max(max_of(FinalizeTime, DeleteTime)),
    Finalized = make_set(FinalizeUri), Deleted = make_set(DeleteUri) by CIp
"""


def kind(path):
    if path.parent.name == "web":
        return "web"
    return "auditd" if path.stem.startswith("lnx_auditd_") else "file_delete"


def convert(args, files):
    # sigma-cli resolves correlation references only within one input directory,
    # so the rules for one query go into a directory of their own
    with tempfile.TemporaryDirectory() as tmp:
        for f in files:
            shutil.copy(f, tmp)
        run = subprocess.run([SIGMA, "convert", *args, tmp], capture_output=True, text=True)
    if run.returncode:
        sys.exit(f"sigma convert {' '.join(args)} {[f.name for f in files]}:\n{run.stderr}")
    return run.stdout.strip()


def main():
    rules = {p.stem: p for p in sorted(RULES.rglob("*.yml"))}
    for target in TARGETS:
        shutil.rmtree(OUT / target, ignore_errors=True)
        (OUT / target).mkdir(parents=True)
    for stem, path in rules.items():
        for target, by_kind in TARGETS.items():
            args = by_kind.get(kind(path))
            if args is None:
                continue
            if stem == CORRELATION:
                if target == "kql":
                    continue
                files = [rules[s] for s in CORRELATION_INPUTS] + [path]
            else:
                files = [path]
            query = convert(args, files)
            if target == "kql" and kind(path) == "web":
                query = "AppServiceHTTPLogs\n| where " + query
            (OUT / target / f"{stem}.{EXT[target]}").write_text(query + "\n", encoding="utf-8")
    finalize, delete = (convert(TARGETS["kql"]["web"], [rules[s]]) for s in CORRELATION_INPUTS)
    (OUT / "kql" / f"{CORRELATION}.kql").write_text(
        KQL_CORRELATION.format(finalize=finalize, delete=delete), encoding="utf-8")
    for target in TARGETS:
        print(target, sorted(p.name for p in (OUT / target).iterdir()))


if __name__ == "__main__":
    main()
