# Running the renderings on real engines

`run.py` loads the same fixtures the unit tests use into a real engine, translated into
that engine's schema with the field mapping the rendering was generated with, and runs
every rendering for it. A rendering passes when it returns exactly the events whose
`expect` list names its rule; a correlation, when it returns exactly the expected client
addresses. Each target also gets one file-creation event for `wp-config.php` that its
event-type condition has to drop.

Last run on 2026-10-24: Elasticsearch 8.19.4 (ES|QL) 6/6, Kusto emulator
1.0.9791 (KQL) 6/6, Splunk 9.4.3 (SPL) 7/7. Breaking one rendering per engine on purpose
(a wrong file name, a 1-minute window) made each engine fail exactly those two checks.

Bind the engines to localhost only:

```sh
# Elasticsearch, ES|QL
docker run -d --name det-es -p 127.0.0.1:19200:9200 -e discovery.type=single-node \
  -e xpack.security.enabled=false -e ES_JAVA_OPTS="-Xms1g -Xmx1g" \
  docker.elastic.co/elasticsearch/elasticsearch:8.19.4
python tests/engines/run.py esql

# Kusto emulator, KQL
docker run -d --name det-kusto -p 127.0.0.1:8080:8080 -e ACCEPT_EULA=Y \
  mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
python tests/engines/run.py kql

# Splunk, SPL (HEC on 18088, management on 18089)
export SPLUNK_PASSWORD='<choose one>' SPLUNK_HEC_TOKEN="$(uuidgen)"
docker run -d --name det-splunk -p 127.0.0.1:18089:8089 -p 127.0.0.1:18088:8088 \
  -e SPLUNK_PASSWORD -e SPLUNK_HEC_TOKEN -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com splunk/splunk:9.4.3
python tests/engines/run.py spl
```

The SPL and ES|QL correlations are what the backends generate: they count in fixed
15-minute buckets, so the fixture pair that straddles 10:15 is missed, and `run.py`
expects that. The KQL correlation is a join with a sliding window and catches it, as do
the Sigma rule and the SQLite test.
