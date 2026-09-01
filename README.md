# Talos TE COG Wheelhouse GUI

An internal Flask application that brings common Talos Escalations workflows into one dashboard. It combines COG and Analyst Console ticket views, Jira metrics, replay and PCAP analysis, rule search, CVE/CR lookup, and supporting team resources.

> Cisco Talos internal use only. This application depends on internal services and is not intended for public deployment.

## Features

- COG ticket dashboards, assignment workflows, backlog tools, and Jira reporting windows
- Analyst Console ticket views and escalation summaries
- PigReplay uploads, Snort 3 replay, SID/rule lookup, PCAP content and PCRE analysis, and Jira-ready summaries
- CVE change-request lookup and Jira staging
- BP signature search, Elastic queries, Malware Analytics search, and malicious-IP reporting
- Team calendar, reporting shortcuts, staging links, and escalation resources

## Requirements

- Python 3.10 or newer
- Snort 3 for replay workflows
- TShark/Wireshark for PCAP decoding through PyShark
- Access to the required Cisco/Talos internal services

## Install

```bash
git clone https://github.com/wikoeste/talos-te-cogwheelhouse-gui.git
cd talos-te-cogwheelhouse-gui
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
cp .env.example .env
chmod 600 .env
```

Editable installation requires a current pip release. If an older pip reports that the `pyproject.toml` project is not editable, run the upgrade command above and retry.

## Configuration

Set local values in `.env`. The file is ignored by Git and must never be committed.

| Variable | Purpose |
| --- | --- |
| `FLASK_SECRET_KEY` | Stable Flask session-signing secret |
| `COGWHEELHOUSE_HOST`, `COGWHEELHOUSE_PORT` | Bind address and port; defaults to `127.0.0.1:8000` |
| `FLASK_DEBUG` | Enables Flask debug mode when set to `true`; leave disabled for normal use |
| `ACE_DB_HOST`, `ACE_DB_NAME`, `ACE_DB_USER`, `ACE_DB_PASSWORD` | Analyst Console read-only database connection |
| `THREATGRID_API_KEY` | Malware Analytics/Threat Grid API key |
| `BP_GITHUB_TOKEN` | Optional token for BP signature repository access |
| `PIGREPLAY_PCAP_DIR` | Optional persistent PCAP working directory |
| `PIGREPLAY_SHARED_RULES_DIR` | Optional Snort-rule directory override |
| `COGWHEELHOUSE_DATA_ROOT`, `COGWHEELHOUSE_STATE_ROOT` | Optional packaged-data and runtime-state overrides |

Additional internal-service credentials already supported by the application may also be configured in `.env.example`. Legacy keys in the user's `.profile` remain supported for existing installations.

PigReplay searches for rules in the configured rule directory, then `/var/tmp/snort-rules/` and `/private/var/tmp/snort-rules/`. Uploaded PCAPs, downloaded rules, generated ticket pages, replay posts, and local caches are runtime data and are excluded from source control.

## Run

```bash
talos-te-cogwheelhouse
```

For a source checkout, this is equivalent to:

```bash
python server.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). Change the host or port with the environment variables above.

## Test and package

```bash
python -m unittest discover -s tests -v
python -m pip wheel --no-deps .
```

## Release notes

### 0.6.0

- Added structured PCAP content and PCRE analysis, multi-PCAP replay results, rule lookup by SID, and Jira-ready replay summaries.
- Added Jira Metrics date windows, CVE/CR lookup, BP and Elastic query views, team calendar, malicious-IP reporting, and shared navigation.
- Modernized the dashboard, responsive layouts, accessibility states, and Talos-themed visual styling.
- Migrated packaging to `pyproject.toml`, added a console entry point, made paths portable, and documented environment-based configuration.
- Removed credentials, generated ticket data, PCAPs, downloaded rules, IDE metadata, and Python bytecode from source control.

### 0.5.0

- Introduced the COG Wheelhouse dashboard, PigReplay tooling, Jira metrics, Analyst Console ticket views, and the initial dark interface.

### 0.0.1

- Initial local beta.
