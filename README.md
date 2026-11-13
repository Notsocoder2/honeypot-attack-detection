# Honeypot Attack Detection Demo

A standard-library Python demonstration of a custom TCP login prompt, authentication failure telemetry, time-window detection, and temporary application-level source cooldowns. It is designed for localhost and controlled lab demonstrations.

> This is not an SSH server, HTTP server, firewall, or production intrusion prevention system. It does not authenticate users. It rejects every submitted credential pair and records an authentication failure.

## Architecture

```text
TCP client -> server.py -> bounded worker threads -> DetectionEngine
                                  |                       |
                                  +---- EventLogger <-----+
                                       rotating JSONL
```

- `server.py`: listener lifecycle, bounded concurrent handling, input framing and CLI.
- `config.py`: defaults for bind address, timeouts, limits, detection, and log rotation.
- `detection.py`: synchronized in-memory time windows, alert suppression, distributed activity heuristic, and cooldown expiry.
- `eventlog.py`: sanitized JSON Lines events with size-based rotation.
- `client.py`: one safe sample attempt.
- `tests/`: local unit and integration coverage.

## Requirements and installation

Python 3.10 or newer; no third-party packages are required. Clone the repository and run commands from its root. No dependency installation is needed.

## Run

Start the server:

```sh
python server.py
```

By default it listens only on `127.0.0.1:12348` and writes rotating events under `logs/events.jsonl`. In another terminal, send one sample attempt:

```sh
python client.py
```

Options include `--host`, `--port`, `--log`, `--max-workers`, `--timeout`, `--max-field-bytes`, `--cooldown`, `--ip-threshold`/`--ip-window`, `--username-threshold`/`--username-window`, `--global-threshold`/`--global-window`, `--distributed-threshold`/`--distributed-window`, `--connection-threshold`/`--connection-window`, and `--alert-suppression`. For example, use a different local port with `python server.py --port 12349`. Binding to a non-loopback address is explicit via `--host`; do so only in an isolated, authorized lab. Stop with Ctrl+C.

## Detection behavior

Each completed username/password exchange is treated as a failed authentication. Password contents are discarded and never included in event records or console messages. Defaults are:

- 9 failures from one source within 15 seconds: `brute_force_ip`, high severity, and a 60-second application-level cooldown.
- 6 failures for one case-insensitive username within 20 seconds: `targeted_username`, medium severity.
- 12 failures from more than one source within 30 seconds: `distributed_activity`, high severity.
- 16 failures across all sources within 10 seconds: `high_traffic_global`, medium severity.
- 20 accepted connections from one source within 10 seconds: `connection_burst`, medium severity.

Alerts for each category/key are suppressed for 60 seconds. Connection-frequency events count accepted connections separately from completed login failures. These are heuristics for a demonstration; they indicate suspicious patterns and do not prove malicious intent. State is in memory and resets when the process exits. Cooldown closes accepted connections at the application layer; it does not block packets or update a firewall.

## Events

`logs/events.jsonl` contains one JSON object per line, with UTC timestamp, peer IP, service name, port, event type, optional username, category, reason, severity, and metadata. Usernames and reasons have control characters sanitized. Logs rotate at 5 MB with three backups by default. Do not place logs in a publicly served directory.

Example (field values are illustrative):

```json
{"timestamp":"2026-11-12T12:00:00+00:00","source_ip":"127.0.0.1","service":"custom_tcp_login_demo","port":12348,"event_type":"authentication_failure","detection_category":null,"username":"admin","reason":"demo service rejects all credentials","severity":"info","metadata":{}}
```

## Tests

Run the standard-library test suite:

```sh
python -m unittest discover -s tests -v
```

Tests bind only to ephemeral localhost ports and use temporary log directories.

## Security considerations and limitations

- The wire protocol is a deliberately simple plaintext custom TCP exchange. Do not send real credentials or expose it to untrusted networks.
- The server defaults to localhost; broader binding requires explicit configuration and remains the operator's responsibility.
- Detection state is process-local, and distributed detection only identifies a short burst from multiple observed source addresses. It is not reputation analysis or cross-host correlation.
- The service is not protocol-compatible with SSH or HTTP and does not simulate their handshakes.
- Source addresses are taken from the TCP peer address. There is no proxy-header support.
- JSONL is intended for local analysis. CSV export, dashboards, external notifications, firewall integration, and persistent historical analytics are not implemented.
- Thread and field sizes are bounded, but this prototype has not undergone independent security review or production load testing.

## Possible next steps

Add an explicitly scoped protocol-specific service only if there is a concrete monitoring goal, then evaluate the detection rules against labeled localhost scenarios and false-positive cases before considering external integrations.
