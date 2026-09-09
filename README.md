# Recorder Next

Recorder Next is a standalone Python server for Phone and Watch turn uploads.
It uses SQLite as the source of truth and exposes a versioned HTTP API for
turns, projects, event delivery, audio replies, diagnostics, scheduling, and
immutable Phone/Wear update files. It does not replace the legacy Recorder
compatibility service or Hermes Gateway.

## Requirements

- Python 3.11 or newer
- SQLite supplied by Python's standard library
- No runtime third-party dependencies

The optional provider adapters use configured HTTP endpoints. The test suite
uses local fakes and temporary databases; it does not require credentials,
devices, emulators, or a running service.

## Run locally

```text
python3 -m recorder_next --db /tmp/recorder-next.sqlite3 \
  --storage-root /tmp/recorder-next-data --host 127.0.0.1 --port 8643
```

Port 5000 is reserved for the legacy compatibility service and is rejected by
`create_http_server`. The systemd unit in `systemd/recorder-next.service` is a
deployment template; inspect and adapt its paths and credential source before
installing it.

## Check the source

```text
python3 -m unittest discover -s tests -v
python3 -m compileall -q recorder_next tests
python3 -m recorder_next --help
```

The optional multimodal fixture generator needs local `espeak-ng` and
`ffmpeg` binaries:

```text
python3 fixtures/generate_multimodal_fixtures.py \
  --output-root fixtures/generated \
  --espeak /path/to/espeak-ng \
  --ffmpeg /usr/bin/ffmpeg \
  --espeak-data /path/to/espeak-ng-data-parent
```

Supported turn inputs are UTF-8 text (`text/plain`), images (`image/*`), and
canonical PCM16 mono 16 kHz WAV (`audio/wav` or `audio/x-wav`). Document,
CSV, and generic binary inputs are rejected. Mixed multipart input is outside
the Phone/Watch API scope. The generated fixture manifest records the hashes
of the synthetic files used by the tests.

## HTTP API

The machine-readable contract is `api/openapi.json` and is served at
`GET /v1/openapi.json`. The same operation catalog defines request fields,
response status and media types, authentication parameters, range handling,
and the closed JSON error envelope.

The main turn flow is:

1. `POST /v1/turns` creates a manifest or accepts a text turn.
2. `PUT` or `POST /v1/turns/{turn_id}/parts/{part_id}/chunks/{sequence}`
   uploads ordered bytes.
3. `POST /v1/turns/{turn_id}/parts/{part_id}/finish` verifies totals and the
   whole-part hash.
4. `POST /v1/turns/{turn_id}/accept` records durable receipt.
5. `GET /v1/outbox?device_id=...` reads origin-device delivery events.
6. `POST /v1/turns/{turn_id}/events/{event_id}/ack` acknowledges an exact event.

Other API areas include:

- `GET /v1/history` for a project-scoped, path-free history read model.
- `GET /v1/tts/{artifact_id}` for target audio and
  `GET /v1/tts/{artifact_id}/bridge-read` for an authenticated Phone bridge.
- `POST /v1/tts/{artifact_id}/playback-ack` for target playback completion;
  a relay receipt cannot complete playback.
- `GET /v1/updates/{channel}/manifest` and the corresponding artifact route
  for hash-verified Phone/Wear files with `Range`, `If-Range`, `ETag`, and
  `If-None-Match` support. `HEAD` returns the same metadata without a body.
- Phone-owned eavesdrop controls and routing-decision readback under
  `/v1/eavesdrop`.
- Opt-in diagnostic events, bounded bundle storage, export, and deletion under
  `/v1/diagnostics`.
- Project registry, scheduled FINAL creation, and bounded worker controls.

Health, OpenAPI, and immutable update reads are public. Other network
operations require a verified active principal. Direct calls to the service
object are an in-process testing interface, not a network authorization
boundary.

## Authentication and credentials

The trusted ingress signs
`X-Recorder-Principal-User`, a NUL byte, and
`X-Recorder-Principal-Device` with HMAC-SHA256. It sends the lowercase
hexadecimal digest in `X-Recorder-Principal-Signature`. The asserted identity
must agree with matching query, header, and JSON fields, and must be an active
registered device. Legacy `X-Recorder-User-ID` and `X-Recorder-Device-ID`
headers are optional matching assertions.

When the Hermes provider is enabled, `hermes_api_key_file` names an owner-only
credential file containing exactly one ASCII `API_SERVER_KEY=<value>` entry.
The adapter reads it at startup and sends an in-memory Bearer authorization
header plus the preferred `X-Hermes-Session-Token` header. The value is never logged or
persisted. The systemd template uses `LoadCredential=recorder_api_key:...`
and `$CREDENTIALS_DIRECTORY/recorder_api_key`. Rotate the source only with an
authorized Recorder service restart; do not restart Hermes Gateway for this
configuration change.

## Database schema and migrations

`recorder_next/schema.sql` is the clean-install schema and records schema
version `5` in `schema_meta`. Existing databases are upgraded transactionally
by the packaged startup code using these additive migrations:

- `002_scheduled_final.sql` — scheduled FINAL fields and tables.
- `003_feature_groups.sql` — worker jobs, update manifests, eavesdrop, and
  diagnostics tables.
- `004_eavesdrop_decisions.sql` — routing-decision and diagnostic tombstone
  tables/columns.
- `005_r25_contracts.sql` — Hermes run bindings, lease/run metadata, source
  deletion metadata, diagnostic privacy/alias state, and readiness indexes.

The repository-level `migrations/` files and byte-equivalent copies under
`recorder_next/migrations/` are kept together so source inspection and the
installed package describe the same upgrade sequence. Migration 005 is the
single schema-5 upgrade; startup guards each additive change for partial
recovery. Before changing an existing database, take a SQLite backup and
retain it as the rollback source. Do not drop tables to roll back an upgrade.

## Layout

- `recorder_next/service.py` — request dispatch and provider integration.
- `recorder_next/http.py` — bounded HTTP framing and response writing.
- `recorder_next/http_contract.py` — operation catalog and OpenAPI projection.
- `recorder_next/api_models.py` — closed request DTO descriptors.
- `recorder_next/store.py` and `recorder_next/features.py` — SQLite state and
  durable feature operations.
- `recorder_next/adapters.py` — injectable Router, Hermes, ASR, and TTS seams.
- `recorder_next/schema.sql` and `migrations/` — schema definitions and
  upgrade SQL.
- `config.example.toml` and `systemd/` — deployment configuration examples.