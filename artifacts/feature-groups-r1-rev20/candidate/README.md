# Recorder Next v1 standalone server

Recorder Next is a server-only, SQLite-authoritative adapter between Phone/Watch turn uploads and project-scoped Hermes sessions. It is deliberately independent of the legacy Recorder compatibility service, Hermes core/Gateway source, and Android/Wear code.

## Candidate scope

- versioned loopback HTTP API under `/v1`
- durable `ACCEPTED`, `ROUTED`, and `FINAL` event ledger
- immutable turn fingerprint and `(turn_id, part_id, sequence)` chunk receipts
- resumable chunk storage with whole-part SHA-256 verification
- ordered per-user Router queue with persistent lease/CAS takeover
- project registry and `project:<stable_project_id>:default` session seam
- transactional route receipt + ROUTED outbox + Hermes session ingress
- Hermes adapter with message-history fallback, bounded late-result grace, and
  optional startup-resolved Bearer authentication
- normalized/hash-bound Hermes result references and append-only FINAL versions
- ASR realtime → batch → local generation arbitration seam
- origin-device-only text/event/playback ACKs; Watch relay is not playback completion
- TTS artifact spool lifecycle independent from text FINAL terminal state
- restart-safe autonomous worker jobs with leases, retry/deadline recovery,
  frozen provider-chain generations, and effect receipts
- named Hermes/Nemotron/Whisper/Edge ASR/TTS provider registries with explicit
  fallback order, health/capability metadata, media limits, and scoped overrides
- immutable Phone/Wear update manifests with monotonic generations, CAS
  publication, SHA-256/ETag range serving, and APK identity metadata
- project-scoped cursor history read model with path-free attachment summaries
- hash-bound resolver delivery of completed image/document/text attachments into
  Hermes; incomplete or changed bytes fail closed
- Phone-mediated Watch eavesdrop state machine with a separate routing decision
  agent, `FORWARD_DEFAULT`/`STORE_SILENT` outcomes, and no project auto-switch
- opt-in diagnostics with consent revocation, bounded compressed bundles,
  server-side redaction before storage, retention purge, export, and tombstones
- archive-only project/turn retention operations
- clean-install schema, config example, service template, OpenAPI JSON, and deterministic fixtures
- generated multimodal acceptance fixtures under `fixtures/generated/`: offline espeak-ng Korean/English speech, PNG, PDF, UTF-8 text, CSV, and generic binary; each file is hash-bound by `fixtures/generated/manifest.json`

The default candidate uses only Python 3.11+ standard-library modules. Real ASR/TTS/Hermes adapters are injected at the seam. The generated acceptance fixture set contains synthetic speech and files only; no user content is included. Mixed turns are intentionally outside the current Phone/Watch-supported scope.

## Run a local smoke server

```text
python3 -m recorder_next --db /tmp/recorder-next.sqlite3 \\
  --storage-root /tmp/recorder-next-data --host 127.0.0.1 --port 8643
```

The protected legacy port `5000` is rejected by `create_http_server`. The service template is an artifact only; this candidate does not install, enable, start, stop, or restart any live service.

## Test and static checks

```text
python3 -m unittest discover -s tests -v
python3 -m compileall -q recorder_next tests
python3 -m recorder_next --help
```

To regenerate the generated fixture set, provide a local espeak-ng and ffmpeg:

```text
python3 fixtures/generate_multimodal_fixtures.py \\
  --output-root fixtures/generated \\
  --espeak /path/to/espeak-ng \\
  --ffmpeg /usr/bin/ffmpeg \\
  --espeak-data /path/to/espeak-ng-data-parent
```

The generator uses fixed prompts, fixed voice parameters, deterministic mode, and metadata-stripped 16 kHz mono PCM16 WAV output. The acceptance tests exercise voice, text, image, PDF/TXT/CSV, and generic attachment cases as separate single-input turns; they do not implement mixed multipart turns.

The tests use temporary SQLite databases, temporary spool roots, generated fixture bytes, and ephemeral loopback ports. No credentials, devices, AVDs/APKs, legacy databases, or live services are touched.

## API

The machine-readable contract is `api/openapi.json` and is also served at `GET /v1/openapi.json`. The minimal flow is:

1. `POST /v1/turns` with a manifest, or with a safe text fixture payload.
2. `PUT /v1/turns/{turn_id}/parts/{part_id}/chunks/{sequence}` for ordered bytes.
3. `POST /v1/turns/{turn_id}/parts/{part_id}/finish` with totals and whole hash.
4. `POST /v1/turns/{turn_id}/accept` after all parts verify.
5. A separately owned Router worker uses `POST /v1/internal/router` and the project registry.
6. An Hermes worker uses `POST /v1/internal/hermes`; the server stores only delivery references and bounded delivery payloads.
7. Origin-device outbox polling uses `GET /v1/outbox?device_id=...`.
8. Exact event ACK uses `POST /v1/turns/{turn_id}/events/{event_id}/ack`.
9. Target TTS playback completion uses `POST /v1/tts/{artifact_id}/playback-ack`; its JSON body must include the target `device_id`, non-empty exact `payload_sha256`, exact `turn_id`, and positive `artifact_version`. A relay receipt cannot complete playback.
10. An active registered Phone can bridge-read Watch-targeted audio with `GET /v1/tts/{artifact_id}/bridge-read?device_id=...`; bridge reads never authorize playback completion or spool deletion.
11. `GET /v1/updates/{channel}/manifest` and `GET /v1/updates/{channel}/{generation}/{artifact_name}` serve immutable, hash-verified Phone/Wear APK candidates with `Range`, `If-Range`, and `If-None-Match` support.
12. `GET /v1/history?user_id=...&project_id=...&cursor=...` returns the path-free project read model with filter-bound keyset cursors.
13. Phone-owned eavesdrop controls use `POST /v1/eavesdrop`, `POST /v1/eavesdrop/{id}/activate|pause|resume|stop`, `POST /v1/eavesdrop/{id}/segments`, and `POST /v1/eavesdrop/{id}/segments/{sequence}/route`; readback requires the registered Phone owner tuple.
14. Opt-in diagnostics use `POST /v1/diagnostics/opt-in`, `POST /v1/diagnostics/events`, `POST /v1/diagnostics/bundles`, `GET /v1/diagnostics`, `GET /v1/diagnostics/export`, and `DELETE /v1/diagnostics`.
15. The autonomous worker is driven by `POST /v1/internal/worker/run` and read through `GET /v1/internal/worker/health`; each completed job has a bound effect receipt.

Authentication/key management is intentionally a deployment seam in this standalone candidate. The event, bridge-read, eavesdrop read, diagnostics, and artifact handlers enforce registered active device identity; playback completion remains bound to the frozen delivery target and exact artifact receipt.

When the configured Hermes provider is enabled, `hermes_api_key_file` must name
one owner-only credential file containing exactly one ASCII
`API_SERVER_KEY=<value>` entry. The adapter reads it once during startup and
sends an in-memory `Authorization: Bearer <value>` header alongside the existing `X-Hermes-Session-Key`; the value is never logged or persisted.
template uses `LoadCredential=recorder_api_key:...` and
`$CREDENTIALS_DIRECTORY/recorder_api_key`. Rotate the source only with a
Recorder Next restart; do not restart Hermes Gateway.

## Layout

- `recorder_next/store.py` — SQLite schema, transactions, state transitions, leases, outboxes, registry, spool
- `recorder_next/service.py` — Router/ASR/Hermes/TTS orchestration and HTTP routing
- `recorder_next/adapters.py` — injectable Router/Hermes/ASR/TTS seams and privacy-safe fixtures
- `recorder_next/schema.sql` + `migrations/001_initial.sql` … `004_eavesdrop_decisions.sql` — authoritative schema artifacts
- `recorder_next/openapi.py` + `api/openapi.json` — machine-readable v1 contract
- `systemd/recorder-next.service` + `config.example.toml` — non-live deployment artifacts

## Release-control binding

This candidate-only activation and rollback packet is an exact ordered argv contract. Fresh preflight revalidates the packet and binds every manifest, freeze, runtime-preimage, test-ID, and test-source referent by canonical path, size, SHA-256, and semantic fields; any drift is a fail-closed hold.
