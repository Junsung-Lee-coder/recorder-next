"""Machine-readable Recorder Next v1 HTTP contract."""

OPENAPI = {
    "openapi": "3.0.3",
    "info": {
        "title": "Recorder Next Server",
        "version": "1.0.0",
        "description": "Standalone reliable Recorder adapter; Hermes core and legacy port 5000 are out of scope.",
    },
    "servers": [{"url": "/"}],
    "paths": {
        "/v1/health": {"get": {"responses": {"200": {"description": "Readiness"}}}},
        "/v1/openapi.json": {"get": {"responses": {"200": {"description": "This contract"}}}},
        "/v1/devices": {"post": {"responses": {"201": {"description": "Registered device"}}}},
        "/v1/devices/{device_id}/revoke": {"post": {"responses": {"200": {"description": "Revoked device"}}}},
        "/v1/turns": {
            "post": {
                "summary": "Create an immutable turn envelope or complete a text turn",
                "responses": {"201": {"description": "Receiving turn"}, "202": {"description": "Accepted text turn"}, "409": {"description": "TURN_ID_CONFLICT"}},
            }
        },
        "/v1/turns/{turn_id}": {"get": {"parameters": [{"$ref": "#/components/parameters/TurnId"}], "responses": {"200": {"description": "Turn ledger"}}}},
        "/v1/turns/{turn_id}/accept": {"post": {"responses": {"200": {"description": "Durable ACCEPTED"}, "409": {"description": "Incomplete parts"}}}},
        "/v1/turns/{turn_id}/parts/{part_id}/chunks/{sequence}": {"put": {"responses": {"200": {"description": "Chunk receipt"}, "409": {"description": "Chunk conflict"}}}},
        "/v1/turns/{turn_id}/parts/{part_id}/missing": {"get": {"responses": {"200": {"description": "Missing sequence list"}}}},
        "/v1/turns/{turn_id}/parts/{part_id}/finish": {"post": {"responses": {"200": {"description": "Verified part"}}}},
        "/v1/turns/{turn_id}/events/{event_id}/ack": {"post": {"responses": {"200": {"description": "Event ACK"}}}},
        "/v1/outbox": {"get": {"responses": {"200": {"description": "Origin-device ordered outbox"}}}},
        "/v1/tts/{artifact_id}": {
            "get": {
                "summary": "Read target TTS or bridge it through an authenticated registered Phone",
                "parameters": [{"$ref": "#/components/parameters/ArtifactId"}, {"$ref": "#/components/parameters/DeviceId"}],
                "responses": {"200": {"description": "TTS payload"}, "401": {"description": "Device is not the target or an active Phone bridge"}, "409": {"description": "TTS payload is unavailable"}},
            }
        },
        "/v1/tts/{artifact_id}/bridge-read": {
            "get": {
                "summary": "Read Watch-targeted TTS through an authenticated registered Phone bridge",
                "parameters": [{"$ref": "#/components/parameters/ArtifactId"}, {"$ref": "#/components/parameters/DeviceId"}],
                "responses": {"200": {"description": "TTS payload"}, "401": {"description": "Active registered Phone bridge required"}, "409": {"description": "TTS payload is unavailable"}},
            }
        },
        "/v1/tts/{artifact_id}/playback-ack": {
            "post": {
                "summary": "Complete playback on the actual TTS delivery target",
                "parameters": [{"$ref": "#/components/parameters/ArtifactId"}],
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PlaybackAck"}}}},
                "responses": {"200": {"description": "Target playback completion"}, "400": {"description": "Required receipt field missing or invalid"}, "401": {"description": "Only the delivery target may complete playback"}, "409": {"description": "Receipt does not match the stored artifact"}},
            }
        },
        "/v1/tts/{artifact_id}/relay-received": {"post": {"responses": {"200": {"description": "Non-origin relay receipt"}}}},
        "/v1/projects": {"get": {"responses": {"200": {"description": "Project registry"}}}, "post": {"responses": {"201": {"description": "Project"}}}},
        "/v1/projects/search": {"get": {"responses": {"200": {"description": "Project search"}}}},
        "/v1/projects/{project_id}": {"get": {"responses": {"200": {"description": "Project"}}}, "patch": {"responses": {"200": {"description": "CAS update"}}}},
        "/v1/turns/{turn_id}/archive": {"post": {"responses": {"200": {"description": "Archive-only turn retention"}}}},
        "/v1/projects/{project_id}/archive": {"post": {"responses": {"200": {"description": "Archive-only transition"}}}},
        "/v1/internal/router": {"post": {"responses": {"200": {"description": "Internal router worker step"}}}},
        "/v1/internal/hermes": {"post": {"responses": {"200": {"description": "Internal Hermes worker step"}}}},
        "/v1/internal/tts": {"post": {"responses": {"200": {"description": "Internal TTS worker step"}}}},
        "/v1/internal/schedule_create": {"post": {"summary": "Trusted Recorder adapter schedule creation", "responses": {"201": {"description": "Durably scheduled with atomic confirmation FINAL"}, "401": {"description": "Trusted adapter header required"}, "409": {"description": "Immutable schedule conflict"}}}},
        "/v1/internal/scheduler/fire": {"post": {"summary": "Claim and fire due server schedules", "responses": {"200": {"description": "Scheduled FINAL readback"}}}},
        "/v1/internal/scheduler/recover": {"post": {"summary": "Requeue expired scheduler leases", "responses": {"200": {"description": "Recovery counts"}}}},
        "/v1/schedules/{schedule_id}": {"get": {"parameters": [{"name": "schedule_id", "in": "path", "required": True, "schema": {"type": "string"}}], "responses": {"200": {"description": "Schedule and occurrence readback"}}}},
        "/v1/updates/{channel}/manifest": {"get": {"responses": {"200": {"description": "Current immutable channel manifest"}}}},
        "/v1/updates/{channel}/{generation}/{artifact_name}": {"get": {"responses": {"200": {"description": "Hash-bound APK bytes"}, "206": {"description": "Byte range"}, "304": {"description": "ETag matched"}, "416": {"description": "Unsatisfiable range"}}}, "head": {"responses": {"200": {"description": "APK metadata"}}}},
        "/v1/history": {"get": {"summary": "Project-scoped keyset history read model", "responses": {"200": {"description": "Paired user/assistant messages"}}}},
        "/v1/eavesdrop": {"post": {"summary": "Start a phone-mediated eavesdrop session", "responses": {"201": {"description": "Created session"}}}},
        "/v1/eavesdrop/{session_id}": {"get": {"responses": {"200": {"description": "Session state"}}}},
        "/v1/eavesdrop/{session_id}/{action}": {"post": {"parameters": [{"name": "action", "in": "path", "required": True, "schema": {"type": "string", "enum": ["activate", "pause", "resume", "stop", "segments"]}}], "responses": {"200": {"description": "State transition or segment receipt"}}}},
        "/v1/eavesdrop/{session_id}/replies": {"get": {"responses": {"200": {"description": "Optional response receipts"}}}},
        "/v1/diagnostics/opt-in": {"post": {"responses": {"201": {"description": "Consent event"}}}},
        "/v1/diagnostics/events": {"post": {"responses": {"201": {"description": "Redacted diagnostic event"}}}},
        "/v1/diagnostics/bundles": {"post": {"responses": {"201": {"description": "Bounded compressed diagnostic bundle"}}}},
        "/v1/diagnostics": {"get": {"responses": {"200": {"description": "Diagnostic metadata"}}}, "delete": {"responses": {"200": {"description": "Deletion receipt and tombstones"}}}},
        "/v1/diagnostics/delete": {"post": {"responses": {"200": {"description": "Deletion receipt and tombstones"}}}},
        "/v1/internal/worker/{action}": {"post": {"responses": {"200": {"description": "Durable worker lease operation"}}}},
        "/v1/internal/worker/health": {"get": {"responses": {"200": {"description": "Bounded worker backlog and lease health"}}}},
        "/v1/eavesdrop/{session_id}/segments/{segment_sequence}/route": {"post": {"responses": {"200": {"description": "Idempotent fixed-project routing decision"}}}},
        "/v1/eavesdrop/{session_id}/decisions": {"get": {"responses": {"200": {"description": "Eavesdrop routing decision ledger"}}}},
        "/v1/diagnostics/export": {"get": {"responses": {"200": {"description": "Redacted diagnostic export"}}}},
    },
    "components": {
        "parameters": {
            "TurnId": {"name": "turn_id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}},
            "ArtifactId": {"name": "artifact_id", "in": "path", "required": True, "schema": {"type": "string"}},
            "DeviceId": {"name": "device_id", "in": "query", "required": True, "description": "Registered active device identity; a Phone may bridge-read a Watch-targeted artifact.", "schema": {"type": "string", "minLength": 1}},
        },
        "schemas": {
            "TurnState": {"type": "string", "enum": ["RECEIVING", "ACCEPTED", "PREPROCESSING", "ROUTING", "ROUTED", "HERMES_PENDING", "FINAL_READY", "DELIVERY_PENDING", "RETRY_WAIT", "LATE_RESULT_GRACE", "DELIVERED", "FAILED_PERMANENT", "EXPIRED"]},
            "EventKind": {"type": "string", "enum": ["ACCEPTED", "ROUTED", "FINAL"]},
            "ArtifactState": {"type": "string", "enum": ["PENDING", "READY", "DELIVERY_PENDING", "PLAYED", "FAILED_GENERATION", "EXPIRED"]},
            "ScheduleState": {"type": "string", "enum": ["SCHEDULED", "CLAIMED", "FIRED", "FAILED", "CANCELLED"]},
            "ServerTurnSource": {"type": "string", "enum": ["server_schedule"]},
            "PlaybackAck": {
                "type": "object",
                "required": ["device_id", "payload_sha256", "turn_id", "artifact_version"],
                "additionalProperties": False,
                "properties": {
                    "device_id": {"type": "string", "minLength": 1},
                    "payload_sha256": {"type": "string", "minLength": 1},
                    "turn_id": {"type": "string", "format": "uuid", "minLength": 1},
                    "artifact_version": {"type": "integer", "minimum": 1},
                },
            },
            "Error": {"type": "object", "required": ["error"], "properties": {"error": {"type": "object", "properties": {"code": {"type": "string"}, "message": {"type": "string"}}}}},
        },
    },
}
