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
        "/v1/tts/{artifact_id}": {"get": {"responses": {"200": {"description": "Origin-device TTS payload"}}}},
        "/v1/tts/{artifact_id}/playback-ack": {"post": {"responses": {"200": {"description": "Origin playback completion"}}}},
        "/v1/tts/{artifact_id}/relay-received": {"post": {"responses": {"200": {"description": "Non-origin relay receipt"}}}},
        "/v1/projects": {"get": {"responses": {"200": {"description": "Project registry"}}}, "post": {"responses": {"201": {"description": "Project"}}}},
        "/v1/projects/search": {"get": {"responses": {"200": {"description": "Project search"}}}},
        "/v1/projects/{project_id}": {"get": {"responses": {"200": {"description": "Project"}}}, "patch": {"responses": {"200": {"description": "CAS update"}}}},
        "/v1/turns/{turn_id}/archive": {"post": {"responses": {"200": {"description": "Archive-only turn retention"}}}},
        "/v1/projects/{project_id}/archive": {"post": {"responses": {"200": {"description": "Archive-only transition"}}}},
        "/v1/internal/router": {"post": {"responses": {"200": {"description": "Internal router worker step"}}}},
        "/v1/internal/hermes": {"post": {"responses": {"200": {"description": "Internal Hermes worker step"}}}},
        "/v1/internal/tts": {"post": {"responses": {"200": {"description": "Internal TTS worker step"}}}},
    },
    "components": {
        "parameters": {"TurnId": {"name": "turn_id", "in": "path", "required": True, "schema": {"type": "string", "format": "uuid"}}},
        "schemas": {
            "TurnState": {"type": "string", "enum": ["RECEIVING", "ACCEPTED", "PREPROCESSING", "ROUTING", "ROUTED", "HERMES_PENDING", "FINAL_READY", "DELIVERY_PENDING", "RETRY_WAIT", "LATE_RESULT_GRACE", "DELIVERED", "FAILED_PERMANENT", "EXPIRED"]},
            "EventKind": {"type": "string", "enum": ["ACCEPTED", "ROUTED", "FINAL"]},
            "ArtifactState": {"type": "string", "enum": ["PENDING", "READY", "DELIVERY_PENDING", "PLAYED", "FAILED_GENERATION", "EXPIRED"]},
            "Error": {"type": "object", "required": ["error"], "properties": {"error": {"type": "object", "properties": {"code": {"type": "string"}, "message": {"type": "string"}}}}},
        },
    },
}
