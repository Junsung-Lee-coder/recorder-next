#!/bin/sh
# Start the headless Hermes JSON/HTTP backend used only for Recorder TTS.
# The credential value is read at runtime and is never printed or persisted.
set -eu

# Parse bytes before shell assignment: shell read can silently discard NUL.
# Keep this standalone grammar equal to recorder_next.adapters' parser.
# Only the validated token crosses this private pipe; it is never an argv.
session_token=$(python3 - <<'PY'
import os
import re
import sys

try:
    path = os.path.join(os.environ["CREDENTIALS_DIRECTORY"], "recorder_api_key")
    with open(path, "rb") as handle:
        raw = handle.read(4113)
    match = re.fullmatch(rb"API_SERVER_KEY=([A-Za-z0-9._~+/=-]{1,4096})\n?", raw) if len(raw) <= 4112 else None
    if match is None:
        sys.exit(78)
except (OSError, KeyError, ValueError):
    sys.exit(78)
sys.stdout.write(match[1].decode("ascii"))
PY
) || exit 78

# The service unit pins HERMES_HOME to its private StateDirectory.  The
# STATE_DIRECTORY fallback keeps this wrapper usable in a disposable unit
# smoke without changing the production path.
hermes_home="${HERMES_HOME:-${STATE_DIRECTORY:-/var/lib/recorder-next-hermes-tts}}"
case "$hermes_home" in
  /*) ;;
  *) exit 78 ;;
esac
[ -f "$hermes_home/config.yaml" ] || exit 78
mkdir -p "$hermes_home/cron" "$hermes_home/logs" "$hermes_home/sessions"
export HERMES_HOME="$hermes_home"
export HOME="$hermes_home"
[ -f "$hermes_home/active_profile" ] || printf '%s\n' default > "$hermes_home/active_profile"

# `serve` is the supported headless backend. Explicitly remove Desktop-only
# markers so the web-server lifespan cannot start Desktop's cron/orphan path.
unset HERMES_DESKTOP 2>/dev/null || true
unset HERMES_WEB_DIST 2>/dev/null || true
export HERMES_SERVE_HEADLESS=1
export HERMES_DASHBOARD_SESSION_TOKEN="$session_token"
unset session_token

exec /home/rumi/.hermes/hermes-agent/venv/bin/hermes \
  serve \
  --isolated \
  --skip-build \
  --host 127.0.0.1 \
  --port 9120
