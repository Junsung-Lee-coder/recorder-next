"""Task-scoped R19 packet producer. Capture is read-only outside its output root."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

# B6 (REV-012): historical release_control/runtime_readback imports are
# optional and live only behind the operations that need them, so pure
# projection helpers and their tests import this module without those
# (non-archived) control files.
try:
    sys.path.insert(0, str(ROOT / "control"))
    import release_control as control  # type: ignore[import-not-found]
    import runtime_readback as runtime  # type: ignore[import-not-found]
except ModuleNotFoundError:  # pragma: no cover - archived-candidate import path
    control = None  # type: ignore[assignment]
    runtime = None  # type: ignore[assignment]

_HERMES_LAUNCHER_SCRIPT = "/home/rumi/.hermes/hermes-agent/venv/bin/hermes"
_PYTHON_BASENAME_RE = re.compile(r"python(?:3(?:\.\d+)?)?$")
_ARGV_MAX_TOKENS = 32
_ARGV_MAX_TOKEN_LEN = 4096
_ARGV_MAX_TOTAL = 16 * 1024
_ARGV_SENSITIVE_FLAGS = frozenset({
    "api-key", "api_key", "key", "token", "access-token", "access_token",
    "authorization", "password", "passwd", "secret", "client-secret",
    "client_secret", "cookie",
})


def _canonical_port(value: int) -> str:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("port must be an actual int in 1..65535")
    return str(value)


def project_runtime_argv(argv, *, role, executable, config, port):
    """Fail-closed structural argv projection (B6 REV-012).

    Reconstructs the managed runtime argv entirely from an allowlisted
    grammar plus trusted runtime identity.  Returns the reconstructed vector
    byte-for-byte equal to the actual argv when safe; raises ValueError for
    any argv that cannot be proven safe (unknown/duplicate/reordered/inline
    flags, credential-bearing or secret-shaped tokens, oversize input), so
    raw argv is never persisted.
    """
    if role not in {"recorder", "hermes"}:
        raise ValueError("runtime role is invalid")
    if not isinstance(argv, (list, tuple)) or not argv or len(argv) > _ARGV_MAX_TOKENS:
        raise ValueError("runtime argv shape is unsafe")
    exe = str(executable)
    if not exe or len(exe) > 4096 or _PYTHON_BASENAME_RE.search(PurePosixPath(exe.replace("\\", "/")).name) is None:
        raise ValueError("runtime executable is not a canonical Python interpreter")
    canonical_config = str(config)
    if not canonical_config or len(canonical_config) > 4096:
        raise ValueError("runtime config path is invalid")
    port_token = _canonical_port(port)

    tokens = [str(token) for token in argv]
    if any(len(token) > _ARGV_MAX_TOKEN_LEN for token in tokens):
        raise ValueError("runtime argv token is oversize")
    if sum(len(token) + 1 for token in tokens) > _ARGV_MAX_TOTAL:
        raise ValueError("runtime argv total size is oversize")
    if any(any(ord(char) < 0x20 for char in token) for token in tokens):
        raise ValueError("runtime argv contains control characters")

    def reject_token(token: str, index: int) -> None:
        lowered = token.lower()
        stripped = lowered.lstrip("-")
        if stripped in _ARGV_SENSITIVE_FLAGS or lowered in _ARGV_SENSITIVE_FLAGS:
            raise ValueError("credential-bearing flag cannot enter the projection")
        if any(marker in lowered for marker in ("token=", "key=", "api_key=", "api-key=", "password=", "secret=", "authorization=", "bearer ")):
            raise ValueError("credential-shaped value cannot enter the projection")
        if "://" in token or "@" in token:
            raise ValueError("URL/userinfo token cannot enter the projection")
        if token == "--":
            raise ValueError("end-of-options sentinel is not admitted")
        if index > 0 and token.startswith("-") and "=" in token:
            raise ValueError("inline option values are not admitted")

    for index, token in enumerate(tokens):
        reject_token(token, index)

    rest = tokens[1:] if tokens[0] in {exe, "-B", "-s"} or tokens[0].endswith("python3") or tokens[0].endswith("python") else tokens
    # Grammar 1: recorder launcher
    #   <python> [-B] [-s] -m recorder_next --config <config> [--host 127.0.0.1] [--port <port>]
    cursor = 0
    if tokens[0] == exe:
        cursor = 1
    saw_b = saw_s = False
    while cursor < len(tokens) and tokens[cursor] in {"-B", "-s"}:
        if tokens[cursor] == "-B":
            if saw_b:
                raise ValueError("duplicate launcher flag")
            saw_b = True
        else:
            if saw_s:
                raise ValueError("duplicate launcher flag")
            saw_s = True
        cursor += 1
    if cursor < len(tokens) and tokens[cursor] == "-m":
        cursor += 1
        if cursor >= len(tokens) or tokens[cursor] != "recorder_next":
            raise ValueError("unknown module for the recorder launcher")
        cursor += 1
        if cursor >= len(tokens) or tokens[cursor] != "--config":
            raise ValueError("recorder launcher requires --config next")
        cursor += 1
        if cursor >= len(tokens) or tokens[cursor] != canonical_config:
            raise ValueError("config path does not match the trusted runtime identity")
        cursor += 1
        # Exact canonical order after --config: [--host 127.0.0.1] [--port N].
        host_seen = port_seen = False
        reconstructed = [exe]
        if saw_b:
            reconstructed.append("-B")
        if saw_s:
            reconstructed.append("-s")
        reconstructed += ["-m", "recorder_next", "--config", canonical_config]
        while cursor < len(tokens):
            flag = tokens[cursor]
            if flag == "--host" and not host_seen and not port_seen:
                host_seen = True
                cursor += 1
                if cursor >= len(tokens) or tokens[cursor] != "127.0.0.1":
                    raise ValueError("host must be the loopback literal")
                reconstructed += ["--host", "127.0.0.1"]
                cursor += 1
            elif flag == "--port" and not port_seen:
                port_seen = True
                cursor += 1
                if cursor >= len(tokens) or tokens[cursor] != port_token:
                    raise ValueError("port does not match the trusted runtime identity")
                reconstructed += ["--port", port_token]
                cursor += 1
            else:
                raise ValueError(f"unknown or reordered recorder flag: {flag!r}")
        return reconstructed

    # Grammar 2: hermes gateway/run launcher
    if tokens[0] == _HERMES_LAUNCHER_SCRIPT:
        if len(tokens) >= 2 and tokens[1] == "gateway" and len(tokens) == 3 and tokens[2] == "run":
            return [tokens[0], "gateway", "run"]
        if (len(tokens) == 8 and tokens[1] == "serve"
                and tokens[2] == "--isolated" and tokens[3] == "--skip-build"
                and tokens[4] == "--host" and tokens[5] == "127.0.0.1"
                and tokens[6] == "--port" and tokens[7] == port_token):
            return [_HERMES_LAUNCHER_SCRIPT, "serve", "--isolated", "--skip-build", "--host", "127.0.0.1", "--port", port_token]
        raise ValueError("unknown hermes launcher shape")
    raise ValueError("runtime argv does not match any admitted launcher grammar")

GENERATION = "recorder-next-live-r19-r23p2-provenance-support-producer-closure-candidate"
PRODUCT = "recorder-next-server-product-items-1-through-8"
BASE = "ab98a7feea910b1f546a847175a66459dee78ca9"
TARGET_MAIN = "32fc5f4b31b8282d1b182ea6cfad86e3ed6d6d91"
# This producer starts from the failed candidate object and permits no
# product/test delta; the repair is limited to provenance/support bytes.
AUTHORIZED_PRODUCT_CHANGES = set()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Only the private, not-yet-frozen producer namespace is writable.
    # Replace its read-only projection, never chmod a sealed referent in place.
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as handle:
        handle.write(json.dumps(value, sort_keys=True, indent=2) + "\n")
        temp = Path(handle.name)
    temp.chmod(0o444)
    os.replace(temp, path)


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()


def desc(root, path, mode=False):
    value = {"path": str(path.relative_to(root)), "sha256": sha(path), "size": path.stat().st_size}
    if mode:
        value["mode"] = f"{stat.S_IMODE(path.stat().st_mode):04o}"
    return value


def source_names():
    names = git("ls-files").splitlines()
    names += git("ls-files", "--others", "--exclude-standard", "recorder_next", "tests", "control", "release_tests").splitlines()
    return sorted({name for name in names if not name.startswith(("artifacts/", "evidence/"))})


def credential(path):
    # Explicit metadata-only boundary; never read or hash a credential.
    info = Path(path).lstat()
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError("credential metadata target is not regular")
    return dict(path=str(path), mode=stat.S_IMODE(info.st_mode), uid=info.st_uid,
                gid=info.st_gid, size=info.st_size)


def modules(root, hermes=False):
    root = Path(root)
    if hermes:
        names = subprocess.check_output(["git", "-C", str(root), "ls-files"], text=True).splitlines()
        paths = [root / name for name in names if name.endswith(".py") or name in {"pyproject.toml", "requirements.txt", "uv.lock"}]
        paths.append(root / "venv/bin/hermes")
    else:
        paths = [p for p in (root / "recorder_next").rglob("*") if p.suffix in {".py", ".sql"}]
    result = []
    for path in sorted(paths):
        if not path.is_file() or path.is_symlink():
            raise RuntimeError("runtime closure has a missing/nonregular source")
        result.append({"path": str(path.relative_to(root)), "sha256": sha(path)})
    if not result:
        raise RuntimeError("empty runtime closure")
    return result


def observed(role, unit, port, config, credentials, *, profile="default"):
    manager = ["systemctl", "--user"] if role == "hermes" else ["systemctl"]
    pid = int(subprocess.check_output([*manager, "show", unit, "--value", "--property=MainPID"], text=True))
    if pid <= 0:
        raise RuntimeError("mandatory active runtime missing")
    argv = runtime._cmdline(pid)
    argv = project_runtime_argv(
        argv,
        role=role,
        executable=Path(os.path.realpath(f"/proc/{pid}/exe")),
        config=config,
        port=port,
    )
    uid, gid = runtime._uid_gid(pid)
    root = Path(os.path.realpath(f"/proc/{pid}/cwd"))
    exe = Path(os.path.realpath(f"/proc/{pid}/exe"))
    config = str(Path(config))
    return {"expected_state": "active", "unit": unit, "port": port,
            "runtime_root": str(root), "expected_config": config,
            "expected_config_sha256": sha(config), "expected_profile": profile,
            "expected_profile_sha256": runtime.profile_sha256(profile),
            "expected_uid": uid, "expected_gid": gid, "expected_exe": str(exe),
            "expected_exe_sha256": sha(f"/proc/{pid}/exe"), "expected_version": runtime._version(pid),
            "expected_argv": argv, "expected_cgroup": runtime._cgroup(pid),
            "expected_files": modules(root, role == "hermes"), "expected_credentials": credentials}


def capture(output, *, hermes_unit="hermes-recorder-api-server.service", hermes_profile=None,
            hermes_config=None, hermes_credential=None):
    output.mkdir(parents=True, exist_ok=False)
    template = json.loads((ROOT / "control/transaction-manifest.json").read_text())
    rows, disposable = [], []
    for original in template["targets"]:
        row = copy.deepcopy(original)
        path = Path("/") / row["target"]
        if row["source"] is None:
            if path.exists() or path.is_symlink():
                raise RuntimeError("create-only opening directory is not absent: " + row["target"])
        elif path.exists():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError("nonregular target opening")
            data = path.read_bytes()
            row["preimage"] = dict(exists=True, sha256=hashlib.sha256(data).hexdigest(),
                                   mode=f"{stat.S_IMODE(info.st_mode):04o}", size=len(data))
            rel = "preimages/" + row["target"]
            dest = output / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(data)
            dest.chmod(0o444)
            disposable.append(dict(source="disposable/" + rel, target=row["target"],
                                   sha256=sha(dest), mode=row["preimage"]["mode"], size=len(data)))
        else:
            row["preimage"] = dict(exists=False, sha256=None, mode=None, size=None)
        rows.append(row)
    profile = hermes_profile or os.environ.get("R19_HERMES_PROFILE")
    if profile is None:
        profile = hermes_unit.removeprefix("hermes-").removesuffix(".service")
    if not runtime.PROFILE_RE.fullmatch(profile):
        raise RuntimeError("Hermes profile is invalid")
    config = Path(hermes_config) if hermes_config is not None else Path.home() / ".hermes" / "profiles" / profile / "config.yaml"
    source_credential = credential(hermes_credential or "/home/rumi/.hermes/profiles/default/recorder-worker-api-key.env")
    delivered = credential("/run/credentials/recorder-next.service/recorder_api_key")
    hermes = observed("hermes", hermes_unit, 8642, config, [source_credential], profile=profile)
    recorder = observed("recorder", "recorder-next.service", 8653,
                        "/etc/recorder-next/recorder-next.toml", [delivered])
    tts = copy.deepcopy(hermes)
    executable_script = Path("/home/rumi/.hermes/hermes-agent/venv/bin/hermes")
    shebang = executable_script.open().readline().strip()
    if not shebang.startswith("#!/"):
        raise RuntimeError("TTS entrypoint interpreter is unbound")
    tts.update(expected_state="absent", unit="hermes-dashboard-tts.service", port=9120,
               expected_config="/var/lib/recorder-next-hermes-tts/config.yaml",
               expected_config_sha256=sha(ROOT / "control/hermes-tts-state-config.yaml"),
               expected_profile="default", expected_profile_sha256=runtime.profile_sha256("default"),
               expected_argv=[shebang[2:], str(executable_script), "serve", "--isolated", "--skip-build", "--host", "127.0.0.1", "--port", "9120"],
               expected_cgroup="/system.slice/hermes-dashboard-tts.service")
    bindings = {"preflight": {"hermes": hermes, "recorder": recorder, "tts": tts}}
    bindings["postactivation"] = copy.deepcopy(bindings["preflight"])
    post = bindings["postactivation"]
    post["tts"]["expected_state"] = "active"
    post["tts"]["expected_credentials"] = [dict(delivered, path="/run/credentials/hermes-dashboard-tts.service/recorder_api_key")]
    post["recorder"]["expected_files"] = [dict(path=row["target"].removeprefix("opt/recorder-next/"), sha256=sha(ROOT / row["source"].removeprefix("candidate/"))) for row in rows if row["source"] is not None and row["target"].startswith("opt/recorder-next/")]
    control.validate_runtime_bindings(bindings)
    write(output / "opening.json", {"schema": "recorder-next-r19-opening/v1", "targets": rows,
                                    "runtime_bindings": bindings, "credential_content_read": False,
                                    "main": git("rev-parse", "main")})
    write(output / "preimage-manifest.json", {"rows": disposable})
    print(json.dumps({"status": "CAPTURED", "targets": len(rows), "opening_sha256": sha(output / "opening.json")}))


def prepare(opening, packet):
    packet.mkdir(parents=True, exist_ok=False)
    names = source_names()
    protected = [name for name in names if name.startswith(("recorder_next/", "tests/")) or name in {"pyproject.toml", "control/start-hermes-dashboard-tts.sh"}]
    changed_protected = []
    for name in protected:
        exists_in_base = subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "-e", BASE + ":" + name],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).returncode == 0
        original = subprocess.check_output(["git", "-C", str(ROOT), "show", BASE + ":" + name]) if exists_in_base else None
        if original != (ROOT / name).read_bytes():
            changed_protected.append(name)
    unexpected_changes = sorted(set(changed_protected) - AUTHORIZED_PRODUCT_CHANGES)
    if unexpected_changes:
        raise RuntimeError("unqualified product bytes changed: " + ", ".join(unexpected_changes))
    if git("rev-parse", "main") != TARGET_MAIN:
        raise RuntimeError("canonical main drift")
    source_commit, source_tree = git("rev-parse", "HEAD"), git("rev-parse", "HEAD^{tree}")
    vector = []
    product_names = [name for name in names if not name.startswith(("control/", "release_tests/"))]
    for name in names:
        path = ROOT / name
        vector.append(dict(path=name, sha256=sha(path), size=path.stat().st_size))
        if name in product_names or name.startswith(("control/", "release_tests/")):
            dest = packet / ("candidate/" + name if name in product_names else name)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, dest)
            dest.chmod(0o444)
    # The official projection minimum includes the qualified standalone launcher.
    extra = "control/start-hermes-dashboard-tts.sh"
    target = packet / "candidate" / extra
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / extra, target)
    target.chmod(0o444)
    members = [desc(packet / "candidate", p, True) for p in sorted((packet / "candidate").rglob("*")) if p.is_file()]
    product_sha = hashlib.sha256(json.dumps(members, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    identity_sha = hashlib.sha256(json.dumps(vector, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    candidate_id = GENERATION + "-" + identity_sha[:16]
    with tarfile.open(packet / "candidate-source.tar.gz", "w:gz") as archive:
        for row in members:
            archive.add(packet / "candidate" / row["path"], arcname="candidate/" + row["path"], recursive=False)
    (packet / "candidate-source.tar.gz").chmod(0o444)
    with tarfile.open(packet / "source-snapshot.tar.gz", "w:gz") as archive:
        for name in names:
            archive.add(ROOT / name, arcname=name, recursive=False)
    (packet / "source-snapshot.tar.gz").chmod(0o444)
    write(packet / "source-vector.json", {"commit": source_commit, "tree": source_tree, "rows": vector,
                                         "protected_count": len(protected), "protected_paths": protected})
    snapshot = json.loads((opening / "opening.json").read_text())
    shutil.copytree(opening, packet / "disposable")
    tx = json.loads((ROOT / "control/transaction-manifest.json").read_text())
    tx.update(schema=control.TRANSACTION_SCHEMA, generation=GENERATION,
              candidate=dict(id=candidate_id, sha256=identity_sha, product_sha256=product_sha),
              targets=snapshot["targets"], runtime_bindings=snapshot["runtime_bindings"],
              target_binding={"candidate_source_commit": source_commit, "candidate_source_tree": source_tree})
    for row in tx["targets"]:
        if row["source"] is not None:
            path = packet / row["source"]
            row["postimage"] = dict(exists=True, sha256=sha(path), mode=f"{stat.S_IMODE(path.stat().st_mode):04o}", size=path.stat().st_size)
    write(packet / "control/transaction-manifest.json", tx)
    candidate = dict(schema="recorder-next-candidate/v1", generation=GENERATION, candidate_id=candidate_id,
                     candidate_sha256=identity_sha, product_sha256=product_sha, product_identity=PRODUCT,
                     source_commit=source_commit, source_tree=source_tree, source_archive=desc(packet, packet / "candidate-source.tar.gz"),
                     candidate_members=members, candidate_file_count=len(members), candidate_only_not_applied=True)
    write(packet / "candidate-manifest.json", candidate)
    helpers = []
    roles = {"release_control.py": "operator", "runtime_readback.py": "readback", "semantic_probe.py": "semantic_probe",
             "operator-bootstrap.py": "bootstrap", "verify_packet.py": "candidate-verifier", "disposable_apply.py": "disposable"}
    for name, role in roles.items():
        path = packet / "control" / name
        helpers.append(dict(path="control/" + name, sha256=sha(path), mode="0444", role=role))
    manifest: dict[str, Any] = {key: {} for key in control.PACKET_KEYS}
    manifest.update(schema=control.PACKET_SCHEMA, generation=GENERATION, status="candidate_incomplete",
                    status_detail="Self-verification in progress; not approved for live apply",
                    candidate=dict(id=candidate_id, sha256=identity_sha, product_sha256=product_sha,
                                   source_commit=source_commit, source_tree=source_tree,
                                   archive=desc(packet, packet / "candidate-source.tar.gz"),
                                   manifest=desc(packet, packet / "candidate-manifest.json", True)),
                    helpers=helpers, transaction=dict(desc(packet, packet / "control/transaction-manifest.json"), target_count=len(tx["targets"])),
                    external_binding={"runtime_bindings": snapshot["runtime_bindings"]},
                    public_ancestry={"target_main": TARGET_MAIN, "source_commit": source_commit},
                    scope={"product_identity": PRODUCT, "live_mutation": False, "product_bytes_changed": True},
                    apply_contract={"mode": "direct-replacement", "review_required": True, "root_owned_packet_required": True,
                                    "live_root": "/", "state_root": "/var/lib/recorder-next/state", "receipts_root": "/var/lib/recorder-next/receipts",
                                    "gateway_mutation": False, "automatic_rollback": False})
    stage = "/opt/recorder-next-release-r19-control-caller-r2/packet"
    common = ["--packet-root", stage, "--live-root", "/", "--state-root", "/var/lib/recorder-next/state",
              "--receipts-root", "/var/lib/recorder-next/receipts", "--candidate-id", candidate_id,
              "--candidate-sha256", identity_sha, "--mode", "live"]
    manifest["apply_contract"].update(
        stage_root=stage,
        apply_argv=["/usr/bin/python3.13", stage + "/control/operator-bootstrap.py", "apply", *common, "--confirm-live"],
        verify_argv=["/usr/bin/python3.13", stage + "/control/release_control.py", "verify", *common],
        readback_argv=["/usr/bin/python3.13", stage + "/control/operator-bootstrap.py", "readback", *common, "--confirm-live"],
    )
    write(packet / "packet-manifest.json", manifest)
    from verify_packet import verify_candidate
    write(packet / "evidence/candidate-verification.json", dict(status="PASS", **verify_candidate(packet, candidate)))
    freeze(packet)
    print(json.dumps({"status": "PREPARED", "candidate_id": candidate_id, "candidate_sha256": identity_sha,
                      "product_count": len(members), "protected_count": len(protected)}))


def freeze(packet):
    # The privileged bootstrap stays stdlib-only before it authenticates
    # helpers. The producer consumes that bootstrap's schema and fails closed
    # if the independent archive consumer disagrees.
    import runpy
    bootstrap_schema = runpy.run_path(str(ROOT / "control/operator-bootstrap.py"))["FREEZE_SCHEMA"]
    if bootstrap_schema != control.FREEZE_SCHEMA:
        raise RuntimeError("bootstrap/archive freeze schema mismatch")
    manifest = json.loads((packet / "packet-manifest.json").read_text())
    excluded = ["freeze-vector.json", "packet-manifest.json"]
    rows = []
    projection = hashlib.sha256()
    for path in sorted(packet.rglob("*"), key=lambda item: str(item.relative_to(packet))):
        if path.is_file() and str(path.relative_to(packet)) not in excluded:
            path.chmod(0o444)
            row = desc(packet, path, True)
            rows.append(row)
            projection.update(row["path"].encode() + b"\0" + row["sha256"].encode() + b"\n")
    freeze_doc = dict(schema=bootstrap_schema, generation=GENERATION, rows=rows, entry_count=len(rows),
                      projection_sha256=projection.hexdigest(), excluded_paths=excluded)
    write(packet / "freeze-vector.json", freeze_doc)
    manifest["freeze"] = {key: freeze_doc[key] for key in ("entry_count", "excluded_paths", "projection_sha256")}
    manifest["freeze"]["path"] = "freeze-vector.json"
    write(packet / "packet-manifest.json", manifest)
    # Seal the directory graph as well as the files.  A read-only file under
    # a writable directory is still replaceable through rename.
    for path in sorted((item for item in [packet, *packet.rglob("*")] if item.is_dir() and not item.is_symlink()),
                       key=lambda item: len(item.parts), reverse=True):
        path.chmod(0o555)
    control.load_packet(packet, require_read_only=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("capture", "prepare", "freeze"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--opening", type=Path)
    parser.add_argument("--hermes-unit", default="hermes-recorder-api-server.service")
    parser.add_argument("--hermes-profile")
    parser.add_argument("--hermes-config", type=Path)
    parser.add_argument("--hermes-credential", type=Path)
    args = parser.parse_args()
    if args.command == "capture":
        capture(args.output.absolute(), hermes_unit=args.hermes_unit, hermes_profile=args.hermes_profile,
                hermes_config=args.hermes_config, hermes_credential=args.hermes_credential)
    elif args.command == "prepare":
        prepare(args.opening.absolute(), args.output.absolute())
    else:
        freeze(args.output.absolute())


if __name__ == "__main__":
    main()
