from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
import importlib.util
from pathlib import Path
from unittest.mock import patch

from recorder_next.adapters import CredentialError, _read_api_key_file

ROOT = Path(__file__).parents[1]
BUILDER = Path(os.environ.get("RECORDER_NEXT_BUILDER", str(ROOT / "release/build_candidate.py")))


class Rev17RepairTests(unittest.TestCase):
    def _systemd_metadata(self, root: Path):
        real_stat = os.stat
        real_fstat = os.fstat

        def with_metadata(info: os.stat_result, *, mode: int | None = None, uid: int = 0) -> os.stat_result:
            fields = list(info)
            if mode is not None:
                fields[0] = stat.S_IFMT(info.st_mode) | mode
            fields[4] = uid
            return os.stat_result(fields)

        def fake_stat(path, *args, **kwargs):
            info = real_stat(path, *args, **kwargs)
            if Path(path).is_relative_to(root):
                if stat.S_ISREG(info.st_mode):
                    return with_metadata(info, mode=0o440)
                if stat.S_ISDIR(info.st_mode):
                    return with_metadata(info, mode=0o550)
            return info

        def fake_fstat(fd):
            info = real_fstat(fd)
            if Path(f"/proc/self/fd/{fd}").resolve().is_relative_to(root):
                if stat.S_ISREG(info.st_mode):
                    return with_metadata(info, mode=0o440)
                if stat.S_ISDIR(info.st_mode):
                    return with_metadata(info, mode=0o550)
            return info

        return patch("recorder_next.adapters.os.stat", side_effect=fake_stat), patch(
            "recorder_next.adapters.os.fstat", side_effect=fake_fstat
        )

    def test_systemd_named_acl_credential_accepts_trusted_manager_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            credential_root = root / "credentials"
            credential_root.mkdir(mode=0o700)
            credential = credential_root / "recorder_api_key"
            credential.write_bytes(b"API_SERVER_KEY=fixture-value\n")
            credential.chmod(0o440)
            direct_source = root / "direct.env"
            direct_source.write_bytes(b"API_SERVER_KEY=fixture-value\n")
            direct_source.chmod(0o600)
            unsafe_direct_source = root / "unsafe-direct.env"
            unsafe_direct_source.write_bytes(b"API_SERVER_KEY=fixture-value\n")
            unsafe_direct_source.chmod(0o440)

            stat_patch, fstat_patch = self._systemd_metadata(credential_root)
            with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": str(credential_root)}, clear=False):
                with patch("recorder_next.adapters.os.getuid", return_value=1000):
                    with stat_patch, fstat_patch:
                        self.assertEqual(_read_api_key_file(credential), "fixture-value")
                        self.assertEqual(_read_api_key_file(direct_source), "fixture-value")
                        with self.assertRaises(CredentialError):
                            _read_api_key_file(unsafe_direct_source)

    def test_product_paths_excludes_every_descendant_of_real_git_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            clone = root / "clone"
            source.mkdir()
            (source / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            subprocess.run(["git", "init", "--quiet", str(source)], check=True, capture_output=True, text=True)
            subprocess.run(
                ["git", "-C", str(source), "add", "tracked.txt"],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "-c",
                    "user.name=Recorder Next Test",
                    "-c",
                    "user.email=recorder-next-test@example.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "fixture",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "clone", "--quiet", "--no-hardlinks", str(source), str(clone)],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertTrue((clone / ".git").is_dir())

            spec = importlib.util.spec_from_file_location("rev17_build_candidate", BUILDER)
            if spec is None or spec.loader is None:
                raise AssertionError("could not load candidate builder")
            module = importlib.util.module_from_spec(spec)
            sys.path.insert(0, str(BUILDER.parent))
            try:
                spec.loader.exec_module(module)
            finally:
                sys.path.pop(0)

            relative_paths = {path.relative_to(clone).as_posix() for path in module.product_paths(clone)}
            self.assertIn("tracked.txt", relative_paths)
            self.assertFalse(any(path == ".git" or path.startswith(".git/") for path in relative_paths))


if __name__ == "__main__":
    unittest.main()
