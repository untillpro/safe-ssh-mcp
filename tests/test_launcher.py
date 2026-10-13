"""Regression tests for the Bash launcher."""

import os
import shutil
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
SOURCE_LAUNCHER = REPOSITORY_ROOT / "safe_ssh_mcp.sh"


class LauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        bash = shutil.which("bash")
        if bash is None:
            raise unittest.SkipTest("bash is not available")
        cls.bash = bash

    @classmethod
    def bash_path(cls, path: Path) -> str:
        resolved = path.resolve()
        if os.name != "nt":
            return resolved.as_posix()
        result = subprocess.run(
            [cls.bash, "-lc", 'cygpath -u "$1"', "bash", str(resolved)],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        return result.stdout.strip()

    @staticmethod
    def write_executable(path: Path, content: str) -> None:
        path.write_text(content, encoding="utf-8", newline="\n")
        path.chmod(0o755)

    def prepare_project(self, root: Path, *, with_server: bool = True) -> Path:
        launcher = root / "safe_ssh_mcp.sh"
        self.write_executable(launcher, SOURCE_LAUNCHER.read_text(encoding="utf-8"))
        if with_server:
            (root / "safe_ssh_mcp.py").write_text("", encoding="utf-8")
        return launcher

    def write_runner(
        self, bin_dir: Path, name: str, *, compatible: bool = True
    ) -> None:
        backend_help = "printf '%s\\n' '  --backend {pip,uv}'" if compatible else ":"
        self.write_executable(
            bin_dir / name,
            f"""#!/usr/bin/env bash
set -euo pipefail
if [[ "${{1-}}" == "run" && "${{2-}}" == "--help" ]]; then
    {backend_help}
    exit 0
fi
{{
    printf 'runner={name}\\n'
    printf 'arg=%s\\n' "$@"
}} > "$RUNNER_LOG"
""",
        )

    def run_launcher(
        self, launcher: Path, bin_dir: Path, log_file: Path, *arguments: str
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PATH"] = f"{self.bash_path(bin_dir)}:/usr/bin:/bin"
        env["RUNNER_LOG"] = self.bash_path(log_file)
        return subprocess.run(
            [self.bash, self.bash_path(launcher), *arguments],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            env=env,
        )

    def test_uv_takes_precedence_and_preserves_paths_and_arguments(self) -> None:
        with TemporaryDirectory(prefix="safe ssh mcp ") as temp_dir:
            root = Path(temp_dir)
            bin_dir = root / "fake bin"
            bin_dir.mkdir()
            launcher = self.prepare_project(root)
            log_file = root / "runner log"
            self.write_runner(bin_dir, "uv")
            self.write_runner(bin_dir, "pipx")

            result = self.run_launcher(
                launcher, bin_dir, log_file, "first", "two words"
            )
            log_lines = log_file.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(log_lines[0:3], ["runner=uv", "arg=run", "arg=--script"])
        self.assertTrue(log_lines[3].replace("\\", "/").endswith("/safe_ssh_mcp.py"))
        self.assertEqual(log_lines[4:], ["arg=first", "arg=two words"])

    def test_compatible_pipx_is_the_fallback(self) -> None:
        with TemporaryDirectory(prefix="safe ssh mcp ") as temp_dir:
            root = Path(temp_dir)
            bin_dir = root / "fake bin"
            bin_dir.mkdir()
            launcher = self.prepare_project(root)
            log_file = root / "runner log"
            self.write_runner(bin_dir, "pipx")

            result = self.run_launcher(launcher, bin_dir, log_file, "argument")
            log_lines = log_file.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(
            log_lines[0:4],
            ["runner=pipx", "arg=run", "arg=--backend", "arg=pip"],
        )
        self.assertTrue(log_lines[4].replace("\\", "/").endswith("/safe_ssh_mcp.py"))
        self.assertEqual(log_lines[5:], ["arg=argument"])

    def test_explicit_pipx_overrides_uv_and_separator_forwards_options(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            launcher = self.prepare_project(root)
            log_file = root / "runner.log"
            self.write_runner(bin_dir, "uv")
            self.write_runner(bin_dir, "pipx")

            result = self.run_launcher(
                launcher,
                bin_dir,
                log_file,
                "--runner",
                "pipx",
                "--",
                "--runner",
                "server-value",
            )
            log_lines = log_file.read_text(encoding="utf-8").splitlines()

        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(log_lines[0], "runner=pipx")
        self.assertEqual(log_lines[-2:], ["arg=--runner", "arg=server-value"])

    def test_explicit_runner_does_not_fall_back(self) -> None:
        cases = (("uv", "pipx"), ("pipx", "uv"))
        for selected_runner, available_runner in cases:
            with self.subTest(selected_runner=selected_runner):
                with TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    bin_dir = root / "bin"
                    bin_dir.mkdir()
                    launcher = self.prepare_project(root)
                    log_file = root / "runner.log"
                    self.write_runner(bin_dir, available_runner)

                    result = self.run_launcher(
                        launcher,
                        bin_dir,
                        log_file,
                        f"--runner={selected_runner}",
                    )
                    runner_called = log_file.exists()

                self.assertEqual(result.returncode, 127)
                self.assertEqual(result.stdout, "")
                self.assertIn(f"selected runner '{selected_runner}'", result.stderr)
                self.assertFalse(runner_called)

    def test_invalid_launcher_options_are_usage_errors(self) -> None:
        cases = (("--runner",), ("--runner", "invalid"), ("--unknown",))
        for arguments in cases:
            with self.subTest(arguments=arguments):
                with TemporaryDirectory() as temp_dir:
                    root = Path(temp_dir)
                    bin_dir = root / "bin"
                    bin_dir.mkdir()
                    launcher = self.prepare_project(root)
                    log_file = root / "runner.log"

                    result = self.run_launcher(launcher, bin_dir, log_file, *arguments)

                self.assertEqual(result.returncode, 64)
                self.assertEqual(result.stdout, "")
                self.assertIn("safe-ssh-mcp:", result.stderr)

    def test_help_does_not_require_a_server_or_runner(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            launcher = self.prepare_project(root, with_server=False)
            log_file = root / "runner.log"

            result = self.run_launcher(launcher, bin_dir, log_file, "--help")

        self.assertEqual(result.returncode, 0)
        self.assertIn("Usage: safe_ssh_mcp.sh", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_incompatible_pipx_is_rejected_without_stdout(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            launcher = self.prepare_project(root)
            log_file = root / "runner.log"
            self.write_runner(bin_dir, "pipx", compatible=False)

            result = self.run_launcher(launcher, bin_dir, log_file)
            runner_called = log_file.exists()

        self.assertEqual(result.returncode, 127)
        self.assertEqual(result.stdout, "")
        self.assertIn("pipx is too old", result.stderr)
        self.assertFalse(runner_called)

    def test_missing_runner_is_reported_without_stdout(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            launcher = self.prepare_project(root)
            log_file = root / "runner.log"

            result = self.run_launcher(launcher, bin_dir, log_file)

        self.assertEqual(result.returncode, 127)
        self.assertEqual(result.stdout, "")
        self.assertIn("neither uv nor pipx", result.stderr)

    def test_missing_server_is_reported_without_stdout(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            bin_dir = root / "bin"
            bin_dir.mkdir()
            launcher = self.prepare_project(root, with_server=False)
            log_file = root / "runner.log"
            self.write_runner(bin_dir, "uv")

            result = self.run_launcher(launcher, bin_dir, log_file)
            runner_called = log_file.exists()

        self.assertEqual(result.returncode, 66)
        self.assertEqual(result.stdout, "")
        self.assertIn("server script is missing or unreadable", result.stderr)
        self.assertFalse(runner_called)
