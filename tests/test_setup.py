"""Run the documented setup in temporary directories, with offline curl fixtures."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest


README = Path(__file__).resolve().parents[1] / "README.md"


@unittest.skipUnless(sys.platform.startswith("linux"), "Shell setup tests require Linux")
class SetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="triage-setup-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.fixtures = self.root / "fixtures"
        self.fixtures.mkdir()
        content = b'VERSION = "inert-download-fixture"\n'
        (self.fixtures / "runcloud-triage.py").write_bytes(content)
        self.checksum = self.fixtures / "runcloud-triage.py.sha256"
        self.checksum.write_text(hashlib.sha256(content).hexdigest() + "  runcloud-triage.py\n")
        curl = self.bin / "curl"
        curl.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' \"$@\" >> \"$CURL_ARGS_LOG\"\n"
            "[ \"$DOWNLOAD_FAIL\" != 1 ] || exit 22\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "    if [ \"$1\" = '-o' ]; then shift; cp \"$FIXTURE_DIR/$1\" \"$1\"; exit; fi\n"
            "    shift\n"
            "done\nexit 2\n"
        )
        curl.chmod(0o700)
        chmod = self.bin / "chmod"
        chmod.write_text('#!/bin/sh\nprintf called > "$CHMOD_MARKER"\nexec /bin/chmod "$@"\n')
        chmod.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.bin) + ":/usr/bin:/bin",
                        FIXTURE_DIR=str(self.fixtures), CHMOD_MARKER=str(self.root / "chmod-called"),
                        CURL_ARGS_LOG=str(self.root / "curl-args"))
        self.readme = README.read_text(encoding="utf-8")

    def block(self, section):
        text = self.readme.split(section, 1)[1]
        return re.search(r"```bash\n(.*?)\n```", text, re.S).group(1)

    def run_command(self, shell, command, token=None):
        # The fixtures never write /root, contact GitHub or execute downloaded content.
        command = command.replace("/root/runcloud-triage", str(self.root / "runcloud-triage"))
        return subprocess.run([shell, "-c", command], env=self.env,
                              input=token, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def assert_pinned_downloads(self):
        refs = re.findall(r"TRIAGE_REF='([a-f0-9]{40})'", self.readme)
        self.assertEqual(len(refs), 2)
        self.assertEqual(len(set(refs)), 1)
        urls = [line for line in (self.root / "curl-args").read_text().splitlines() if line.startswith("https://")]
        self.assertTrue(urls)
        for url in urls:
            self.assertIn("/" + refs[0] + "/", url)
            self.assertNotIn("/master/", url)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "Documented root ownership requires root")
    def test_download_and_token_commands_remain_separate_when_newlines_become_spaces(self):
        download = " ".join(self.block("## 3. Download").splitlines())
        token = self.block("## 4. Run it")
        for shell in ("/bin/bash", "/bin/sh"):
            with self.subTest(shell=shell):
                result = self.run_command(shell, download + " " + token, b"dummy-test-token\n")
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertIn(b"runcloud-triage.py: OK", result.stdout, result.stderr.decode())
                directory = self.root / "runcloud-triage"
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
                for path in (directory / "runcloud-triage.py", directory / "runcloud-triage.py.sha256",
                             self.root / "runcloud-triage-notify.token"):
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual((self.root / "runcloud-triage-notify.token").read_bytes(), b"dummy-test-token\n")
                self.assert_pinned_downloads()

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "Documented root ownership requires root")
    def test_download_failure_or_checksum_mismatch_does_not_finish_setup(self):
        command = self.block("## 3. Download")
        for shell in ("/bin/bash", "/bin/sh"):
            with self.subTest(shell=shell):
                self.env["DOWNLOAD_FAIL"] = "1"
                result = self.run_command(shell, command)
                self.assertEqual(result.returncode, 22, result.stderr.decode())
                self.assertFalse((self.root / "chmod-called").exists())
                self.env["DOWNLOAD_FAIL"] = "0"
                self.checksum.write_text("0" * 64 + "  runcloud-triage.py\n")
                result = self.run_command(shell, command)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / "chmod-called").exists())


    def test_user_setup_works_with_spaces_in_home_in_bash_and_sh(self):
        section = self.readme.split("### Run as a RunCloud user without root", 1)[1]
        blocks = re.findall(r"```bash\n(.*?)\n```", section, re.S)
        for shell in ("/bin/bash", "/bin/sh"):
            directory = self.root / (Path(shell).name + " account space")
            directory.mkdir()
            environment = dict(self.env, HOME=str(directory))
            command = " ".join(blocks[0].splitlines()) + " " + blocks[2]
            result = subprocess.run([shell, "-c", command], env=environment, input=b"fixture-token\n",
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn(b"OK", result.stdout)
            self.assertEqual((directory / "runcloud-triage-notify.token").read_text(), "fixture-token\n")
            self.assertEqual(stat.S_IMODE((directory / "runcloud-triage").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((directory / "runcloud-triage-notify.token").stat().st_mode), 0o600)
            self.assert_pinned_downloads()


@unittest.skipUnless(sys.platform.startswith("linux"), "Background launch tests require Linux")
class BackgroundTests(unittest.TestCase):
    def test_background_run_survives_hangup_and_records_private_logs_and_exit_codes(self):
        readme = README.read_text(encoding="utf-8").split("### Run in the background after SSH disconnects", 1)[1]
        command = re.search(r"```bash\n(.*?)\n```", readme, re.S).group(1)
        self.check_background_command(command)

    def test_user_background_run_survives_hangup_with_spaces_in_home(self):
        section = README.read_text(encoding="utf-8").split("### Run as a RunCloud user without root", 1)[1]
        command = re.findall(r"```bash\n(.*?)\n```", section, re.S)[3]
        self.check_background_command(command)

    def check_background_command(self, command, expected_args=None):
        # A harmless Python fixture replaces the scanner; no host scan or callback runs.
        with tempfile.TemporaryDirectory(prefix="triage-background-test-") as directory:
            root = Path(directory) / "account space"
            scanner = root / "runcloud-triage/runcloud-triage.py"
            scanner.parent.mkdir(parents=True)
            scanner.write_text(
                "import json, os, sys, time\n"
                "assert sys.stdin.read() == ''\n"
                "assert not sys.stdin.isatty() and not sys.stdout.isatty()\n"
                "if 'FIXTURE_ARGS' in os.environ: assert sys.argv[1:] == json.loads(os.environ['FIXTURE_ARGS'])\n"
                "print('fixture started', flush=True)\n"
                "print('fixture stderr', file=sys.stderr, flush=True)\n"
                "time.sleep(0.5)\n"
                "print('fixture finished', flush=True)\n"
                "sys.exit(int(os.environ['FIXTURE_EXIT']))\n"
            )
            command = command.replace("/root/runcloud-background.XXXXXX", shlex.quote(str(root / "runcloud-background.XXXXXX")))
            command = command.replace("/usr/bin/python3", shlex.quote(sys.executable))
            command = command.replace("/root/runcloud-triage/runcloud-triage.py", shlex.quote(str(scanner)))
            environment = dict(os.environ, HOME=str(root))
            if expected_args is not None:
                environment['FIXTURE_ARGS'] = json.dumps(expected_args)
            jobs = set()
            for shell in ("/bin/bash", "/bin/sh"):
                for exit_code in (0, 1, 2):
                    with self.subTest(shell=shell, exit_code=exit_code):
                        # Flattening simulates pasting a multiline command as one line.
                        launch = subprocess.Popen([shell, "-c", " ".join(command.splitlines())],
                                                  env=dict(environment, FIXTURE_EXIT=str(exit_code)),
                                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                                  stderr=subprocess.PIPE, start_new_session=True)
                        output, errors = launch.communicate(timeout=5)
                        self.assertEqual(launch.returncode, 0, errors.decode())
                        job = Path(re.search(rb"Background job: (.+)", output).group(1).decode())
                        self.assertNotIn(job, jobs)
                        jobs.add(job)
                        log = job / "scan.log"
                        deadline = time.monotonic() + 5
                        while (not log.exists() or "fixture started" not in log.read_text()) and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertIn("fixture started", log.read_text())
                        self.assertFalse((job / "exit-code").exists(), "Launcher must return before the scan finishes")
                        # SSH/shell hangup reaches the job's process group; nohup must ignore it.
                        os.killpg(launch.pid, signal.SIGHUP)
                        while (not (job / "exit-code").exists() or not (job / "exit-code").read_text()) and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.assertEqual((job / "exit-code").read_text(), str(exit_code) + "\n")
                        self.assertIn("fixture finished", log.read_text())
                        self.assertIn("fixture stderr", log.read_text())
                        self.assertEqual(stat.S_IMODE(job.stat().st_mode), 0o700)
                        for name in ("scan.log", "pid", "exit-code"):
                            self.assertEqual(stat.S_IMODE((job / name).stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
