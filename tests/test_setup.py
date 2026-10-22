"""Run the documented setup in temporary directories, with offline curl fixtures."""
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
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
        content = b"# inert download fixture\n"
        (self.fixtures / "runcloud-triage.py").write_bytes(content)
        self.checksum = self.fixtures / "runcloud-triage.py.sha256"
        self.checksum.write_text(hashlib.sha256(content).hexdigest() + "  runcloud-triage.py\n")
        curl = self.bin / "curl"
        curl.write_text(
            "#!/bin/sh\n"
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
                        FIXTURE_DIR=str(self.fixtures), CHMOD_MARKER=str(self.root / "chmod-called"))
        self.readme = README.read_text(encoding="utf-8")

    def block(self, section):
        text = self.readme.split(section, 1)[1]
        return re.search(r"```bash\n(.*?)\n```", text, re.S).group(1)

    def run_command(self, shell, command, token=None):
        # The fixtures never write /root, contact GitHub or execute downloaded content.
        command = command.replace("/root/runcloud-triage", str(self.root / "runcloud-triage"))
        return subprocess.run([shell, "-c", command], env=self.env,
                              input=token, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

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


if __name__ == "__main__":
    unittest.main()
