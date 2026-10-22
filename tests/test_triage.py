"""Offline triage fixtures; generated PHP samples are data and never executed."""
import argparse
import ast
import bz2
import gzip
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "runcloud-triage.py"
spec = importlib.util.spec_from_file_location("triage", str(SCRIPT))
triage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(triage)


def sample(body):
    # Keep source fixtures inert; no executable PHP source is embedded in this file.
    return b"<" + b"?php /* inert detector test: " + body + b" */"


def request_sample():
    return sample(b"system(" + b"$_POST['test']);")


class DetectionTests(unittest.TestCase):
    def rules(self, path, content, persistence=False):
        return {x["rule"] for x in triage.file_rules(path, content, persistence)[0]}

    def test_request_execution(self):
        self.assertIn("request_to_execution", self.rules("/home/a/a.php", request_sample()))

    def test_encoded_execution(self):
        self.assertIn("encoded_execution", self.rules("/home/a/a.php", sample(b"eval(" + b"gzinflate(base64_decode('AAAA')));")))

    def test_request_callable(self):
        self.assertIn("variable_request_callable", self.rules("/home/a/a.php", sample(b"$_REQUEST['f']" + b"('x');")))

    def test_disguised_php_upload(self):
        result = self.rules("/home/a/webapps/b/wp-content/uploads/image.jpg", b"\xff\xd8\xff" + request_sample())
        self.assertTrue({"request_to_execution", "php_in_other_file_type", "php_in_writable_directory"} <= result)

    def test_normal_decoder_and_generated_view(self):
        self.assertFalse(self.rules("/home/a/vendor/pkg/a.php", sample(b"return base64_decode($payload);")))
        self.assertFalse(self.rules("/home/a/storage/framework/views/a.php", sample(b"echo htmlspecialchars($name);")))

    def test_automatic_include_requires_review(self):
        findings, _ = triage.file_rules("/home/a/.user.ini", b"auto_prepend_file=/home/a/firewall.php")
        self.assertEqual(findings[0]["severity"], "REVIEW")
        self.assertFalse(self.rules("/home/a/.user.ini", b";auto_prepend_file=/tmp/old.php"))

    def test_normal_post_is_context_only(self):
        events, access = triage.log_event(b'192.0.2.1 - - [21/Oct/2026:23:30:00 +0200] "POST /login?token=secret HTTP/1.1" 200 123\n')
        self.assertFalse(events)
        self.assertEqual(access[2], "2026-10-21T21:00Z")
        self.assertEqual(access[4], "/login")

    def test_encoded_log_marker(self):
        events, _ = triage.log_event(b'GET /?q=%3C%3Fphp%20eval%28x%29')
        self.assertIn("request_payload_marker", {x["rule"] for x in events})

    def test_dates(self):
        self.assertEqual(triage.parse_time("2026-10-21T12:30:00+02:00"), triage.parse_time("2026-10-21T10:30:00Z"))
        self.assertEqual(triage.parse_time("2026-10-21").hour, 0)
        self.assertEqual(triage.parse_time("2026-10-21T10:30:00.123456Z").microsecond, 123456)
        for date in ("yesterday", "2026-13-01", "2026-10-21T10:30:00+25:00", "2026-10-21T10:30:00+01:99"):
            with self.assertRaises(argparse.ArgumentTypeError):
                triage.parse_time(date)

    @unittest.skipIf(sys.version_info < (3, 8), "AST grammar selection needs newer Python")
    def test_python36_grammar(self):
        ast.parse(SCRIPT.read_text(encoding="utf-8"), feature_version=(3, 6))


class ProgressTests(unittest.TestCase):
    def test_progress_includes_repeated_unsaved_matches_and_severity(self):
        report = triage.Report("unused", argparse.Namespace(home="/home"))
        report.counts.update(files=12456, logs=40)
        # Two lines in the same log each match both REVIEW and INFO rules.
        # Unsaved evidence still contributes to the live totals.
        events, _ = triage.log_event(b"PHP Fatal error: Allowed memory size of 1 byte exhausted\n")
        for _ in range(2):
            for event in events:
                report.finding("/home/example/error.log", event, save=False)
        with mock.patch("builtins.print") as output:
            report.progress("Scanning logs")
        message = output.call_args[0][0]
        self.assertIn("12,456 non-log files, 40 log files", message)
        self.assertIn("Rule matches: 4", message)
        self.assertIn("HIGH=0, REVIEW=2, INFO=2", message)
        self.assertIn("not confirmed infections", message)
        self.assertFalse(report.handles)


@unittest.skipUnless(sys.platform.startswith("linux"), "Filesystem tests require Linux")
class LinuxFixtureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="runcloud-triage-test-")
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.out = self.root / "report"
        self.out.mkdir(mode=0o700)
        self.args = triage.parser().parse_args([])
        self.args.home = str(self.home)
        self.args.since = "2026-10-01T00:00:00+00:00"
        self.args.patched_at = "2026-10-21T15:00:00+00:00"
        self.report = triage.Report(str(self.out), self.args)

    def tearDown(self):
        for handle in self.report.handles.values():
            handle.close()
        self.tmp.cleanup()

    def write(self, relative, data):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def rows(self, name):
        for handle in self.report.handles.values():
            handle.flush()
        path = self.out / (name + ".jsonl")
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_all_sites_vendor_old_releases_nonstandard_home(self):
        paths = [self.write(p, request_sample()) for p in (
            "alice/webapps/one/vendor/a.php", "bob/webapps/two/releases/old/a.php", "carol/custom/app/a.php")]
        for path in paths:
            os.utime(str(path), (1, 1))
        before = {str(p): (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}
        for path, _ in triage.walk_files(str(self.home), self.report):
            triage.scan_file(path, self.report)
        self.assertEqual(self.report.severities["HIGH"], 3)
        self.assertEqual(len(self.rows("files")), 3)
        self.assertEqual(len(self.report.sites), 3)
        for path in paths:
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), before[str(path)])
        self.assertEqual(self.rows("files")[0]["mtime_relative_to_patch"], "before")

    def test_symlink_ancestor_link_and_fifo_not_read(self):
        target = self.root / "outside.php"
        target.write_bytes(request_sample())
        (self.home / "link.php").symlink_to(target)
        (self.home / "dirlink").symlink_to(self.root, target_is_directory=True)
        os.mkfifo(str(self.home / "pipe.php"))
        self.assertEqual(list(triage.walk_files(str(self.home), self.report)), [])
        self.assertEqual(self.report.counts["symlinks_not_followed"], 2)
        for path in (self.home / "link.php", self.home / "dirlink" / "outside.php", self.home / "pipe.php"):
            with self.assertRaises(OSError):
                triage.open_regular(str(path))

    def test_read_error_is_explicit(self):
        path = self.write("x.php", sample(b"echo 1;"))
        with mock.patch.object(triage, "open_regular", side_effect=PermissionError("fixture")):
            triage.scan_file(str(path), self.report)
        self.assertEqual(self.report.gaps["file_read_error"], 1)

    def test_traversal_avoids_python37_scandir_fd(self):
        self.write("alice/webapps/site/hello.txt", b"hello")
        with mock.patch.object(triage.os, "scandir", side_effect=AssertionError("scandir(fd) requires 3.7")):
            self.assertEqual(len(list(triage.walk_files(str(self.home), self.report))), 1)

    def test_does_not_scan_own_output(self):
        (self.out / "existing.txt").write_text("private report")
        self.assertEqual(list(triage.walk_files(str(self.out), self.report)), [])

    def test_snapshot_output_and_time_are_bounded(self):
        data, rc, reason = triage.capture_bounded([sys.executable, "-c", "import os; os.write(1,b'x'*1000000)"], limit=1024)
        self.assertEqual(len(data), 1024)
        self.assertEqual(reason, "snapshot_output_limit")
        data, rc, reason = triage.capture_bounded([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1)
        self.assertEqual(reason, "snapshot_timeout")

    def test_partial_hash_is_not_full_hash(self):
        self.args.max_file_mib = 1
        path = self.write("huge.php", b"a" * (triage.MIB + 10))
        triage.scan_file(str(path), self.report)
        row = self.rows("files")[0]
        self.assertFalse(row["content_complete"])
        self.assertIsNone(row["sha256"])
        self.assertEqual(row["prefix_sha256"], hashlib.sha256(b"a" * triage.MIB).hexdigest())
        self.assertEqual(self.report.gaps["file_content_limit"], 1)

    def test_plain_and_compressed_logs(self):
        data = (b'192.0.2.10 - - [20/Oct/2026:12:00:00 +0000] "POST /upload HTTP/1.1" 500 10\n'
                b'PHP Fatal error: Allowed memory size of 100 bytes exhausted\n')
        for suffix, encode in (("", lambda b: b), (".gz", gzip.compress), (".bz2", bz2.compress), (".xz", lzma.compress)):
            path = self.write("a/logs/site_error.log" + suffix, encode(data))
            triage.scan_log(str(path), self.report)
        self.assertEqual(len(self.rows("logs")), 4)
        self.assertEqual(len(self.rows("traffic")), 4)
        self.assertEqual(self.report.severities["REVIEW"], 4)

    def test_sample_limit_does_not_hide_later_review_count(self):
        self.args.log_samples = 1
        path = self.write("access.log", b"PHP Fatal error: ordinary error\nAllowed memory size of 1 byte exhausted\n")
        triage.scan_log(str(path), self.report)
        self.assertEqual(len(self.rows("findings")), 1)
        self.assertEqual(self.report.severities["REVIEW"], 1)
        self.assertEqual(self.report.gaps["log_evidence_sample_limit"], 1)

    def test_decompression_and_total_log_limits(self):
        self.args.max_log_mib = self.args.max_total_log_mib = 1
        path = self.write("large.log.gz", gzip.compress(b"ordinary line\n" * 100000))
        triage.scan_log(str(path), self.report)
        self.assertEqual(self.report.counts["log_bytes"], triage.MIB)
        self.assertFalse(self.rows("logs")[0]["content_complete"])
        triage.scan_log(str(path), self.report)
        self.assertEqual(self.report.gaps["total_log_budget_exhausted"], 1)

    def test_corrupt_gzip(self):
        path = self.write("bad.log.gz", b"not a gzip file")
        triage.scan_log(str(path), self.report)
        self.assertEqual(self.report.gaps["log_read_error"], 1)

    def test_newline_paths_are_escaped(self):
        path = self.write("alice/webapps/site/odd\nfile.php", request_sample())
        triage.scan_file(str(path), self.report)
        rows = self.rows("findings")
        self.assertEqual(len(rows), 2)  # Request execution and PHP below the fixture's /tmp root.
        self.assertTrue(all(row["path"] == str(path) for row in rows))

    def test_summary_manifest_permissions(self):
        path = self.write("alice/webapps/site/normal.txt", b"Ordinary static content")
        triage.scan_file(str(path), self.report)
        self.report.finish(True)
        self.assertEqual(self.rows("summary")[0]["verdict"], "NO_MATCHING_INDICATORS")
        for line in (self.out / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertEqual(hashlib.sha256((self.out / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(stat.S_IMODE((self.out / "files.jsonl").stat().st_mode), 0o600)

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "Isolated chroot CLI test requires root")
    def test_full_cli_in_isolated_filesystem(self):
        # The child sees only this fixture tree. No production /home, /etc or /root
        # is inspected, and no host system commands exist in the isolated root.
        jail = self.root / "isolated"
        for relative in ("root", "home/user/webapps/site", "etc", "tmp"):
            (jail / relative).mkdir(parents=True, mode=0o700, exist_ok=True)
        (jail / "runcloud-triage.py").write_bytes(SCRIPT.read_bytes())
        code = (
            "import os,sys,importlib.util,_strptime,encodings.ascii; "
            "s=importlib.util.spec_from_file_location('triage',sys.argv[1]+'/runcloud-triage.py'); "
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
            "os.chroot(sys.argv[1]); os.chdir('/'); m.__file__='/runcloud-triage.py'; "
            "sys.argv=['runcloud-triage.py']+sys.argv[2:]; sys.exit(m.main())"
        )
        clean = subprocess.run([sys.executable, "-c", code, str(jail)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(clean.returncode, 0, clean.stdout.decode() + clean.stderr.decode())
        (jail / "home/user/webapps/site/example.jpg").write_bytes(request_sample())
        review = subprocess.run([sys.executable, "-c", code, str(jail)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(review.returncode, 1, review.stdout.decode() + review.stderr.decode())
        incomplete = subprocess.run([sys.executable, "-c", code, str(jail), "--home", "/missing"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(incomplete.returncode, 2, incomplete.stdout.decode() + incomplete.stderr.decode())
        reports = list((jail / "root").glob("runcloud-triage-*"))
        self.assertEqual(len(reports), 3)
        for report in reports:
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o700)
            for artifact in report.iterdir():
                self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            self.assertTrue((report / "SHA256SUMS").exists())


if __name__ == "__main__":
    unittest.main()
