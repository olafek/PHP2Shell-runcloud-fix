"""Offline triage fixtures; generated PHP samples are data and never executed."""
import argparse
import ast
import bz2
import contextlib
import gzip
import hashlib
import http.server
import importlib.util
import io
import json
import lzma
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
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
    def report(self):
        report = triage.Report("unused", triage.parse_options([]))
        report.interactive = False
        report.started_monotonic = report.scan_started = 0
        return report

    def test_progress_includes_repeated_unsaved_matches_and_severity(self):
        report = self.report()
        # Two lines in the same log each match both REVIEW and INFO rules.
        # Unsaved evidence still contributes to the live totals.
        events, _ = triage.log_event(b"PHP Fatal error: Allowed memory size of 1 byte exhausted\n")
        for _ in range(2):
            for event in events:
                report.finding("/home/example/error.log", event, save=False)
        with mock.patch("builtins.print") as output:
            report.progress("Scanning logs")
        message = output.call_args[0][0]
        self.assertIn("Matches=4", message)
        self.assertIn("HIGH=0 REVIEW=2 INFO=2", message)
        self.assertFalse(report.handles)

    def test_percentage_eta_and_completion(self):
        report = self.report()
        report.total_items, report.completed_items = 4, 1
        with mock.patch.object(triage.time, "monotonic", return_value=30), mock.patch("builtins.print") as output:
            report.progress("Scanning logs")
            self.assertIn("25% 1/4 | ETA ~00:01:30 | Elapsed 00:00:30 | Logs", output.call_args[0][0])
            # Discovery has not ended yet: reaching the old count is not completion.
            report.completed_items = 4
            report.progress(force=True)
            self.assertNotIn("100%", output.call_args[0][0])
            report.scan_complete = True
            report.progress("Scan complete", force=True)
            self.assertIn("100% 4/4 | ETA 00:00:00", output.call_args[0][0])

    def test_empty_and_unknown_totals(self):
        report = self.report()
        with mock.patch("builtins.print") as output:
            report.progress("Scanning files")
            self.assertIn("ETA unavailable", output.call_args[0][0])
            report.total_items = 0
            report.progress(force=True)
            self.assertIn("0% 0/0 | ETA estimating", output.call_args[0][0])
            report.scan_complete = True
            report.progress(force=True)
            self.assertIn("100% 0/0", output.call_args[0][0])

    def test_redirected_output_is_plain_and_rate_limited(self):
        output = io.StringIO()
        with mock.patch.object(triage.sys, "stdout", output):
            report = triage.Report("unused", triage.parse_options([]))
            with mock.patch.object(triage.time, "monotonic", side_effect=[100, 101, 115]):
                report.progress("Collecting processes")
                report.progress()
                report.progress()
        self.assertFalse(report.interactive)
        self.assertEqual(len(output.getvalue().splitlines()), 2)
        self.assertNotIn("\r", output.getvalue())
        self.assertNotIn("\033", output.getvalue())

    def test_terminal_updates_one_line_and_respects_width(self):
        class Terminal(io.StringIO):
            def isatty(self):
                return True
        output = Terminal()
        with mock.patch.object(triage.sys, "stdout", output), mock.patch.dict(os.environ, TERM="xterm"), \
                mock.patch.object(triage.shutil, "get_terminal_size", return_value=os.terminal_size((60, 24))):
            report = triage.Report("unused", triage.parse_options([]))
            report.counting, report.total_items = True, 12345
            report.progress(force=True)
            report.counting, report.scan_started = False, triage.time.monotonic()
            report.progress("Scanning files", force=True)
            report.clear_progress()
        self.assertTrue(report.interactive)
        self.assertEqual(output.getvalue().count("\r\033[K"), 3)
        self.assertNotIn("\n", output.getvalue())
        self.assertTrue(all(len(line) <= 59 for line in output.getvalue().split("\r\033[K")))


class OptionTests(unittest.TestCase):
    def test_standard_and_quick_limits(self):
        for options, expected in (([], (16, 512, 8192, 200)), (["--quick"], (1, 32, 512, 50))):
            args = triage.parse_options(options)
            self.assertEqual((args.max_file_mib, args.max_log_mib, args.max_total_log_mib, args.log_samples), expected)
            self.assertFalse(args.no_precount)

    def test_explicit_limits_override_quick_in_either_order(self):
        limits = ["--max-file-mib=8", "--max-log-mib", "64", "--max-total-log-mib", "1024", "--log-samples", "75"]
        for options in (["--quick"] + limits, limits + ["--quick"]):
            args = triage.parse_options(options + ["--no-precount"])
            self.assertEqual((args.max_file_mib, args.max_log_mib, args.max_total_log_mib, args.log_samples), (8, 64, 1024, 75))
            self.assertTrue(args.no_precount)

    def test_notification_options_validate_before_scanning(self):
        self.assertIsNone(triage.parse_options([]).notify_url)
        self.assertEqual(triage.parse_options(["--notify-url", "https://example.test/hook"]).notify_timeout, 10)
        for options in (["--notify-url", "file:///etc/passwd"], ["--notify-url", "https://user:pass@example.test/hook"],
                        ["--notify-url", "https://example.test/hook#fragment"], ["--notify-url", "http://example.test:99999"],
                        ["--notify-url", "https://example.test/\r\nheader"], ["--notify-token-file", "/root/token"],
                        ["--notify-timeout", "0"], ["--notify-timeout", "61"]):
            with mock.patch.object(triage.sys, "stderr", io.StringIO()), self.assertRaises(SystemExit):
                triage.parse_options(options)


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        fixture = self
        self.response_status = 204
        self.response_delay = 0
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                fixture.requests.append((self.path, dict(self.headers), json.loads(body.decode("utf-8"))))
                time.sleep(fixture.response_delay)
                self.send_response(fixture.response_status)
                self.send_header("Content-Length", "0")
                if 300 <= fixture.response_status < 400:
                    self.send_header("Location", "/redirected?secret=must-not-follow")
                self.end_headers()
            def log_message(self, *args):
                pass
        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.01})
        self.thread.daemon = True
        self.thread.start()
        self.args = triage.parse_options(["--notify-url", "http://127.0.0.1:{}/hook?key=private-url".format(self.server.server_port)])

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def test_posts_json_with_optional_auth_and_ignores_proxy_environment(self):
        # Only the local fixture is contacted, even with proxy variables present.
        with mock.patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1"}), \
                mock.patch("builtins.print"):
            self.assertTrue(triage.send_notification(self.args, {"schema_version": 1, "exit_code": 1}, "private-token"))
        path, headers, payload = self.requests[0]
        self.assertEqual(path, "/hook?key=private-url")
        self.assertEqual(headers["Authorization"], "Bearer private-token")
        self.assertEqual(headers["Content-Type"], "application/json; charset=utf-8")
        self.assertEqual(payload, {"schema_version": 1, "exit_code": 1})

    def test_redirects_are_not_followed(self):
        for code in (301, 302, 303, 307, 308):
            self.requests.clear()
            self.response_status = code
            with mock.patch("builtins.print"):
                self.assertFalse(triage.send_notification(self.args, {"exit_code": 0}, "private-token"))
            self.assertEqual(len(self.requests), 1)
            self.assertTrue(self.requests[0][0].startswith("/hook"))

    def test_failure_is_not_retried_and_does_not_print_secrets(self):
        self.response_status = 503
        with mock.patch("builtins.print") as output:
            self.assertFalse(triage.send_notification(self.args, {"exit_code": 1}, "private-token"))
        message = output.call_args[0][0]
        self.assertIn("HTTP 503", message)
        self.assertNotIn("private-url", message)
        self.assertNotIn("private-token", message)
        self.assertEqual(len(self.requests), 1)

    def test_notification_timeout(self):
        self.response_delay = 2
        self.args.notify_timeout = 1
        started = time.monotonic()
        with mock.patch("builtins.print"):
            self.assertFalse(triage.send_notification(self.args, {"exit_code": 0}))
        self.assertLess(time.monotonic() - started, 1.8)

    @unittest.skipUnless(hasattr(triage.signal, "setitimer"), "Total deadline requires Unix interval timers")
    def test_total_deadline_bounds_blocking_setup_and_restores_alarm(self):
        self.args.notify_timeout = 1
        previous_handler = triage.signal.getsignal(triage.signal.SIGALRM)
        with mock.patch.object(triage.urllib.request, "build_opener") as opener, mock.patch("builtins.print"):
            opener.return_value.open.side_effect = lambda *args, **kwargs: time.sleep(2)
            started = time.monotonic()
            self.assertFalse(triage.send_notification(self.args, {"exit_code": 0}))
        self.assertLess(time.monotonic() - started, 1.8)
        self.assertEqual(triage.signal.getsignal(triage.signal.SIGALRM), previous_handler)
        self.assertEqual(triage.signal.getitimer(triage.signal.ITIMER_REAL)[0], 0)

    def test_payload_is_a_summary_without_paths_options_or_evidence(self):
        report = triage.Report("/root/report-id", self.args)
        report.counts.update(files=123, logs=4)
        report.severities.update(HIGH=2, REVIEW=3, INFO=4)
        report.gaps["file_read_error"] = 1
        report.preview.append({"path": "/private/site.php", "excerpt": "secret-evidence"})
        report.sites["/private/site"]["HIGH"] = 2
        for code, expected in ((0, "completed"), (1, "review_required"), (2, "incomplete")):
            payload = triage.notification_payload(self.args, report, 0, 20, code != 2, True, code)
            self.assertEqual(payload["status"], expected)
            self.assertEqual(payload["counts"], {"files": 123, "logs": 4})
            self.assertEqual(payload["indicators"], {"HIGH": 2, "REVIEW": 3, "INFO": 4})
            self.assertEqual(payload["coverage_issues"], {"file_read_error": 1})
            self.assertEqual(payload["run_id"], "report-id")
            serialized = json.dumps(payload)
            for sensitive in ("private-url", "secret-evidence", "/private", "/root"):
                self.assertNotIn(sensitive, serialized)
        missing = triage.notification_payload(self.args, None, 0, 1, False, False, 2)
        self.assertIsNone(missing["run_id"])
        self.assertFalse(missing["report_finalized"])
        self.assertEqual(missing["status"], "incomplete")


@unittest.skipUnless(sys.platform.startswith("linux"), "Filesystem tests require Linux")
class LinuxFixtureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="runcloud-triage-test-")
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.out = self.root / "report"
        self.out.mkdir(mode=0o700)
        self.args = triage.parse_options([])
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

    def test_counting_uses_same_targets_without_reading_content_or_duplicating_records(self):
        self.write("alice/webapps/site/code.php", request_sample())
        self.write("alice/webapps/site/error.log", b"ordinary log\n")
        (self.home / "link").symlink_to(self.out, target_is_directory=True)
        os.mkfifo(str(self.home / "pipe"))
        self.args.extra_root = [str(self.home), str(self.home / "alice")]
        self.args.log_root = [str(self.home / "alice/webapps/site/error.log")]
        # Restrict discovery to the fixture. No real host directories are scanned.
        with mock.patch.object(triage, "existing_paths", return_value=[]), \
                mock.patch.object(triage.os, "scandir", return_value=[]), \
                mock.patch.object(triage.os.path, "isdir", return_value=False):
            with mock.patch.object(triage, "open_regular", side_effect=AssertionError("Counting must not read contents")):
                counted = list(triage.scan_targets(self.report, record=False))
            self.assertFalse(self.report.handles)
            self.assertFalse(self.report.counts)
            self.assertFalse(self.report.gaps)
            self.assertFalse(self.report.sites)
            scanned = list(triage.scan_targets(self.report))
        self.assertEqual([(p, kind) for p, _, kind in counted], [(p, kind) for p, _, kind in scanned])
        self.assertEqual(len(counted), 2)
        self.assertEqual({kind for _, _, kind in counted}, {"file", "log"})
        self.assertEqual(len(self.rows("symlinks")), 2)  # Two overlapping root walks, not doubled by counting.

    def test_progress_accounts_for_new_files_and_failed_attempts(self):
        path = self.write("normal.txt", b"normal")
        target = (str(path), path.stat(), "file")
        missing = (str(self.home / "removed.txt"), path.stat(), "file")
        with mock.patch.object(triage, "system_snapshot"), \
                mock.patch.object(triage, "scan_targets", side_effect=[iter([target]), iter([target, missing])]):
            triage.run_scan(self.report)
        self.assertEqual(self.report.completed_items, 2)
        self.assertEqual(self.report.total_items, 2)
        self.assertEqual(self.report.gaps["file_read_error"], 1)
        self.assertTrue(self.report.scan_complete)

    def test_no_precount_uses_one_pass(self):
        self.args.no_precount = True
        path = self.write("normal.txt", b"normal")
        with mock.patch.object(triage, "system_snapshot"), \
                mock.patch.object(triage, "scan_targets", return_value=iter([(str(path), path.stat(), "file")])) as targets:
            triage.run_scan(self.report)
        targets.assert_called_once_with(self.report)
        self.assertIsNone(self.report.total_items)
        self.assertEqual(self.report.completed_items, 1)

    def test_disappearing_files_adjust_total_at_finish(self):
        path = self.write("normal.txt", b"normal")
        target = (str(path), path.stat(), "file")
        with mock.patch.object(triage, "system_snapshot"), \
                mock.patch.object(triage, "scan_targets", side_effect=[iter([target] * 3), iter([target])]):
            triage.run_scan(self.report)
        self.assertEqual(self.report.total_items, 1)
        self.assertEqual(self.report.completed_items, 1)
        self.assertTrue(self.report.scan_complete)

    def test_failed_counting_falls_back_to_scan_without_eta(self):
        with mock.patch.object(triage, "system_snapshot"), \
                mock.patch.object(triage, "scan_targets", side_effect=[PermissionError("fixture"), iter([])]):
            triage.run_scan(self.report)
        self.assertIsNone(self.report.total_items)
        self.assertEqual(self.report.gaps["precount_incomplete"], 1)
        self.assertTrue(self.report.scan_complete)

    def test_interrupt_during_counting_leaves_partial_report(self):
        with mock.patch.object(triage, "system_snapshot"), \
                mock.patch.object(triage, "scan_targets", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                triage.run_scan(self.report)
        self.assertFalse(self.report.counting)
        self.assertFalse(self.report.scan_complete)
        self.assertEqual(self.report.completed_items, 0)
        self.report.finish(False)
        self.assertFalse(self.rows("summary")[0]["scan_finished"])

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

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "Token ownership check requires root")
    def test_notification_token_requires_private_regular_file(self):
        token = self.root / "notify.token"
        token.write_text("private-token\n")
        token.chmod(0o600)
        self.assertEqual(triage.read_notification_token(str(token)), "private-token")
        token.chmod(0o644)
        with self.assertRaises(ValueError):
            triage.read_notification_token(str(token))
        token.chmod(0o600)
        link = self.root / "token-link"
        link.symlink_to(token)
        with self.assertRaises(OSError):
            triage.read_notification_token(str(link))
        for content in ("", "token\nInjected: header", "x" * 4097):
            token.write_text(content)
            with self.assertRaises(ValueError):
                triage.read_notification_token(str(token))

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
            "m.send_notification=lambda args,payload,token=None: print('CALLBACK '+m.json.dumps(payload)) or False; "
            "os.chroot(sys.argv[1]); os.chdir('/'); m.__file__='/runcloud-triage.py'; "
            "sys.argv=['runcloud-triage.py']+sys.argv[2:]; sys.exit(m.main())"
        )
        clean = subprocess.run([sys.executable, "-c", code, str(jail)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(clean.returncode, 0, clean.stdout.decode() + clean.stderr.decode())
        self.assertIn(b"Counting files:", clean.stdout)
        self.assertIn(b"100%", clean.stdout)
        self.assertNotIn(b"CALLBACK ", clean.stdout)
        quick = subprocess.run([sys.executable, "-c", code, str(jail), "--quick", "--no-precount"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(quick.returncode, 0, quick.stdout.decode() + quick.stderr.decode())
        self.assertNotIn(b"Counting files:", quick.stdout)
        self.assertIn(b"Quick mode:", quick.stdout)
        notify_args = ["--notify-url", "http://example.test/hook?private=url"]
        notified_clean = subprocess.run([sys.executable, "-c", code, str(jail)] + notify_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(notified_clean.returncode, 0)
        (jail / "home/user/webapps/site/example.jpg").write_bytes(request_sample())
        review = subprocess.run([sys.executable, "-c", code, str(jail)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(review.returncode, 1, review.stdout.decode() + review.stderr.decode())
        # Without a terminal nothing is offered or moved; the later command is printed instead.
        self.assertIn(b"--quarantine /root/runcloud-triage-", review.stdout)
        review_report = re.search(rb"Writing private report to: (\S+)", review.stdout).group(1).decode()
        for action in (["--quarantine", review_report], ["--restore"], ["--purge"]):
            refused = subprocess.run([sys.executable, "-c", code, str(jail)] + action, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(refused.returncode, 2, refused.stdout.decode() + refused.stderr.decode())
            self.assertIn(b"interactive terminal", refused.stderr)
        self.assertTrue((jail / "home/user/webapps/site/example.jpg").exists())
        self.assertFalse((jail / "root/runcloud-quarantine").exists())
        notified_review = subprocess.run([sys.executable, "-c", code, str(jail)] + notify_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(notified_review.returncode, 1)
        incomplete = subprocess.run([sys.executable, "-c", code, str(jail), "--home", "/missing"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(incomplete.returncode, 2, incomplete.stdout.decode() + incomplete.stderr.decode())
        notified_incomplete = subprocess.run([sys.executable, "-c", code, str(jail), "--home", "/missing"] + notify_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(notified_incomplete.returncode, 2)
        notified_init = subprocess.run([sys.executable, "-c", code, str(jail), "--output-parent", "/missing"] + notify_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(notified_init.returncode, 2)
        interrupted_code = code.replace("sys.exit(m.main())", "m.run_scan=lambda report: (_ for _ in ()).throw(KeyboardInterrupt()); sys.exit(m.main())")
        notified_interrupted = subprocess.run([sys.executable, "-c", interrupted_code, str(jail)] + notify_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(notified_interrupted.returncode, 2)
        for result, status, finalized in ((notified_clean, "completed", True), (notified_review, "review_required", True),
                                          (notified_incomplete, "incomplete", True), (notified_init, "incomplete", False),
                                          (notified_interrupted, "incomplete", True)):
            callbacks = [json.loads(line[len("CALLBACK "):]) for line in result.stdout.decode().splitlines() if line.startswith("CALLBACK ")]
            self.assertEqual(len(callbacks), 1)
            self.assertEqual(callbacks[0]["status"], status)
            self.assertEqual(callbacks[0]["report_finalized"], finalized)
            self.assertEqual(callbacks[0]["exit_code"], result.returncode)
        reports = list((jail / "root").glob("runcloud-triage-*"))
        self.assertEqual(len(reports), 8)
        for report in reports:
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o700)
            for artifact in report.iterdir():
                self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            self.assertTrue((report / "SHA256SUMS").exists())
            saved_options = json.loads((report / "summary.jsonl").read_text())["options"]
            self.assertIn(saved_options["notify_url"], (None, "[configured]"))


class SelectionTests(unittest.TestCase):
    def test_numbers_ranges_and_shortcuts(self):
        self.assertEqual(triage.parse_selection("1 3-4", 5), [0, 2, 3])
        self.assertEqual(triage.parse_selection("2,2, 1", 5), [0, 1])
        self.assertEqual(triage.parse_selection("a", 3), [0, 1, 2])
        self.assertEqual(triage.parse_selection("h", 4, high=[0, 2]), [0, 2])
        self.assertEqual(triage.parse_selection("  ", 4), [])

    def test_out_of_range_or_unknown_choices_are_rejected(self):
        for text in ("0", "6", "3-1", "x", "1-", "-2", "1 9"):
            with self.assertRaises(ValueError):
                triage.parse_selection(text, 5)


class QuarantineOptionTests(unittest.TestCase):
    def test_actions_are_exclusive_and_do_not_take_notification_options(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for argv in (["--quarantine", "/root/r", "--restore"], ["--restore", "--purge"],
                         ["--restore", "--notify-url", "https://example.test/hook"]):
                with self.assertRaises(SystemExit):
                    triage.parse_options(argv)
        self.assertEqual(triage.parse_options(["--restore"]).quarantine_dir, "/root/runcloud-quarantine")


@unittest.skipUnless(sys.platform.startswith("linux"), "Filesystem tests require Linux")
class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="runcloud-triage-quarantine-test-")
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.report_dir = self.root / "report"
        self.report_dir.mkdir(mode=0o700)
        self.qdir = str(self.root / "quarantine")
        self.args = triage.parse_options([])
        self.args.home = str(self.home)
        self.args.since = "2026-10-01T00:00:00+00:00"
        self.prompts = []

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, relative, data, mode=0o644):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def scan(self, *paths, logs=()):
        with contextlib.redirect_stdout(io.StringIO()):
            report = triage.Report(str(self.report_dir), self.args)
            for path in paths:
                triage.scan_file(str(path), report)
            for path in logs:
                triage.scan_log(str(path), report)
            report.finish(True)

    def answers(self, *replies):
        replies = list(replies)

        def ask(prompt):
            self.prompts.append(prompt)
            if not replies:
                raise EOFError()  # SSH session closed / Ctrl+D
            return replies.pop(0)
        return ask

    def quarantine_all(self):
        results = [triage.quarantine_file(c, self.qdir, str(self.report_dir))
                   for c in triage.quarantine_candidates(str(self.report_dir))]
        self.assertTrue(all(ok for ok, _ in results), results)

    def shell_and_upload(self):
        shell = self.write("alice/webapps/site/shell.php", request_sample(), mode=0o640)
        upload = self.write("alice/webapps/site/wp-content/uploads/x.php", sample(b"echo 1;"))
        return shell, upload

    def test_lists_each_flagged_file_once_high_first_without_log_evidence(self):
        shell, upload = self.shell_and_upload()
        plain = self.write("alice/webapps/site/readme.txt", b"Ordinary static content")
        log = self.write("alice/logs/access.log", b"GET /?q=%3C%3Fphp%20eval%28x%29\n")
        self.scan(upload, plain, shell, logs=[log])
        found = triage.quarantine_candidates(str(self.report_dir))
        self.assertEqual([c["path"] for c in found], [str(shell), str(upload)])
        self.assertEqual([c["severity"] for c in found], ["HIGH", "REVIEW"])
        self.assertIn("request_to_execution", found[0]["rules"])

    def test_quarantine_moves_the_file_into_a_private_copy(self):
        shell, _ = self.shell_and_upload()
        self.scan(shell)
        [candidate] = triage.quarantine_candidates(str(self.report_dir))
        ok, message = triage.quarantine_file(candidate, self.qdir, str(self.report_dir))
        self.assertTrue(ok, message)
        self.assertFalse(shell.exists())
        [item] = triage.quarantined_items(self.qdir)
        self.assertEqual(item["original_path"], str(shell))
        content = Path(self.qdir) / item["id"] / "content"
        self.assertEqual(content.read_bytes(), request_sample())
        self.assertEqual(stat.S_IMODE(content.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(Path(self.qdir).stat().st_mode), 0o700)

    def test_restore_puts_the_file_back_exactly(self):
        shell, _ = self.shell_and_upload()
        owner = (os.getuid(), os.getgid())
        if os.geteuid() == 0:
            os.chown(str(shell), 1234, 1235)
            owner = (1234, 1235)
        os.utime(str(shell), ns=(1600000000000000000, 1600000000123456789))
        self.scan(shell)
        self.quarantine_all()
        [item] = triage.quarantined_items(self.qdir)
        ok, message = triage.restore_item(item, self.qdir)
        self.assertTrue(ok, message)
        st = shell.stat()
        self.assertEqual(shell.read_bytes(), request_sample())
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o640)
        self.assertEqual(st.st_mtime_ns, 1600000000123456789)
        self.assertEqual((st.st_uid, st.st_gid), owner)
        self.assertEqual(triage.quarantined_items(self.qdir), [])

    def test_a_file_changed_since_the_scan_is_left_alone(self):
        shell, _ = self.shell_and_upload()
        self.scan(shell)
        shell.write_bytes(request_sample() + b" ")
        [candidate] = triage.quarantine_candidates(str(self.report_dir))
        ok, message = triage.quarantine_file(candidate, self.qdir, str(self.report_dir))
        self.assertFalse(ok)
        self.assertIn("changed since the scan", message)
        self.assertEqual(shell.read_bytes(), request_sample() + b" ")
        self.assertEqual(triage.quarantined_items(self.qdir), [])

    def test_a_file_already_gone_is_reported_not_moved(self):
        shell, _ = self.shell_and_upload()
        self.scan(shell)
        shell.unlink()
        [candidate] = triage.quarantine_candidates(str(self.report_dir))
        ok, message = triage.quarantine_file(candidate, self.qdir, str(self.report_dir))
        self.assertFalse(ok)
        self.assertIn("no longer exists", message)

    def test_a_symlinked_parent_directory_is_never_followed(self):
        shell, _ = self.shell_and_upload()
        self.scan(shell)
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        (elsewhere / "shell.php").write_bytes(request_sample())
        site = shell.parent
        site.rename(site.with_name("site-moved"))
        site.symlink_to(elsewhere)
        [candidate] = triage.quarantine_candidates(str(self.report_dir))
        ok, _ = triage.quarantine_file(candidate, self.qdir, str(self.report_dir))
        self.assertFalse(ok)
        self.assertTrue((elsewhere / "shell.php").exists())
        self.assertEqual(triage.quarantined_items(self.qdir), [])

    def test_a_partially_read_file_matches_on_its_recorded_prefix_and_size(self):
        self.args.max_file_mib = 1
        big = self.write("alice/webapps/site/big.php", request_sample() + b"a" * (triage.MIB + 10))
        self.scan(big)
        [candidate] = triage.quarantine_candidates(str(self.report_dir))
        ok, message = triage.quarantine_file(candidate, self.qdir, str(self.report_dir))
        self.assertTrue(ok, message)

    def test_a_partially_read_file_that_grew_is_left_alone(self):
        self.args.max_file_mib = 1
        big = self.write("alice/webapps/site/big.php", request_sample() + b"a" * (triage.MIB + 10))
        self.scan(big)
        with big.open("ab") as handle:
            handle.write(b"appended after the scan")
        [candidate] = triage.quarantine_candidates(str(self.report_dir))
        ok, message = triage.quarantine_file(candidate, self.qdir, str(self.report_dir))
        self.assertFalse(ok)
        self.assertIn("changed since the scan", message)
        self.assertTrue(big.exists())

    def test_other_hard_links_are_reported(self):
        shell, _ = self.shell_and_upload()
        os.link(str(shell), str(shell.with_name("copy.php")))
        self.scan(shell)
        [candidate] = triage.quarantine_candidates(str(self.report_dir))
        ok, message = triage.quarantine_file(candidate, self.qdir, str(self.report_dir))
        self.assertTrue(ok, message)
        self.assertIn("1 other hard link", message)

    def test_restore_never_overwrites_a_newer_file(self):
        shell, _ = self.shell_and_upload()
        self.scan(shell)
        self.quarantine_all()
        shell.write_bytes(b"redeployed file")
        [item] = triage.quarantined_items(self.qdir)
        ok, message = triage.restore_item(item, self.qdir)
        self.assertFalse(ok)
        self.assertIn("already exists", message)
        self.assertEqual(shell.read_bytes(), b"redeployed file")
        self.assertEqual(len(triage.quarantined_items(self.qdir)), 1)

    def test_purge_deletes_only_the_chosen_copy(self):
        shell, upload = self.shell_and_upload()
        self.scan(shell, upload)
        self.quarantine_all()
        first, second = triage.quarantined_items(self.qdir)
        ok, message = triage.purge_item(first, self.qdir)
        self.assertTrue(ok, message)
        self.assertFalse((Path(self.qdir) / first["id"]).exists())
        self.assertEqual([i["id"] for i in triage.quarantined_items(self.qdir)], [second["id"]])
        self.assertFalse(shell.exists())

    def test_every_action_is_logged(self):
        shell, _ = self.shell_and_upload()
        self.scan(shell)
        self.quarantine_all()
        triage.restore_item(triage.quarantined_items(self.qdir)[0], self.qdir)
        self.quarantine_all()
        triage.purge_item(triage.quarantined_items(self.qdir)[0], self.qdir)
        rows = [json.loads(line) for line in (Path(self.qdir) / "actions.jsonl").read_text().splitlines()]
        self.assertEqual([r["action"] for r in rows], ["quarantine", "restore", "quarantine", "purge"])
        self.assertEqual({r["original_path"] for r in rows}, {str(shell)})
        self.assertEqual({r["sha256"] for r in rows}, {hashlib.sha256(request_sample()).hexdigest()})

    def test_report_and_quarantine_folders_must_be_private(self):
        shell, _ = self.shell_and_upload()
        self.scan(shell)
        self.report_dir.chmod(0o755)
        with self.assertRaises(ValueError):
            triage.quarantine_candidates(str(self.report_dir))
        self.report_dir.chmod(0o700)
        Path(self.qdir).mkdir(mode=0o755)
        Path(self.qdir).chmod(0o755)
        [candidate] = triage.quarantine_candidates(str(self.report_dir))
        with self.assertRaises(ValueError):
            triage.quarantine_file(candidate, self.qdir, str(self.report_dir))
        self.assertTrue(shell.exists())

    def test_prompt_moves_only_the_chosen_files_after_confirmation(self):
        shell, upload = self.shell_and_upload()
        self.scan(shell, upload)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = triage.offer_quarantine(str(self.report_dir), self.qdir, ask=self.answers("1", "y"))
        self.assertEqual(code, 0)
        self.assertFalse(shell.exists())
        self.assertTrue(upload.exists())
        self.assertIn(str(upload), out.getvalue())

    def test_skipping_declining_or_closing_the_prompt_changes_nothing(self):
        shell, upload = self.shell_and_upload()
        self.scan(shell, upload)
        for replies in (("",), ("a", "n"), ("a",), ()):
            with contextlib.redirect_stdout(io.StringIO()):
                code = triage.offer_quarantine(str(self.report_dir), self.qdir, ask=self.answers(*replies))
            self.assertEqual(code, 0, replies)
            self.assertTrue(shell.exists() and upload.exists(), replies)

    def test_an_invalid_choice_is_asked_again(self):
        shell, upload = self.shell_and_upload()
        self.scan(shell, upload)
        with contextlib.redirect_stdout(io.StringIO()) as out:
            triage.offer_quarantine(str(self.report_dir), self.qdir, ask=self.answers("9", "h", "y"))
        self.assertIn("Choose", out.getvalue())
        self.assertFalse(shell.exists())
        self.assertTrue(upload.exists())

    def test_restore_prompt_restores_the_chosen_file(self):
        shell, upload = self.shell_and_upload()
        self.scan(shell, upload)
        self.quarantine_all()
        with contextlib.redirect_stdout(io.StringIO()):
            code = triage.offer_restore(self.qdir, ask=self.answers("1", "y"))
        self.assertEqual(code, 0)
        self.assertTrue(shell.exists())
        self.assertFalse(upload.exists())

    def test_purge_prompt_needs_the_word_delete(self):
        shell, upload = self.shell_and_upload()
        self.scan(shell, upload)
        self.quarantine_all()
        with contextlib.redirect_stdout(io.StringIO()):
            triage.offer_purge(self.qdir, ask=self.answers("1", "y"))
        self.assertEqual(len(triage.quarantined_items(self.qdir)), 2)
        with contextlib.redirect_stdout(io.StringIO()):
            code = triage.offer_purge(self.qdir, ask=self.answers("1", "DELETE"))
        self.assertEqual(code, 0)
        self.assertEqual([i["original_path"] for i in triage.quarantined_items(self.qdir)], [str(upload)])


if __name__ == "__main__":
    unittest.main()
