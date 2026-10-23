"""Offline checkpoint recovery fixtures; never execute the PHP sample bytes."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "runcloud-triage.py"
spec = importlib.util.spec_from_file_location("resume_triage", str(SCRIPT))
triage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(triage)
SAMPLE = b"<" + b"?php system(" + b"$_POST['fixture']);"


@unittest.skipUnless(sys.platform.startswith("linux"), "Resume requires Linux descriptors/locks")
class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, self.previous_umask)
        self.tmp = tempfile.TemporaryDirectory(prefix="runcloud-resume-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.reports = []
        self.output = io.StringIO()
        self.quiet = contextlib.redirect_stdout(self.output)
        self.quiet.__enter__()
        self.addCleanup(self.quiet.__exit__, None, None, None)
        self.addCleanup(self.close_reports)

    def close_reports(self):
        for report in self.reports:
            if report.checkpoints:
                report.checkpoints.close()
            for handle in report.handles.values():
                handle.close()

    def write(self, name, data=SAMPLE):
        path = self.home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def source(self, report):
        source = triage.ResumeSource(str(report.out))
        self.addCleanup(source.close)
        return source

    def report(self, source=None, extra=()):
        out = self.root / ("report-" + str(len(self.reports)))
        out.mkdir(mode=0o700)
        argv = (["--resume", source.path] if source else ["--home", str(self.home), "--since", "2026-10-01"])
        args = triage.parse_options(argv + ["--no-precount", "--notify-url", "https://example.test/hook", "--notify-findings"] + list(extra))
        if source:
            source.restore_options(args)
        args.user_mode = True  # Only this temporary tree, never host /home, /etc, logs or snapshots.
        args.since = args.since.isoformat()
        args.patched_at = args.patched_at.isoformat() if args.patched_at else None
        report = triage.Report(out, args)
        report.vendor_baseline = triage.read_vendor_baseline(args.vendor_baseline)
        self.reports.append(report)
        report.checkpoints = triage.Checkpoints(report, source)
        return report

    def run_report(self, report):
        triage.run_scan(report)
        report.checkpoints.seal()
        report.finish(True)
        report.checkpoints.close()

    def rows(self, report, stream):
        for handle in report.handles.values():
            handle.flush()
        path = report.out / (stream + ".jsonl")
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_resume_reuses_unchanged_checks_without_duplicate_findings_or_notifications(self):
        self.write("a.php")
        self.write("b.php", b"ordinary text")
        first = self.report()
        self.run_report(first)
        before = {p.name: p.read_bytes() for p in first.out.iterdir()}
        second = self.report(self.source(first))
        with mock.patch.object(triage, "scan_file", side_effect=AssertionError("unchanged content was read again")):
            self.run_report(second)
        self.assertEqual(second.counts["files_reused"], 2)
        self.assertEqual(second.counts["files"], 2)
        self.assertEqual(second.severities, first.severities)
        self.assertEqual(second.gaps, first.gaps)
        self.assertEqual(len(self.rows(second, "findings")), len(self.rows(first, "findings")))
        self.assertEqual(len(second.notification_findings), len(first.notification_findings))
        self.assertTrue(second.notification_findings[0]["reused"])
        self.assertEqual(second.notification_findings[0]["inspected_utc"], first.notification_findings[0]["inspected_utc"])
        payload = triage.notification_payload(second.args, second, second.started, 1, True, True, 1)
        self.assertEqual(payload["counts"]["files_reused"], 2)
        self.assertEqual(payload["resumed_from"], str(first.out))
        self.assertEqual(before, {p.name: p.read_bytes() for p in first.out.iterdir()})
        self.assertNotIn(b"example.test", (second.out / "checkpoint.jsonl").read_bytes())
        self.assertFalse((second.out / "resume-index.sqlite").exists())
        for report in (first, second):
            for path in report.out.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_changed_new_deleted_and_replaced_files_and_logs_are_refreshed(self):
        unchanged = self.write("unchanged.php")
        changed = self.write("changed.php")
        deleted = self.write("deleted.php")
        replaced = self.write("replaced.php")
        log = self.write("error.log", b"PHP Fatal error: fixture\n")
        first = self.report()
        self.run_report(first)
        old = changed.stat()
        changed.write_bytes(b"x" * old.st_size)
        os.utime(str(changed), ns=(old.st_atime_ns, old.st_mtime_ns))  # ctime still invalidates cache.
        deleted.unlink()
        replaced.unlink()
        replaced.symlink_to(unchanged)
        added = self.write("new.php")
        with log.open("ab") as handle:
            handle.write(b"PHP Fatal error: another fixture\n")
        second = self.report(self.source(first))
        with mock.patch.object(triage, "scan_file", wraps=triage.scan_file) as scan:
            self.run_report(second)
        self.assertEqual({call[0][0] for call in scan.call_args_list}, {str(changed), str(added)})
        self.assertEqual(second.counts["files_reused"], 1)
        self.assertEqual(second.counts["files"], 3)
        self.assertEqual(second.counts["logs"], 1)
        paths = {row["path"] for row in self.rows(second, "findings") if row["rule"] != "php_in_writable_directory"}
        self.assertEqual(paths, {str(unchanged), str(added), str(log)})
        self.assertEqual(second.severities["INFO"], 2)
        self.assertEqual(len(self.rows(second, "files")), 3)

    def test_partial_reads_keep_limits_and_gaps_on_resume(self):
        self.write("large.bin", b"a" * (2 * triage.MIB))
        first = self.report(extra=["--quick"])
        self.run_report(first)
        second = self.report(self.source(first))
        self.assertTrue(second.args.quick)
        self.assertEqual(second.args.max_file_mib, 1)
        self.run_report(second)
        self.assertEqual(second.counts["files_reused"], 1)
        self.assertEqual(second.gaps["file_content_limit"], 1)
        [row] = self.rows(second, "files")
        self.assertFalse(row["content_complete"])
        self.assertIsNone(row["sha256"])
        self.assertEqual(row["bytes_read"], triage.MIB)

    def test_failed_or_changed_during_read_files_are_not_reused(self):
        self.write("retry.php")
        first = self.report()
        with mock.patch.object(triage, "read_prefix", side_effect=OSError("fixture read failure")):
            self.run_report(first)
        second = self.report(self.source(first))
        self.run_report(second)
        self.assertEqual(second.counts["files_reused"], 0)
        self.assertEqual(second.gaps["file_read_error"], 0)
        self.assertEqual(second.severities["HIGH"], 1)
        source = self.source(second)
        third = self.report(source)
        # A mode change forces a read; a race recorded during that read forbids caching.
        (self.home / "retry.php").chmod(0o600)
        original = triage.read_prefix
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            args[2].gap(args[0], "changed_during_read")
            return result
        with mock.patch.object(triage, "read_prefix", side_effect=changed):
            self.run_report(third)
        fourth = self.report(self.source(third))
        self.run_report(fourth)
        self.assertEqual(fourth.counts["files_reused"], 0)

    def test_resume_can_be_interrupted_again_without_losing_unvisited_checkpoints(self):
        for name in ("a.php", "b.php", "c.php"):
            self.write(name)
        first = self.report()
        self.run_report(first)
        second = self.report(self.source(first))
        targets = list(triage.scan_targets(second, record=False))
        def interrupted(report, record=True):
            yield targets[0]
            raise KeyboardInterrupt()
        with mock.patch.object(triage, "scan_targets", side_effect=interrupted), self.assertRaises(KeyboardInterrupt):
            triage.run_scan(second)
        second.checkpoints.close()
        third = self.report(self.source(second))
        with mock.patch.object(triage, "scan_file", side_effect=AssertionError("lost an inherited checkpoint")):
            self.run_report(third)
        self.assertEqual(third.counts["files_reused"], 3)
        self.assertEqual(third.severities["HIGH"], 3)

    def test_torn_tail_is_ignored_but_a_damaged_complete_record_is_rejected(self):
        self.write("one.php")
        first = self.report()
        self.run_report(first)
        path = first.out / "checkpoint.jsonl"
        with path.open("ab") as handle:
            handle.write(b'{"payload":"unfinished')
        second = self.report(self.source(first))
        self.run_report(second)
        self.assertEqual(second.counts["files_reused"], 1)
        self.assertEqual(second.gaps["checkpoint_tail_incomplete"], 1)
        with (second.out / "checkpoint.jsonl").open("ab") as handle:
            handle.write(b'{"payload":"corrupt","sha256":"wrong"}\n')
        with self.assertRaisesRegex(ValueError, "Damaged checkpoint"):
            self.report(self.source(second))

    def test_active_source_and_concurrent_resumes_are_rejected(self):
        first = self.report()
        with self.assertRaisesRegex(ValueError, "still running"):
            triage.ResumeSource(str(first.out))
        self.run_report(first)
        source = self.source(first)
        with self.assertRaisesRegex(ValueError, "still running"):
            triage.ResumeSource(str(first.out))
        source.close()
        self.source(first).close()

    def test_private_source_links_legacy_reports_and_changed_scanner_are_rejected(self):
        first = self.report()
        self.run_report(first)
        alias = self.root / "alias"
        alias.symlink_to(first.out, target_is_directory=True)
        with self.assertRaises(OSError):
            triage.ResumeSource(str(alias))
        path = first.out / "checkpoint.jsonl"
        path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private"):
            triage.ResumeSource(str(first.out))
        path.chmod(0o600)
        os.link(str(path), str(first.out / "hardlink"))
        with self.assertRaisesRegex(ValueError, "singly linked"):
            triage.ResumeSource(str(first.out))
        (first.out / "hardlink").unlink()
        with mock.patch.object(triage, "VERSION", "future"):
            with self.assertRaisesRegex(ValueError, "same server"):
                triage.ResumeSource(str(first.out))
        legacy = self.root / "legacy"
        legacy.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "no checkpoints"):
            triage.ResumeSource(str(legacy))

    def test_interrupted_checkpoint_import_points_back_to_its_source(self):
        first = self.report()
        self.run_report(first)
        source = self.source(first)
        with mock.patch.object(triage.Checkpoints, "load_source", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.report(source)
        with self.assertRaisesRegex(ValueError, "resume its source report"):
            triage.ResumeSource(str(self.reports[-1].out))

    def test_resume_rejects_changed_scope_and_action_flags(self):
        with contextlib.redirect_stderr(io.StringIO()):
            for flags in (["--home", "/different"], ["--quick"], ["--since=2026-10-01"],
                          ["--max-file-mib=4"], ["--restore"], ["--quarantine", "/report"], ["--purge"]):
                with self.assertRaises(SystemExit):
                    triage.parse_options(["--resume", "/report"] + flags)

    def test_vendor_baseline_is_inherited_and_a_changed_manifest_requires_a_fresh_scan(self):
        path = self.write("vendor/pkg/a.php")
        baseline = self.root / "baseline.json"
        entry = {"sha256": hashlib.sha256(SAMPLE).hexdigest(), "package": "fixture/pkg"}
        baseline.write_text(json.dumps({"schema_version": 1, "files": {str(path): entry}}))
        first = self.report(extra=["--vendor-baseline", str(baseline)])
        self.run_report(first)
        second = self.report(self.source(first))
        self.run_report(second)
        self.assertEqual(second.counts["vendor_match"], 1)
        self.assertEqual(second.gaps["vendor_baseline_unverified"], 0)
        entry["sha256"] = "0" * 64
        baseline.write_text(json.dumps({"schema_version": 1, "files": {str(path): entry}}))
        with self.assertRaisesRegex(ValueError, "Vendor baseline changed"):
            self.report(self.source(second))

    def test_unusual_filename_and_hash_guard_for_reused_quarantine_candidates(self):
        path = self.write(os.fsdecode(b"name-\xff.php"))
        first = self.report()
        self.run_report(first)
        second = self.report(self.source(first))
        self.run_report(second)
        self.assertEqual(second.counts["files_reused"], 1)
        [candidate] = triage.quarantine_candidates(str(second.out))
        self.assertEqual(candidate["path"], str(path))
        self.assertEqual(candidate["scanned"]["sha256"], hashlib.sha256(SAMPLE).hexdigest())
        if os.geteuid() == 0:
            path.write_bytes(b"x" * len(SAMPLE))
            moved, message = triage.quarantine_file(candidate, str(self.root / "quarantine"), str(second.out))
            self.assertFalse(moved)
            self.assertIn("changed since the scan", message)
            self.assertTrue(path.exists())

    def test_replay_rejects_stream_paths_and_missing_file_identities(self):
        path = self.write("fixture.php")
        first = self.report()
        self.run_report(first)
        lines = (first.out / "checkpoint.jsonl").read_bytes().splitlines(keepends=True)
        record = triage.checkpoint_record(lines[1])
        record["rows"][0][0] = "../../outside-report"
        with self.assertRaisesRegex(ValueError, "Invalid file checkpoint"):
            triage.validate_file_checkpoint(record)
        record = triage.checkpoint_record(lines[1])
        record["identity"] = None
        with self.assertRaisesRegex(ValueError, "Invalid file checkpoint"):
            triage.validate_file_checkpoint(record)
        self.assertEqual(record["path"], str(path))

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "Isolated CLI crash test requires root")
    def test_sigkill_checkpoint_recovers_in_real_cli_and_user_scope(self):
        jail = self.root / "jail"
        for name in ("root", "home", "etc", "tmp", "account/webapps"):
            (jail / name).mkdir(parents=True, mode=0o700, exist_ok=True)
        (jail / "runcloud-triage.py").write_bytes(SCRIPT.read_bytes())
        (jail / "etc/passwd").write_text("fixture:x:12345:12345::/account:/bin/sh\n")
        (jail / "etc/passwd").chmod(0o644)
        (jail / "runcloud-triage.py").chmod(0o644)
        jail.chmod(0o755)
        (jail / "etc").chmod(0o755)
        for scope, uid in (("home", 0), ("account/webapps", 12345)):
            for name in ("a.php", "b.php"):
                target = jail / scope / name
                target.write_bytes(SAMPLE)
                os.chown(str(target), uid, uid)
        os.chown(str(jail / "account"), 12345, 12345)
        os.chown(str(jail / "account/webapps"), 12345, 12345)
        code = """
import os, sys, signal, importlib.util, sqlite3, fcntl, _strptime, encodings.ascii, pwd
pwd.getpwuid(os.geteuid())  # Preload older glibc's NSS module before entering the minimal jail.
spec = importlib.util.spec_from_file_location('triage', sys.argv[1] + '/runcloud-triage.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
uid, crash = int(sys.argv[2]), sys.argv[3] == 'crash'
os.chroot(sys.argv[1]); os.chdir('/'); m.__file__ = '/runcloud-triage.py'
if uid:
    os.setgroups([]); os.setgid(uid); os.setuid(uid)
m.send_notification = lambda args, payload, token=None: print('CALLBACK ' + m.json.dumps(payload)) or True
if crash:
    original = m.Checkpoints.add
    def kill_after_checkpoint(self, record):
        original(self, record)
        self.sync(force=True)
        os.kill(os.getpid(), signal.SIGKILL)
    m.Checkpoints.add = kill_after_checkpoint
sys.argv = ['runcloud-triage.py'] + sys.argv[4:]
sys.exit(m.main())
"""
        for uid, parent in ((0, "root"), (12345, "account")):
            command = [sys.executable, "-c", code, str(jail), str(uid)]
            first = subprocess.run(command + ["crash", "--no-precount"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(first.returncode, -signal.SIGKILL, first.stderr.decode())
            [old] = list((jail / parent).glob("runcloud-triage-*"))
            original = {p.name: p.read_bytes() for p in old.iterdir()}
            second = subprocess.run(command + ["resume", "--resume", "/" + parent + "/" + old.name,
                                               "--notify-url", "http://example.test/hook", "--notify-findings"],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(second.returncode, 1, second.stdout.decode() + second.stderr.decode())
            payload = json.loads(next(line[9:] for line in second.stdout.decode().splitlines() if line.startswith("CALLBACK ")))
            self.assertTrue(payload["scan_finished"])
            self.assertTrue(payload["report_finalized"])
            self.assertEqual(payload["counts"]["files_reused"], 1)
            self.assertEqual(payload["indicators"]["HIGH"], 2)
            self.assertEqual(len(payload["findings"]), 2)
            self.assertEqual(payload["scan_scope"], "user" if uid else "system")
            self.assertEqual(original, {p.name: p.read_bytes() for p in old.iterdir()})


if __name__ == "__main__":
    unittest.main()
