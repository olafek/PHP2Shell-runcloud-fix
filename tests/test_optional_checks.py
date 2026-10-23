"""Offline fixtures for optional package assessment and sensor log imports."""
import contextlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "runcloud-triage.py"
spec = importlib.util.spec_from_file_location("triage_optional", str(SCRIPT))
triage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(triage)


def zeek(note="Large_Form_Key", **extra):
    data = {"ts": 1792666800.5, "note": "PHP2SHELL::" + note, "uid": "Cfixture123",
            "id.orig_h": "192.0.2.1", "id.resp_h": "2001:db8::1", "id.orig_p": 45000, "id.resp_p": 443}
    data.update(extra)
    return data


def eve(sid=3000650, **extra):
    data = {"timestamp": "2026-10-22T11:00:00.123456+0200", "event_type": "alert",
            "alert": {"signature_id": sid, "signature": "private-message"}, "flow_id": 12345678901234567,
            "src_ip": "192.0.2.1", "dest_ip": "192.0.2.2", "src_port": 45000, "dest_port": 443}
    data.update(extra)
    return data


def package(name, version, status="install ok installed"):
    return "Package: {}\nStatus: {}\nVersion: {}\n\n".format(name, status, version).encode()


class OptionalRuleTests(unittest.TestCase):
    def test_flags_default_off_and_do_not_apply_to_quarantine(self):
        args = triage.parse_options([])
        self.assertEqual(triage.optional_checks(args), {"php_assessment": False, "zeek_notice_files": 0, "suricata_eve_files": 0})
        with contextlib.redirect_stderr(io.StringIO()):
            for action in ("--restore", "--purge"):
                with self.assertRaises(SystemExit):
                    triage.parse_options([action, "--assess-php"])
            with self.assertRaises(SystemExit):
                triage.parse_options(["--zeek-notice", "notice.log", "--suricata-eve", "notice.log"])

    def test_official_cutoffs_epochs_vendor_revisions_and_unknown_versions(self):
        for branch, fixed in (((8, 2), 35), ((8, 3), 36), ((8, 4), 27), ((8, 5), 12)):
            prefix = "{}.{}.".format(*branch)
            self.assertEqual(triage.php_version_assessment(prefix + str(fixed - 1))[0], "below_upstream_fix")
            self.assertEqual(triage.php_version_assessment("2:" + prefix + str(fixed) + "-1ubuntu2")[0], "at_or_above_upstream_fix")
            self.assertEqual(triage.php_version_assessment(prefix + str(fixed) + "RC1")[0], "unknown")
        for version in ("7.4.33", "7.4.99-vendor", "8.1.34", "5.6.40"):
            self.assertEqual(triage.php_version_assessment(version)[0], "legacy_requires_vendor_verification")
        for version in ("8.6.0", "6.0.0", "5.3.29", "8.99.1", "8.2", "bad", "8.2.35garbage", "8.2.35\nsecret"):
            self.assertEqual(triage.php_version_assessment(version)[0], "unknown")

    def test_only_installed_runtime_packages_are_assessed(self):
        data = b"".join(package(name, version) for name, version in (
            ("php8.2-fpm", "8.2.34-1"), ("php82rc-cli", "8.2.35-1"),
            ("libapache2-mod-php8.3", "8.3.36"), ("lsphp84", "8.4.27"),
            ("php8.2-mysql", "8.2.34"), ("php8.2", "8.2.34"), ("php-common", "1:99")))
        data += package("php8.4-fpm", "8.4.26", "deinstall ok config-files")
        rows = list(triage.php_packages(data))
        self.assertEqual([row[2] for row in rows], ["fpm", "cli", "apache", "lsapi"])

    def test_zeek_notices_and_suricata_ids_are_typed_and_filtered(self):
        for note in triage.ZEEK_NOTICES:
            row = triage.sensor_record(zeek(note), "zeek")
            self.assertEqual(row["kind"], "runtime" if note.startswith("Potentially") else "network")
            self.assertEqual(row["severity"], "REVIEW")
        for sid in (3000650, 3000651, 3000652):
            row = triage.sensor_record(eve(sid), "suricata")
            self.assertEqual(row["kind"], "network" if sid == 3000650 else "runtime")
            self.assertEqual(row["event_utc"], "2026-10-22T09:00:00+00:00")
        self.assertIsNone(triage.sensor_record(zeek("Unrecognized"), "zeek"))
        self.assertIsNone(triage.sensor_record(eve(12345), "suricata"))
        self.assertIsNone(triage.sensor_record({"event_type": "dns"}, "suricata"))

    def test_sensor_metadata_never_copies_payloads_messages_or_cookies(self):
        for data, source in ((zeek(msg="private-message", sub="body_sample=private-secret", cookie="private-cookie"), "zeek"),
                             (eve(payload="private-payload", http={"url": "private-url", "cookie": "private-cookie"}), "suricata")):
            row = triage.sensor_record(data, source)
            self.assertNotIn("private-", json.dumps(row))
            self.assertEqual(row["source_ip"], "192.0.2.1")
            self.assertEqual(row["destination_port"], 443)
        for invalid in ([], {"note": None}, zeek(ts="NaN"), zeek(ts=True), zeek(ts="Infinity"),
                        zeek(**{"id.orig_h": "private-token"}), zeek(**{"id.orig_h": 123})):
            with self.assertRaises(ValueError):
                triage.sensor_record(invalid, "zeek")


@unittest.skipUnless(sys.platform.startswith("linux"), "Filesystem tests require Linux")
class OptionalFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="triage-optional-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / "report"
        self.out.mkdir(mode=0o700)
        self.args = triage.parse_options([])
        self.args.home = str(self.root / "home")
        Path(self.args.home).mkdir()
        self.args.user_mode = True
        self.args.since = "2026-10-01T00:00:00Z"
        self.args.notify_findings = True
        self.report = triage.Report(str(self.out), self.args)
        self.addCleanup(self.close_report)

    def close_report(self):
        for handle in self.report.handles.values():
            handle.close()

    def rows(self, name):
        for handle in self.report.handles.values():
            handle.flush()
        path = self.out / (name + ".jsonl")
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return str(path)

    def test_disabled_options_do_not_inspect_packages_or_import_sensors(self):
        with mock.patch.object(triage, "assess_php", side_effect=AssertionError("disabled assessment")), \
                mock.patch.object(triage, "import_sensor_log", side_effect=AssertionError("disabled import")), \
                contextlib.redirect_stdout(io.StringIO()):
            triage.run_scan(self.report)
        self.assertEqual(self.report.counts["sensor_logs"], 0)
        self.assertEqual(self.report.counts["php_packages_assessed"], 0)

    def test_package_assessment_keeps_uncertainty_and_never_executes_php(self):
        data = package("php8.2-fpm", "8.2.34-1vendor") + package("php8.3-cli", "8.3.36-1")
        with mock.patch.object(triage, "read_prefix", return_value=(data, None, False)), \
                mock.patch.object(triage.subprocess, "Popen", side_effect=AssertionError("No executables needed")), \
                contextlib.redirect_stdout(io.StringIO()):
            triage.assess_php(self.report)
        rows = self.rows("php-runtime")
        self.assertEqual([row["severity"] for row in rows], ["REVIEW", "INFO"])
        self.assertTrue(all(row["kind"] == "runtime" and row["serving_runtime_verified"] is False for row in rows))
        self.assertEqual(self.report.gaps["php_serving_runtime_unverified"], 1)
        self.assertEqual(triage.quarantine_candidates(str(self.out)), [])

    def test_truncated_package_record_is_not_assessed(self):
        data = package("php8.2-fpm", "8.2.35") + b"Package: php8.3-fpm\nStatus: install ok installed\nVersion: 8.3.3"
        with mock.patch.object(triage, "read_prefix", return_value=(data, None, True)), contextlib.redirect_stdout(io.StringIO()):
            triage.assess_php(self.report)
        self.assertEqual(len(self.rows("php-runtime")), 1)
        self.assertEqual(self.report.gaps["php_inventory_content_limit"], 1)

    def test_json_gzip_and_default_tsv_zeek_inputs(self):
        records = json.dumps(zeek(msg="private-secret")).encode() + b"\n"
        path = self.write("notice.json.gz", gzip.compress(records))
        triage.import_sensor_log(path, "zeek", self.report)
        tsv = (b"#separator \\x09\n#fields\tts\tnote\tid.orig_h\tid.resp_h\tuid\n"
               b"1792666800.5\tPHP2SHELL::PHP_Crash_Sequence\t192.0.2.1\t192.0.2.2\tCfixture\n")
        triage.import_sensor_log(self.write("notice.log", tsv), "zeek", self.report)
        rows = self.rows("network-alerts")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1]["line_or_chunk"], 3)
        self.assertNotIn("private-secret", json.dumps(rows))
        self.assertEqual(triage.quarantine_candidates(str(self.out)), [])

    def test_import_paths_are_counted_once_and_not_scanned_as_files(self):
        path = self.write("home/eve.json", (json.dumps(eve(payload="system($_POST['x']);")) + "\n").encode())
        self.args.suricata_eve = [path, path]
        self.args.extra_root = [self.args.home]
        self.args.log_root = [path]
        with contextlib.redirect_stdout(io.StringIO()):
            triage.run_scan(self.report)
        self.assertEqual(self.report.completed_items, 1)
        self.assertEqual(self.report.total_items, 1)
        self.assertEqual(self.report.counts["files"], 0)
        self.assertEqual(self.report.counts["logs"], 1)
        self.assertEqual({row["rule"] for row in self.rows("findings")}, {"php_network_indicator"})

    def test_samples_cap_saved_rows_but_keep_counts_and_callback_kinds(self):
        self.args.suricata_eve = [str(self.root / "eve.json")]
        self.args.log_samples = 1
        path = self.write("eve.json", ((json.dumps(eve()) + "\n") * 3).encode())
        triage.import_sensor_log(path, "suricata", self.report)
        payload = triage.notification_payload(self.args, self.report, time.time(), 1, True, True, 1)
        self.assertEqual(self.report.severities["REVIEW"], 3)
        self.assertEqual(len(self.rows("network-alerts")), 1)
        self.assertEqual(payload["findings_omitted"], 2)
        self.assertEqual(payload["findings"][0]["kind"], "network")
        self.assertNotIn("private-message", json.dumps(payload))
        self.args.notify_findings = False
        summary = triage.notification_payload(self.args, self.report, time.time(), 1, True, True, 1)
        self.assertNotIn("findings", summary)
        self.assertNotIn(path, json.dumps(summary))

    def test_bad_records_and_oversized_lines_do_not_hide_later_valid_events(self):
        good = (json.dumps(eve()) + "\n").encode()
        path = self.write("bad.json", b"broken\n[]\n" + b"x" * (triage.MIB + 20) + b"\n" + good)
        triage.import_sensor_log(path, "suricata", self.report)
        self.assertEqual(self.report.counts["sensor_indicators"], 1)
        self.assertEqual(self.rows("network-alerts")[0]["line_or_chunk"], 4)
        self.assertEqual(self.report.gaps["sensor_records_invalid"], 1)

    def test_unreadable_missing_and_symlinked_inputs_are_explicit_gaps(self):
        target = self.write("original.json", (json.dumps(eve()) + "\n").encode())
        link = self.root / "symlink.json"
        link.symlink_to(target)
        triage.import_sensor_log(str(link), "suricata", self.report)
        triage.import_sensor_log(str(self.root / "absent.json"), "suricata", self.report)
        self.assertEqual(self.report.gaps["sensor_log_read_error"], 2)
        self.assertEqual(self.report.counts["sensor_indicators"], 0)

    def test_total_and_per_log_byte_limits_are_enforced(self):
        self.args.max_log_mib = self.args.max_total_log_mib = 1
        line = (json.dumps(eve()) + "\n").encode()
        path = self.write("big.json", line * (triage.MIB // len(line) + 2))
        triage.import_sensor_log(path, "suricata", self.report)
        self.assertEqual(self.report.counts["log_bytes"], triage.MIB)
        self.assertEqual(self.report.gaps["log_content_limit"], 1)
        triage.import_sensor_log(path, "suricata", self.report)
        self.assertEqual(self.report.gaps["total_log_budget_exhausted"], 1)

    def test_exact_budget_eof_without_newline_is_a_complete_record(self):
        self.args.max_log_mib = self.args.max_total_log_mib = 1
        record = json.dumps(eve()).encode()
        # Whitespace is legal before a JSON record and must not be confused with a cut record.
        path = self.write("exact.json", b" " * (triage.MIB - len(record)) + record)
        triage.import_sensor_log(path, "suricata", self.report)
        self.assertEqual(self.report.counts["sensor_indicators"], 1)
        self.assertNotIn("log_content_limit", self.report.gaps)
        self.assertNotIn("sensor_records_invalid", self.report.gaps)

    def test_non_file_kinds_never_enter_quarantine_even_with_a_hash(self):
        for kind in ("runtime", "network"):
            self.report.finding("/var/log/eve.json", {"kind": kind, "severity": "REVIEW", "rule": "fixture",
                                                      "sha256": "a" * 64, "content_complete": True})
        self.rows("findings")
        self.assertEqual(triage.quarantine_candidates(str(self.out)), [])

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "Isolated CLI needs root to chroot and drop privileges")
    def test_cli_root_and_user_optional_checks_callbacks_and_failures(self):
        jail = self.root / "jail"
        for relative in ("root", "etc", "home/account/webapps/site", "tmp", "var/lib/dpkg", "opt/sensors"):
            (jail / relative).mkdir(parents=True, exist_ok=True)
        for directory, _, _ in os.walk(str(jail)):
            os.chmod(directory, 0o755)
        (jail / "root").chmod(0o700)
        os.chown(str(jail / "home/account"), 1001, 1001)
        (jail / "etc/passwd").write_text("account:x:1001:1001::/home/account:/bin/sh\n")
        (jail / "runcloud-triage.py").write_bytes(SCRIPT.read_bytes())
        (jail / "runcloud-triage.py").chmod(0o644)
        (jail / "var/lib/dpkg/status").write_bytes(package("php82rc-fpm", "8.2.34-1"))
        (jail / "opt/sensors/eve.json").write_text(json.dumps(eve()) + "\n")
        (jail / "opt/sensors/notice.log").write_text(json.dumps(zeek()) + "\n")
        code = (
            "import os,sys,pwd,importlib.util,_strptime,encodings.ascii; pwd.getpwuid(os.geteuid()); "
            "s=importlib.util.spec_from_file_location('triage',sys.argv[1]+'/runcloud-triage.py'); "
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
            "m.send_notification=lambda args,payload,token=None: print('CALLBACK '+m.json.dumps(payload)) or True; "
            "os.chroot(sys.argv[1]); os.chdir('/'); m.__file__='/runcloud-triage.py'; "
            "uid=int(sys.argv[2]); os.setgroups([]); os.setgid(uid); os.setuid(uid); "
            "sys.argv=['runcloud-triage.py']+sys.argv[3:]; sys.exit(m.main())"
        )
        def run(uid, args):
            return subprocess.run([sys.executable, "-c", code, str(jail), str(uid)] + args,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        options = ["--assess-php", "--zeek-notice", "/opt/sensors/notice.log", "--suricata-eve", "/opt/sensors/eve.json",
                   "--notify-url", "https://example.test/hook", "--notify-findings"]
        for uid in (0, 1001):
            result = run(uid, options)
            self.assertEqual(result.returncode, 1, result.stdout.decode() + result.stderr.decode())
            payload = json.loads(next(line[9:] for line in result.stdout.decode().splitlines() if line.startswith("CALLBACK ")))
            self.assertEqual(payload["optional_counts"]["php_packages_assessed"], 1)
            self.assertEqual(payload["optional_counts"]["sensor_indicators"], 2)
            self.assertEqual({row["kind"] for row in payload["findings"]}, {"network", "runtime"})
            self.assertNotIn(b"can be quarantined", result.stdout)
            self.assertEqual(run(uid, ["--zeek-notice", "/missing"]).returncode, 2)
        (jail / "opt/sensors/eve.json").write_text("invalid JSON\n")
        self.assertEqual(run(1001, ["--suricata-eve", "/opt/sensors/eve.json"]).returncode, 2)


if __name__ == "__main__":
    unittest.main()
