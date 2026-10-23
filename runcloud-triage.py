#!/usr/bin/env python3
"""Read-only incident triage for Ubuntu 18.04+/RunCloud. Python 3.6+, standard library.

Run with /usr/bin/python3 -I. Never imports or executes application code.
A scan only writes to a newly created private report directory. See README.md.
Optional --notify-url posts a small result summary to your own HTTP(S) endpoint.
Add --notify-findings to include the full saved findings list without log excerpts.
Files are moved only when a person chooses them at a terminal: after a scan, or
later with --quarantine REPORT_DIR, --restore or --purge (no rescan needed).
"""

import argparse
import bz2
import collections
from contextlib import ExitStack, contextmanager
import datetime as dt
import errno
import functools
import gzip
import hashlib
import http.client
import ipaddress
import json
import lzma
import os
from pathlib import Path
import re
import selectors
import shlex
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "1.8.0"
MIB = 1024 * 1024
# Not named runcloud-triage-* so it is never mistaken for (or globbed with) a report folder.
QUARANTINE_DIR = "/root/runcloud-quarantine"
QUARANTINE_ITEM = re.compile(r"\d{8}T\d{6}Z-[0-9a-f]{8}")
SEVERITY_ORDER = {"HIGH": 0, "REVIEW": 1}
UTC = dt.timezone.utc
PHP_EXT = re.compile(r"\.(?:php\d*|phtml|pht|phar|inc)(?:\.|$)", re.I)
LOG_NAME = re.compile(r"(?:\.log(?:[.\-].*)?$|^(?:syslog|messages|kern\.log)(?:\.\d+)?(?:\.gz)?$)", re.I)
ARCHIVE_EXT = (".zip", ".gz", ".bz2", ".xz", ".7z", ".tar", ".rar", ".phar")
PHP_TAG = re.compile(rb"<\?(?:php\b|=)", re.I)
PHP_CODE_HINT = re.compile(rb"[$(;]|\?>")
INPUT = rb"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\["
RULES = [
    ("HIGH", "request_to_execution", re.compile(
        rb"\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*" + INPUT, re.I),
     "Request data passed directly to an execution function; verify context."),
    ("HIGH", "encoded_execution", re.compile(
        rb"\b(?:eval|assert)\s*\(\s*(?:(?:gzinflate|gzuncompress|str_rot13)\s*\(\s*)?(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(", re.I),
     "Encoded content passed to eval/assert; legitimate packers can also match."),
    ("HIGH", "variable_request_callable", re.compile(
        INPUT + rb"[^\]\r\n]{1,160}\]\s*\(", re.I),
     "Request-controlled callable; review source without executing it."),
    ("REVIEW", "webshell_marker", re.compile(
        rb"(?:WSO\s+(?:[234]\.\d|Web\s*Shell)|FilesMan|b374k|c99shell|r57shell|weevely|ALFA\s+Team|AnonymousFox)", re.I),
     "Webshell-related text; signatures can occur in security tools or test data."),
    ("HIGH", "shell_network_or_download", re.compile(
        rb"(?:/dev/tcp/|\b(?:curl|wget)\b[^\r\n]{0,240}\|\s*(?:ba)?sh\b|\b(?:nc|ncat)\s[^\r\n]{0,160}\s-e\s)", re.I),
     "Network shell or download-and-execute pattern; verify administrative uses."),
]
LOG_RULES = [
    ("REVIEW", "php_memory_error", re.compile(rb"Allowed memory size[^\r\n]{0,160}exhausted|Out of memory", re.I)),
    ("REVIEW", "worker_crash", re.compile(rb"SIGSEGV|segmentation fault|segfault|signal 11|core dumped", re.I)),
    ("INFO", "php_fatal_or_timeout", re.compile(rb"PHP (?:Fatal|Parse) error|Maximum execution time[^\r\n]{0,80}exceeded", re.I)),
    ("REVIEW", "request_payload_marker", re.compile(rb"PHP_SESSION_UPLOAD_PROGRESS|auto_prepend_file|(?:base64_decode|shell_exec|passthru|eval)\s*\(|/dev/tcp/|<\?php", re.I)),
    ("INFO", "successful_ssh_login", re.compile(rb"sshd[^\r\n]{0,160}Accepted (?:publickey|password)", re.I)),
]
ACCESS = re.compile(rb'^(\S+).*?\[([^\]]+)\]\s+"(\S+)\s+(\S+)[^"]*"\s+(\d{3})\b')
CONFIG_NAMES = {".user.ini", ".htaccess", "php.ini"}
PERSISTENCE_NAMES = {"authorized_keys", "authorized_keys2", ".bashrc", ".profile", ".bash_profile"}
# Official PHP advisory, 2026-10-21. Version evidence alone cannot verify vendor
# backports, the serving runtime, or whether existing workers were restarted.
PHP_FIXED = {(8, 2): 35, (8, 3): 36, (8, 4): 27, (8, 5): 12}
PHP_ADVISORY = "https://www.php.net/archive/2026.php#2026-10-21-5"
ZEEK_NOTICES = {
    "PHP_Crash_Sequence", "Multipart_Header_Flood", "Large_Form_Key",
    "Serialized_Integer_Overflow", "Serialized_Integer_Collisions",
    "Serialized_String_Collisions", "Serialized_Duplicate_Array",
    "Serialized_Object_Repetition", "Potentially_Affected_PHP_Version",
}
SURICATA_RULES = {3000650: "Upload_Progress_Marker", 3000651: "Potentially_Affected_PHP_Header",
                  3000652: "Potentially_Affected_PHP_Info"}


def utc(ts):
    return dt.datetime.fromtimestamp(ts, UTC).isoformat(timespec="seconds")


def parse_time(value):
    try:
        # datetime.fromisoformat and colon-aware strptime %z require Python 3.7.
        match = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,6}))?)?(Z|[+-]\d{2}:?\d{2})?)?", value)
        if not match:
            raise ValueError("Invalid date")
        year, month, day, hour, minute, second, fraction, zone = match.groups()
        tz = UTC
        if zone and zone != "Z":
            offset = zone[1:].replace(":", "")
            hours, minutes = int(offset[:2]), int(offset[2:])
            if hours > 23 or minutes > 59:
                raise ValueError("Invalid UTC offset")
            tz = dt.timezone(dt.timedelta(minutes=(hours * 60 + minutes) * (1 if zone[0] == "+" else -1)))
        parsed = dt.datetime(int(year), int(month), int(day), int(hour or 0), int(minute or 0),
                             int(second or 0), int((fraction or "0").ljust(6, "0")), tzinfo=tz)
        return parsed.astimezone(UTC)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Use YYYY-MM-DD or ISO 8601 with timezone") from exc


def bounded_int(value):
    value = int(value)
    if value <= 0:
        raise argparse.ArgumentTypeError("Must be positive")
    return value


def notification_url(value):
    try:
        if any(ord(char) <= 32 or ord(char) == 127 for char in value):
            raise ValueError()
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.fragment
                or parsed.username is not None or parsed.password is not None):
            raise ValueError()
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError()
    except ValueError:
        raise argparse.ArgumentTypeError("Use an absolute HTTP(S) URL without credentials, whitespace or a fragment")
    return value


def notification_timeout(value):
    value = bounded_int(value)
    if value > 60:
        raise argparse.ArgumentTypeError("Notification timeout must be between 1 and 60 seconds")
    return value


def inside(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def open_directory(path):
    """Anchor every component: no following an attacker-controlled ancestor link."""
    path = os.path.abspath(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in Path(path).parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except BaseException:
        os.close(fd)
        raise


def open_regular(path):
    parent, name = os.path.split(os.path.abspath(path))
    dfd = open_directory(parent)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    used_noatime = True
    try:
        try:
            fd = os.open(name, flags | os.O_NOATIME, dir_fd=dfd)
        except OSError as exc:
            if exc.errno not in (errno.EPERM, errno.EACCES, errno.EINVAL, errno.EOPNOTSUPP):
                raise
            used_noatime = False
            fd = os.open(name, flags, dir_fd=dfd)
    finally:
        os.close(dfd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise OSError("Not a regular file (may have changed during scan)")
    return os.fdopen(fd, "rb"), used_noatime


def metadata(path, st):
    return {"path": path, "size": st.st_size, "uid": st.st_uid, "gid": st.st_gid,
            "mode": oct(stat.S_IMODE(st.st_mode)), "mtime_utc": utc(st.st_mtime),
            "ctime_utc": utc(st.st_ctime), "device": st.st_dev, "inode": st.st_ino}


@functools.lru_cache(maxsize=1)
def birthtime_reader():
    """Optional Linux statx reader. Never open another path or substitute ctime."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        call = getattr(libc, "statx", None)
        syscall_number = None
        if call is None:
            # Ubuntu 18.04's libc predates statx(). Limit the raw syscall fallback
            # to known native 64-bit Linux ABIs; unsupported systems return null.
            if ctypes.sizeof(ctypes.c_void_p) != 8:
                return None
            syscall_number = {"x86_64": 332, "aarch64": 291}.get(os.uname().machine)
            if syscall_number is None:
                return None
            call = libc.syscall
            call.restype = ctypes.c_long
        else:
            call.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p]
            call.restype = ctypes.c_int
    except (ImportError, AttributeError, OSError):
        return None

    def read(fd):
        # Linux UAPI statx is 256 bytes: mask at 0, btime (s64 sec/u32 nsec) at 80.
        # Only request STATX_BTIME, using the already link-free-opened descriptor.
        # AT_EMPTY_PATH | AT_STATX_DONT_SYNC avoids path lookup and forced writeback.
        buffer = ctypes.create_string_buffer(256)
        args = [ctypes.c_int(fd), ctypes.c_char_p(b""), ctypes.c_int(0x5000),
                ctypes.c_uint(0x800), ctypes.byref(buffer)]
        result = call(*([ctypes.c_long(syscall_number)] + args if syscall_number is not None else args))
        if result != 0 or not struct.unpack_from("=I", buffer, 0)[0] & 0x800:
            return None
        seconds, nanoseconds = struct.unpack_from("=qI", buffer, 80)
        if nanoseconds >= 1000000000:
            return None
        return utc(seconds)

    return read


def file_birthtime(fd):
    """UTC filesystem creation time, or None when unavailable; never a scan error."""
    try:
        reader = birthtime_reader()
        return reader(fd) if reader is not None else None
    except (OSError, ValueError, OverflowError):
        return None


def readable_php_tag(data):
    """In binary data "<?=" occurs by chance (about once per 16 MiB of compressed image data).
    Count a tag there only when readable, PHP-like text follows it, as in a disguised script."""
    for match in PHP_TAG.finditer(data):
        after = data[match.end():match.end() + 48].lstrip()
        printable = sum(1 for byte in after if 32 <= byte < 127 or byte in (9, 10, 13))
        if len(after) >= 3 and printable >= 0.9 * len(after) and PHP_CODE_HINT.search(after):
            return True
    return False


def mask_php_comments(data):
    """Mask confirmed PHP comments, preserving byte offsets and line numbers.

    This is deliberately conservative, not a PHP parser. Quoted strings are
    consumed intact so comment markers inside them cannot hide executable code.
    At heredoc/nowdoc syntax we stop masking: ambiguous text remains detectable.
    """
    tokens = re.compile(rb"<\?(?:php\b|=)?|\?>|<<<|'(?:\\.|[^'\\])*'|"
                        rb'"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`|'
                        rb"/\*[\s\S]*?(?:\*/|\Z)|//[^\r\n]*(?:\r?\n|\Z)|\#(?!\[)[^\r\n]*(?:\r?\n|\Z)", re.I)
    masked = bytearray(data)
    opening_tag = re.compile(rb"<\?(?:php\b|=)?", re.I)
    in_php = False
    position = 0
    while position < len(data):
        if not in_php:
            opening = opening_tag.search(data, position)
            if not opening:
                break
            position = opening.end()
            in_php = True
        match = tokens.search(data, position)
        if not match:
            break
        token = match.group()
        position = match.end()
        if token == b"<<<":
            break
        if token == b"?>":
            in_php = False
        elif token.startswith((b"/*", b"//", b"#")):
            # A close tag terminates a single-line PHP comment, even before LF.
            end = match.end()
            if not token.startswith(b"/*") and b"?>" in token:
                end = match.start() + token.index(b"?>")
                position = end
            masked[match.start():end] = re.sub(rb"[^\r\n]", b" ", data[match.start():end])
    return bytes(masked)


def file_rules(path, data, persistence=False):
    """Heuristics, not proof of exploitation or attribution to either CVE."""
    name = Path(path).name.lower()
    lower = path.lower().replace("\\", "/")
    php_extension = bool(PHP_EXT.search(name))
    # NUL bytes near the start mean binary content (images, fonts, archives...).
    has_php = readable_php_tag(data) if b"\0" in data[:8192] else bool(PHP_TAG.search(data))
    results = []
    if has_php or php_extension or persistence:
        for severity, rule, pattern, reason in RULES:
            match = pattern.search(data)
            if match and rule == "variable_request_callable":
                match = pattern.search(mask_php_comments(data))
            if match:
                results.append({"severity": severity, "rule": rule, "reason": reason,
                                "line": data.count(b"\n", 0, match.start()) + 1,
                                "byte_offset": match.start()})
    if has_php and not php_extension and name not in CONFIG_NAMES:
        results.append({"severity": "REVIEW", "rule": "php_in_other_file_type",
                        "reason": "PHP opening tag in a file without a usual PHP extension; may be a template/example."})
    if has_php or php_extension:
        if re.search(r"/(?:wp-content/uploads|uploads?|\.cache|tmp)/", lower):
            results.append({"severity": "REVIEW", "rule": "php_in_writable_directory",
                            "reason": "PHP in an upload/temp directory; verify whether this is expected."})
        # Linux paths are case-sensitive: Symfony's Session/Storage is not Laravel storage.
        normalized = path.replace("\\", "/")
        if "/storage/" in normalized and not re.search(r"/storage/framework/(?:views|cache)/", normalized):
            results.append({"severity": "REVIEW", "rule": "php_in_storage",
                            "reason": "PHP in application storage; inspect whether generated code or an unexpected file."})
    if name in CONFIG_NAMES or persistence:
        match = re.search(rb"(?im)^[ \t]*(?![;#])[^\r\n]{0,80}\b(?:auto_prepend_file|auto_append_file)\b[^\r\n]{0,200}", data)
        if match:
            results.append({"severity": "REVIEW", "rule": "php_auto_include",
                            "line": data.count(b"\n", 0, match.start()) + 1,
                            "reason": "Automatic PHP include configured; security plugins can use this legitimately."})
        if re.search(rb"(?im)^[ \t]*(?:AddType|AddHandler|SetHandler)\b[^\r\n]{0,200}(?:php|phtml)", data):
            results.append({"severity": "REVIEW", "rule": "php_handler_override",
                            "reason": "PHP handler override; review which file types become executable."})
    return results, has_php or php_extension


def log_event(line):
    """Decode URL escapes for detection, preserve the original evidence separately."""
    decoded = urllib.parse.unquote_to_bytes(line)
    events = [{"severity": severity, "rule": rule,
               "reason": "Log indicator only; does not establish a successful exploit."}
              for severity, rule, pattern in LOG_RULES if pattern.search(decoded)]
    match = ACCESS.search(line)
    access = None
    if match:
        ip, date, method, target, status = match.groups()
        # Queries may contain tokens; do not put them into traffic aggregation keys.
        endpoint = target.split(b"?", 1)[0][:300].decode("utf-8", "replace")
        date_text = date.decode("ascii", "replace")
        try:
            timestamp = dt.datetime.strptime(date_text, "%d/%b/%Y:%H:%M:%S %z").astimezone(UTC)
            hour = timestamp.strftime("%Y-%m-%dT%H:00Z")
            date_text = timestamp.isoformat()
        except ValueError:
            hour = "unparsed-time"
        access = (ip.decode("ascii", "replace"), date_text, hour,
                  method.decode("ascii", "replace"), endpoint, int(status))
    return events, access


def duration(seconds):
    hours, remainder = divmod(int(max(0, seconds)), 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


class Report:
    def __init__(self, out, args):
        self.out, self.args = Path(out), args
        self.handles = {}
        self.counts = collections.Counter()
        self.severities = collections.Counter()
        self.gaps = collections.Counter()
        self.sites = collections.defaultdict(collections.Counter)
        self.preview = []
        self.notification_findings = [] if args.notify_findings else None
        self.started = time.time()
        self.started_monotonic = time.monotonic()
        self.last_progress = None
        self.interactive = sys.stdout.isatty() and os.environ.get("TERM") != "dumb"
        self.progress_visible = False
        self.progress_phase = "Starting"
        self.counting = False
        self.total_items = None
        self.completed_items = 0
        self.scan_started = None
        self.scan_complete = False
        self.vendor_baseline = {}
        self.vendor_checked = set()

    def emit(self, stream, row):
        if stream not in self.handles:
            fd = os.open(str(self.out / (stream + ".jsonl")), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            self.handles[stream] = os.fdopen(fd, "w", encoding="utf-8")
        self.handles[stream].write(json.dumps(row, ensure_ascii=True) + "\n")

    def gap(self, path, reason, detail=""):
        self.gaps[reason] += 1
        self.emit("coverage", {"path": path, "reason": reason, "detail": str(detail)})

    def site(self, path):
        home = self.args.home.rstrip("/")
        if inside(path, home):
            parts = path[len(home):].strip("/").split("/")
            if self.args.user_mode:
                return home + "/" + parts[0]
            if len(parts) >= 3 and parts[1] == "webapps":
                return home + "/" + "/".join(parts[:3])
            return home + "/" + parts[0] + "/[outside-webapps]"
        return "[system-or-extra-root]"

    def finding(self, path, row, save=True):
        row = dict(row, path=path, site=self.site(path))
        self.severities[row["severity"]] += 1
        self.sites[row["site"]][row["severity"]] += 1
        if save:
            self.emit("findings", row)
            if self.notification_findings is not None:
                # Explicit fields only: never upload log excerpts or arbitrary evidence.
                finding = {key: row[key] for key in (
                    "path", "site", "severity", "rule", "reason", "line", "byte_offset",
                    "line_or_chunk", "sha256", "content_complete", "mtime_utc", "ctime_utc", "birthtime_utc",
                    "expected_sha256", "package", "version", "source", "sensor_rule",
                    "event_utc", "source_ip", "destination_ip", "source_port", "destination_port",
                    "sensor_event_id", "assessment", "fixed_version", "serving_runtime_verified", "role"
                ) if key in row}
                finding["kind"] = row.get("kind", "log" if "excerpt" in row else "file")
                self.notification_findings.append(finding)
        if save and row["severity"] != "INFO" and len(self.preview) < 40:
            self.preview.append({k: row[k] for k in ("severity", "rule", "path")})

    def progress(self, phase=None, force=False):
        if phase is not None:
            self.progress_phase = phase
        now = time.monotonic()
        interval = 0.25 if self.interactive else 15
        if not force and self.last_progress is not None and now - self.last_progress < interval:
            return
        elapsed = duration(now - self.started_monotonic)
        if self.counting:
            message = f"Counting files: {self.total_items:,} found | Elapsed {elapsed}"
        elif self.progress_phase == "Writing report" or self.scan_started is None:
            message = f"{self.progress_phase} | Elapsed {elapsed}"
        else:
            if self.total_items is None:
                status = f"{self.completed_items:,} finished | ETA unavailable"
            else:
                total = max(self.total_items, self.completed_items)
                percent = 100 if self.scan_complete else min(99, int(100 * self.completed_items / max(1, total)))
                filled = percent // 10
                bar = "#" * filled + "-" * (10 - filled)
                eta = "estimating"
                if self.scan_complete:
                    eta = "00:00:00"
                elif self.completed_items and total > self.completed_items:
                    remaining = (now - self.scan_started) * (total - self.completed_items) / self.completed_items
                    eta = "~" + duration(max(1, remaining))
                status = f"[{bar}] {percent:3d}% {self.completed_items:,}/{total:,} | ETA {eta}"
            phase = {"Scanning files": "Files", "Scanning logs": "Logs", "Scan complete": "Scan complete"}.get(
                self.progress_phase, self.progress_phase)
            message = f"{status} | Elapsed {elapsed} | {phase}"
        message += (f" | Matches={sum(self.severities.values()):,}"
                    f" HIGH={self.severities['HIGH']:,} REVIEW={self.severities['REVIEW']:,}"
                    f" INFO={self.severities['INFO']:,}")
        if self.interactive:
            # Stay below the last column so a long status cannot wrap into a list.
            width = max(1, shutil.get_terminal_size((80, 24)).columns - 1)
            print("\r\033[K" + message[:width], end="", flush=True)
            self.progress_visible = True
        else:
            print(f"[{utc(time.time())}] {message}", flush=True)
        self.last_progress = now

    def clear_progress(self):
        if self.progress_visible:
            print("\r\033[K", end="", flush=True)
            self.progress_visible = False

    def finish(self, complete):
        self.progress("Writing report", force=True)
        options = dict(vars(self.args))
        for name in ("notify_url", "notify_token_file"):
            if options.get(name):
                options[name] = "[configured]"
        summary = {
            "scanner_version": VERSION, "hostname": socket.gethostname(),
            "scan_scope": "user" if self.args.user_mode else "system",
            "effective_uid": os.geteuid() if hasattr(os, "geteuid") else None,
            "started_utc": utc(self.started), "finished_utc": utc(time.time()),
            "scan_finished": complete, "counts": dict(self.counts),
            "indicators": dict(self.severities), "coverage_issues": dict(self.gaps),
            "sites": dict(self.sites), "options": options,
            "optional_checks": optional_checks(self.args),
            "verdict": "REVIEW_REQUIRED" if self.severities["HIGH"] or self.severities["REVIEW"] else "NO_MATCHING_INDICATORS",
            "warning": "Not a clean bill of health. Indicators are heuristics, not proof. Review coverage and inventories.",
        }
        self.emit("summary", summary)
        lines = ["RUNCLOUD INCIDENT TRIAGE " + VERSION, "Host: " + summary["hostname"],
                 "Report: " + str(self.out), "Started UTC: " + summary["started_utc"],
                 "Finished UTC: " + summary["finished_utc"],
                 "Scan scope: " + summary["scan_scope"],
                 "Scan finished: " + str(complete), "Result: " + summary["verdict"],
                 summary["warning"], "", "Indicators: " + json.dumps(dict(self.severities)),
                 "Counts: " + json.dumps(dict(self.counts)),
                 "Coverage issues: " + json.dumps(dict(self.gaps)), "", "Site / scope counts:"]
        lines.extend(json.dumps({"site": site, **counts}, ensure_ascii=True) for site, counts in sorted(self.sites.items()))
        lines += ["", "First 40 non-INFO indicators (all indicators are in findings.jsonl):"]
        lines.extend(json.dumps(row, ensure_ascii=True) for row in self.preview)
        lines += ["", "Review findings.jsonl, coverage.jsonl, traffic.jsonl, persistence.jsonl,",
                  "configuration.jsonl, recent-files.jsonl, files.jsonl, logs.jsonl and snapshot-*.txt where present.",
                  "All retained logs were considered regardless of --since, subject to reported limits.",
                  "--since limits recent-file inventory and journal snapshot only, not file signatures.",
                  "mtime/ctime are clues, not creation times or proof of when exploitation happened.",
                  ("Vendor baseline comparison covers only supplied files; inspect vendor-integrity.jsonl and coverage.jsonl."
                   if self.args.vendor_baseline else "No trusted vendor baseline was supplied; dependency integrity is unverified."),
                  "No database audit, memory capture, or complete container inspection was performed.",
                  "Symlinks are inventoried but not followed. Archives are not unpacked.",
                  "Log bodies/Content-Type may be absent; a POST or a 5xx is not proof of attack.",
                  "A live scan is not atomic. Reads may update access times; command execution creates normal audit records.",
                  "Optional checks: " + json.dumps(optional_checks(self.args)),
                  "See php-runtime.jsonl and network-alerts.jsonl when optional checks were enabled.",
                  "Review serving FPM pools and worker restarts separately; installed packages are not proof of the running patch.",
                  "Keep this directory private. Logs and process arguments can contain secrets.", ""]
        with open(self.out / "summary.txt", "x", encoding="utf-8") as handle:
            handle.write("\n".join(lines))
        for handle in self.handles.values():
            handle.close()
        self.handles.clear()
        # Hash report artifacts for subsequent transfer/comparison; not a trusted signature.
        with open(self.out / "SHA256SUMS", "x", encoding="ascii") as manifest:
            for path in sorted(self.out.iterdir()):
                if path.name == "SHA256SUMS" or not path.is_file():
                    continue
                digest = hashlib.sha256()
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(MIB), b""):
                        digest.update(chunk)
                        self.progress()
                manifest.write(digest.hexdigest() + "  " + path.name + "\n")
        self.clear_progress()
        print("\n" + "\n".join(lines[:11]), flush=True)


def walk_files(root, report, record=True):
    """Descriptor-relative traversal; never open a symlink, device, FIFO or socket."""
    visited = set()
    gap = report.gap if record else lambda *args: None

    def descend(fd, path, depth):
        st = os.fstat(fd)
        identity = (st.st_dev, st.st_ino)
        if identity in visited or depth > 128:
            gap(path, "directory_cycle_or_depth_limit")
            return
        visited.add(identity)
        try:
            # listdir(fd) works on Python 3.6; scandir(fd) was added in 3.7.
            for name in os.listdir(fd):
                report.progress()
                child = os.path.join(path, name)
                if inside(child, str(report.out)):
                    continue  # Never ingest the report currently being written.
                try:
                    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if stat.S_ISLNK(st.st_mode):
                        if not record:
                            continue
                        target = os.readlink(name, dir_fd=fd)
                        report.emit("symlinks", {"path": child, "target": target, "followed": False})
                        report.counts["symlinks_not_followed"] += 1
                        # Resolution is for reporting only, never used to open a file.
                        resolved = os.path.realpath(child)
                        if not inside(resolved, root):
                            gap(child, "symlink_target_outside_root", target)
                        elif not os.path.exists(child):
                            gap(child, "broken_or_looping_symlink", target)
                    elif stat.S_ISDIR(st.st_mode):
                        if record and report.site(child) == child:
                            report.sites[child]["directories"] += 1
                        cfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                        try:
                            yield from descend(cfd, child, depth + 1)
                        finally:
                            os.close(cfd)
                    elif stat.S_ISREG(st.st_mode):
                        yield child, st
                    else:
                        gap(child, "non_regular_file_not_read", stat.filemode(st.st_mode))
                except OSError as exc:
                    # A name returned by listdir can disappear before stat/open/readlink
                    # on a live site. Retain the gap, without treating ENOENT as a hard
                    # traversal failure. Missing roots and all other errors stay hard.
                    reason = "disappeared_during_traversal" if exc.errno == errno.ENOENT else "traversal_error"
                    gap(child, reason, exc)
        except OSError as exc:
            gap(path, "directory_read_error", exc)

    try:
        if inside(root, str(report.out)):
            return
        st = os.lstat(root)
        if stat.S_ISREG(st.st_mode):
            yield root, st
            return
        fd = open_directory(root)
        try:
            yield from descend(fd, root, 0)
        finally:
            os.close(fd)
    except OSError as exc:
        gap(root, "root_unavailable", exc)


def read_prefix(path, limit, report, file_times=None):
    handle, noatime = open_regular(path)
    with handle:
        before = os.fstat(handle.fileno())
        if file_times is not None:
            file_times["birthtime_utc"] = file_birthtime(handle.fileno())
        data = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
    if not noatime:
        report.counts["noatime_fallback_reads"] += 1
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        report.gap(path, "changed_during_read")
    partial = len(data) > limit or before.st_size > limit
    return data[:limit], before, partial


def scan_file(path, report, persistence=False, config=False):
    report.counts["files"] += 1
    site = report.site(path)
    report.sites[site]["files"] += 1
    try:
        file_times = {}
        data, st, partial = read_prefix(path, report.args.max_file_mib * MIB, report, file_times=file_times)
        row = metadata(path, st)
        row.update(file_times)
        digest = hashlib.sha256(data).hexdigest()
        row.update(site=site, bytes_read=len(data), content_complete=not partial,
                   sha256=digest if not partial else None, prefix_sha256=digest if partial else None)
        if partial:
            report.gap(path, "file_content_limit", "Only the leading bytes were inspected")
        if path.lower().endswith(ARCHIVE_EXT):
            report.gap(path, "archive_not_unpacked", "Raw bytes scanned; embedded/compressed files not inspected")
        items, php = file_rules(path, data, persistence or config)
        expected = report.vendor_baseline.get(path)
        if expected is not None:
            report.vendor_checked.add(path)
            integrity = dict(expected, path=path, actual_sha256=row["sha256"],
                             status="unverified" if partial else "match" if digest == expected["sha256"] else "mismatch")
            report.emit("vendor-integrity", integrity)
            report.counts["vendor_" + integrity["status"]] += 1
            if partial:
                report.gap(path, "vendor_baseline_unverified", "Full file content is needed for comparison")
            elif digest != expected["sha256"]:
                items.append({"severity": "HIGH", "rule": "vendor_content_mismatch",
                              "reason": "File differs from the supplied trusted release baseline; verify local patches and source. This is not proof of malware.",
                              "expected_sha256": expected["sha256"], "package": expected.get("package"),
                              "version": expected.get("version")})
        row["php_candidate"] = php
        if php:
            report.counts["php_candidates"] += 1
            report.sites[site]["php_candidates"] += 1
        if report.args.patched_at:
            row["mtime_relative_to_patch"] = "before" if st.st_mtime < parse_time(report.args.patched_at).timestamp() else "at_or_after"
        report.emit("files", row)
        if max(st.st_mtime, st.st_ctime) >= parse_time(report.args.since).timestamp():
            report.emit("recent-files", row)
        for item in items:
            report.finding(path, dict(item, sha256=row["sha256"], content_complete=not partial,
                                      mtime_utc=row["mtime_utc"], ctime_utc=row["ctime_utc"], birthtime_utc=row["birthtime_utc"]))
        if persistence or Path(path).name in PERSISTENCE_NAMES or "/.config/systemd/user/" in path:
            record = dict(row)
            # Inventory command-bearing persistence text for human review. Never copy
            # private SSH keys, passwords, or arbitrary application configuration.
            if ("/cron" in path or "/systemd/" in path or "/profile.d/" in path
                    or Path(path).name in {".bashrc", ".profile", ".bash_profile", "rc.local", "ld.so.preload"}):
                record["review_text"] = data[:65536].decode("utf-8", "replace")
                record["review_text_truncated"] = len(data) > 65536 or partial
            if Path(path).name in {"authorized_keys", "authorized_keys2"}:
                record["public_key_lines"] = data[:65536].decode("utf-8", "replace")
                record["review_text_truncated"] = len(data) > 65536 or partial
            report.emit("persistence", record)
        if config or Path(path).name in CONFIG_NAMES:
            directives = []
            for number, line in enumerate(data.splitlines(), 1):
                if re.match(rb"\s*(?:root\s|DocumentRoot\s|server_name\s|access_log\s|error_log\s|fastcgi_pass\s|listen\s*=|user\s*=|group\s*=|\[|.*session\.upload_progress\.enabled|.*auto_(?:prepend|append)_file)", line):
                    if len(directives) < 200:
                        directives.append({"line": number, "text": line[:500].decode("utf-8", "replace")})
                    else:
                        report.gap(path, "configuration_excerpt_limit")
                        break
            report.emit("configuration", dict(row, selected_directives=directives))
    except (OSError, ValueError) as exc:
        report.gap(path, "file_read_error", exc)
    report.progress("Scanning files")


def scan_log(path, report):
    report.counts["logs"] += 1
    remaining = report.args.max_total_log_mib * MIB - report.counts["log_bytes"]
    if remaining <= 0:
        report.gap(path, "total_log_budget_exhausted")
        return
    limit = min(report.args.max_log_mib * MIB, remaining)
    consumed, line_number, sample_count = 0, 0, 0
    event_counts, traffic = collections.Counter(), collections.Counter()
    first_time = last_time = None
    capped = False
    try:
        raw, noatime = open_regular(path)
        if not noatime:
            report.counts["noatime_fallback_reads"] += 1
        with raw:
            before = os.fstat(raw.fileno())
            # Stream compressed logs only; no extraction or paths from archive metadata.
            log_dates = {"mtime_utc": utc(before.st_mtime), "ctime_utc": utc(before.st_ctime),
                         "birthtime_utc": file_birthtime(raw.fileno())}
            suffix = path.lower()
            stream = (gzip.GzipFile(fileobj=raw) if suffix.endswith(".gz") else
                      bz2.BZ2File(raw) if suffix.endswith(".bz2") else
                      lzma.LZMAFile(raw) if suffix.endswith(".xz") else raw)
            try:
                while consumed < limit:
                    line = stream.readline(min(MIB, limit - consumed))
                    if not line:
                        break
                    consumed += len(line)
                    line_number += 1
                    if not line.endswith(b"\n") and len(line) == MIB:
                        report.gap(path, "log_line_split_at_1mib", line_number)
                    events, access = log_event(line)
                    for event in events:
                        event_counts[event["rule"]] += 1
                        save = sample_count < report.args.log_samples
                        report.finding(path, dict(event, line_or_chunk=line_number,
                                                  excerpt=line[:1200].decode("utf-8", "replace"),
                                                  excerpt_truncated=len(line) > 1200, **log_dates), save=save)
                        if save:
                            sample_count += 1
                    if access:
                        ip, date, hour, method, endpoint, status = access
                        first_time = date if first_time is None else min(first_time, date)
                        last_time = date if last_time is None else max(last_time, date)
                        if method == "POST" or status >= 500:
                            key = (hour, ip, method, endpoint, status)
                            if key in traffic or len(traffic) < 50000:
                                traffic[key] += 1
                            else:
                                event_counts["traffic_keys_over_limit"] += 1
                    report.progress("Scanning logs")
                if consumed >= limit and stream.read(1):
                    capped = True
                    report.gap(path, "log_content_limit", f"Read first {consumed} decompressed bytes")
            finally:
                if stream is not raw:
                    stream.close()
            after = os.fstat(raw.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            report.gap(path, "log_changed_during_read")
        if sum(v for k, v in event_counts.items() if k != "traffic_keys_over_limit") > sample_count:
            report.gap(path, "log_evidence_sample_limit", "All inspected matches counted; only first samples saved")
        if event_counts["traffic_keys_over_limit"]:
            report.gap(path, "traffic_aggregation_limit", event_counts["traffic_keys_over_limit"])
        report.emit("logs", dict(metadata(path, before), bytes_inspected=consumed,
                                  birthtime_utc=log_dates["birthtime_utc"],
                                  lines_or_chunks=line_number, content_complete=not capped,
                                  indicator_counts=dict(event_counts), first_access_time=first_time,
                                  last_access_time=last_time, evidence_samples=sample_count))
        for (hour, ip, method, endpoint, status), count in traffic.most_common():
            report.emit("traffic", {"log": path, "hour_utc": hour, "source_ip_as_logged": ip,
                                    "method": method, "endpoint": endpoint, "status": status, "count": count})
    except (OSError, EOFError, ValueError) as exc:
        report.gap(path, "log_read_error", exc)
    finally:
        report.counts["log_bytes"] += consumed


def optional_checks(args):
    return {"php_assessment": args.assess_php, "zeek_notice_files": len(set(args.zeek_notice)),
            "suricata_eve_files": len(set(args.suricata_eve))}


def php_version_assessment(version):
    """Assess upstream version evidence, never certify a particular vendor build."""
    match = re.fullmatch(r"(?:\d+:)?(\d+)\.(\d+)\.(\d+)([^\s]*)", version)
    if not match:
        return "unknown", None
    major, minor, patch = (int(value) for value in match.groups()[:3])
    suffix = match.group(4)
    if suffix and not suffix.startswith(("-", "+", "~")):
        return "unknown", None
    fixed = PHP_FIXED.get((major, minor))
    if fixed is None:
        legacy = major == 5 and 4 <= minor <= 6 or major == 7 and 0 <= minor <= 4 or major == 8 and minor <= 1
        return ("legacy_requires_vendor_verification" if legacy else "unknown"), None
    target = "{}.{}.{}".format(major, minor, fixed)
    if re.search(r"(?:dev|alpha|beta|rc)", suffix, re.I):
        return "unknown", target
    return ("below_upstream_fix" if patch < fixed else "at_or_above_upstream_fix"), target


def php_packages(data):
    """Select installed PHP runtime packages, excluding libraries/extensions and meta-packages."""
    for paragraph in data.decode("utf-8", "replace").split("\n\n"):
        fields = {}
        for line in paragraph.splitlines():
            key, separator, value = line.partition(": ")
            if separator and key in ("Package", "Version", "Status"):
                fields[key] = value
        if fields.get("Status") != "install ok installed":
            continue
        package, version = fields.get("Package", ""), fields.get("Version", "")
        if not re.fullmatch(r"(?:php(?:\d+(?:\.\d+)?(?:rc)?)-(?:cli|fpm|cgi)|libapache2-mod-php\d+(?:\.\d+)?|lsphp\d+)", package):
            continue
        role = ("fpm" if package.endswith("-fpm") else "cli" if package.endswith("-cli") else
                "cgi" if package.endswith("-cgi") else "apache" if package.startswith("libapache2") else "lsapi")
        yield package, version[:200], role


def assess_php(report):
    path = "/var/lib/dpkg/status"
    report.progress("Assessing PHP package versions", force=True)
    report.gap("PHP runtime", "php_serving_runtime_unverified",
               "Package versions do not verify site-to-pool mapping, vendor backports or worker restarts. No PHP executable was run.")
    try:
        data, _, partial = read_prefix(path, report.args.max_file_mib * MIB, report)
        if partial:
            report.gap(path, "php_inventory_content_limit", "Only complete package entries in the inspected prefix are assessed")
            data = data.rsplit(b"\n\n", 1)[0] if b"\n\n" in data else b""
        for package, version, role in php_packages(data):
            assessment, fixed = php_version_assessment(version)
            review = assessment in ("below_upstream_fix", "legacy_requires_vendor_verification")
            row = {"kind": "runtime", "source": "dpkg_status", "rule": "php_runtime_version",
                   "severity": "REVIEW" if review else "INFO", "package": package, "version": version,
                   "role": role, "assessment": assessment, "fixed_version": fixed,
                   "serving_runtime_verified": False,
                   "reason": "Installed PHP package version: " + assessment + ". Verify the vendor advisory and the actual serving workers; this is not evidence of compromise."}
            report.emit("php-runtime", dict(row, path=path, advisory=PHP_ADVISORY, advisory_date="2026-10-21"))
            report.finding(path, row)
            report.counts["php_packages_assessed"] += 1
            report.counts["php_version_" + assessment] += 1
        if not report.counts["php_packages_assessed"]:
            report.gap(path, "php_inventory_unavailable", "No recognized installed runtime packages; custom builds and containers are not assessed")
    except (OSError, ValueError) as exc:
        report.gap(path, "php_inventory_unavailable", exc)


def sensor_record(data, source):
    """Only known Corelight identifiers and explicit metadata; never copy bodies/cookies/messages."""
    if not isinstance(data, dict):
        raise ValueError("Expected an object")
    if source == "zeek":
        note = data.get("note")
        if not isinstance(note, str):
            raise ValueError("Missing notice type")
        if not note.startswith("PHP2SHELL::") or note.split("::", 1)[1] not in ZEEK_NOTICES:
            return None
        name = note.split("::", 1)[1]
        runtime = name == "Potentially_Affected_PHP_Version"
        timestamp = data.get("ts")
        if isinstance(timestamp, bool) or not isinstance(timestamp, (str, float, int)):
            raise ValueError("Missing notice timestamp")
        try:
            event_time = utc(float(timestamp))
        except (ValueError, OverflowError, OSError):
            raise ValueError("Invalid notice timestamp")
        src, dst = data.get("src") or data.get("id.orig_h"), data.get("dst") or data.get("id.resp_h")
        sport, dport = data.get("id.orig_p"), data.get("id.resp_p")
        event_id = data.get("uid")
        identifier = note
    else:
        if not isinstance(data.get("event_type"), str):
            raise ValueError("Missing EVE event type")
        if data["event_type"] != "alert":
            return None
        alert = data.get("alert")
        if not isinstance(alert, dict):
            raise ValueError("Missing EVE alert object")
        sid = alert.get("signature_id")
        if type(sid) is not int or sid not in SURICATA_RULES:
            return None
        name, identifier = SURICATA_RULES[sid], str(sid)
        runtime = sid != 3000650
        timestamp = data.get("timestamp")
        if not isinstance(timestamp, str):
            raise ValueError("Missing EVE timestamp")
        try:
            event_time = parse_time(timestamp).isoformat(timespec="seconds")
        except argparse.ArgumentTypeError:
            raise ValueError("Invalid EVE timestamp")
        src, dst = data.get("src_ip"), data.get("dest_ip")
        sport, dport = data.get("src_port"), data.get("dest_port")
        event_id = data.get("flow_id")
    row = {"kind": "runtime" if runtime else "network", "source": source,
           "sensor_rule": identifier, "event_utc": event_time, "severity": "REVIEW",
           "rule": "php_sensor_version" if runtime else "php_network_indicator",
           "reason": ("Sensor reports potentially affected PHP version evidence. Verify the actual runtime and vendor patch; banners are not proof."
                      if runtime else "Sensor reports " + name + "; suspicious traffic indicator, not proof of successful exploitation.")}
    for key, value in (("source_ip", src), ("destination_ip", dst)):
        if value not in (None, "", "-"):
            try:
                if not isinstance(value, str):
                    raise ValueError("Expected an IP address string")
                row[key] = str(ipaddress.ip_address(value))
            except ValueError:
                raise ValueError("Invalid sensor IP address")
    for key, value in (("source_port", sport), ("destination_port", dport)):
        if isinstance(value, (str, int)) and not isinstance(value, bool) and re.fullmatch(r"\d{1,5}", str(value)) and 0 <= int(value) <= 65535:
            row[key] = int(value)
    if isinstance(event_id, (str, int)) and not isinstance(event_id, bool) and re.fullmatch(r"[A-Za-z0-9_-]{1,128}", str(event_id)):
        row["sensor_event_id"] = str(event_id)
    return row


def import_sensor_log(path, source, report):
    """Bounded JSON-lines / standard tab-separated Zeek notice reader, including compressed logs."""
    report.counts["logs"] += 1
    report.counts["sensor_logs"] += 1
    limit = min(report.args.max_log_mib * MIB, report.args.max_total_log_mib * MIB - report.counts["log_bytes"])
    if limit <= 0:
        report.gap(path, "total_log_budget_exhausted")
        return
    consumed, line_number, saved, matched, invalid, oversized = 0, 0, 0, 0, 0, 0
    fields, separator_ok, discarding, capped = None, True, False, False
    try:
        raw, noatime = open_regular(path)
        if not noatime:
            report.counts["noatime_fallback_reads"] += 1
        with raw:
            before = os.fstat(raw.fileno())
            suffix = path.lower()
            stream = (gzip.GzipFile(fileobj=raw) if suffix.endswith(".gz") else
                      bz2.BZ2File(raw) if suffix.endswith(".bz2") else
                      lzma.LZMAFile(raw) if suffix.endswith(".xz") else raw)
            try:
                while consumed < limit:
                    remaining = limit - consumed
                    # One look-ahead byte distinguishes exact EOF from a truncated
                    # record. Never parse a prefix of an oversized/budget-cut row.
                    chunk = stream.readline(min(MIB + 1, remaining + 1))
                    if not chunk:
                        break
                    consumed += min(len(chunk), remaining)
                    report.progress("Importing " + source + " alerts")
                    if not discarding:
                        line_number += 1
                    if len(chunk) > remaining:
                        capped = True
                        break
                    if len(chunk) > MIB:
                        if not discarding:
                            oversized += 1
                        discarding = not chunk.endswith(b"\n")
                        continue
                    if discarding:
                        discarding = False
                        continue
                    if not chunk.strip():
                        continue
                    try:
                        text = chunk.decode("utf-8").rstrip("\r\n")
                        if source == "zeek" and text.startswith("#"):
                            if text.startswith("#separator "):
                                fields = None
                                separator_ok = text == r"#separator \x09"
                                if not separator_ok:
                                    invalid += 1
                            elif text.startswith("#fields\t"):
                                fields = text.split("\t")[1:]
                                if not separator_ok or "note" not in fields or "ts" not in fields or len(fields) > 100 or len(set(fields)) != len(fields):
                                    fields = None
                                    invalid += 1
                            continue
                        if source == "zeek" and not text.lstrip().startswith("{"):
                            values = text.split("\t")
                            if not fields or len(values) != len(fields):
                                raise ValueError("Invalid Zeek fields")
                            data = dict(zip(fields, values))
                        else:
                            data = json.loads(text)
                        row = sensor_record(data, source)
                    except (ValueError, TypeError, OverflowError, RecursionError):
                        invalid += 1
                        continue
                    report.counts["sensor_records"] += 1
                    if row is None:
                        report.counts["sensor_records_ignored"] += 1
                        continue
                    matched += 1
                    report.counts["sensor_indicators"] += 1
                    save = saved < report.args.log_samples
                    row["line_or_chunk"] = line_number
                    report.finding(path, row, save=save)
                    if save:
                        report.emit("network-alerts", dict(row, path=path))
                        saved += 1
                if capped or consumed >= limit and stream.read(1):
                    capped = True
                    report.gap(path, "log_content_limit", "Sensor log inspection reached its byte budget")
            finally:
                if stream is not raw:
                    stream.close()
            after = os.fstat(raw.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            report.gap(path, "log_changed_during_read")
        if invalid or oversized:
            report.gap(path, "sensor_records_invalid", "{} invalid records/headers; {} oversized or truncated lines skipped".format(invalid, oversized))
        if matched > saved:
            report.gap(path, "log_evidence_sample_limit", "All imported matches counted; only first samples saved")
        report.emit("logs", dict(metadata(path, before), source=source, bytes_inspected=consumed,
                                  lines_or_chunks=line_number, content_complete=not capped and not invalid and not oversized,
                                  indicators=matched, evidence_samples=saved))
    except (OSError, EOFError, ValueError) as exc:
        report.gap(path, "sensor_log_read_error", type(exc).__name__)
    finally:
        report.counts["log_bytes"] += consumed


def capture_bounded(argv, limit=8 * MIB, timeout=30):
    """Bound command output while reading, rather than after buffering all of it."""
    process = subprocess.Popen(argv, cwd="/", env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "TZ": "UTC"},
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    data = bytearray()
    reason = None
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    reason = "snapshot_timeout"
                    break
                if not selector.select(remaining):
                    reason = "snapshot_timeout"
                    break
                chunk = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    reason = "snapshot_output_limit"
                    break
        if reason:
            process.kill()
        try:
            returncode = process.wait(timeout=max(0.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            reason = "snapshot_timeout"
            process.kill()
            returncode = process.wait()
        return bytes(data[:limit]), returncode, reason
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()


def snapshot(report, name, argv):
    """Only fixed OS inspection commands; no shell, inherited PATH, or app executables."""
    output = report.out / ("snapshot-" + name + ".txt")
    try:
        # Ubuntu releases before usrmerge may keep ps/ss/systemctl in /bin.
        binary = os.path.basename(argv[0])
        candidates = [directory + "/" + binary for directory in ("/usr/bin", "/bin", "/usr/sbin", "/sbin")]
        command = next((path for path in candidates if os.path.isfile(path) and os.access(path, os.X_OK)), None)
        if command is None:
            raise FileNotFoundError("Missing system inspection command: " + binary)
        argv = [command] + argv[1:]
        data, returncode, reason = capture_bounded(argv)
        if reason:
            report.gap(name, reason, "Snapshot is partial")
        if name == "php-packages":
            data = b"\n".join(line for line in data.splitlines() if re.search(rb"php|lsphp", line, re.I)) + b"\n"
        with open(output, "xb") as handle:
            handle.write(data)
        if returncode and not reason:
            report.gap(name, "snapshot_command_failed", f"exit={returncode}; see {output.name}")
    except (OSError, subprocess.TimeoutExpired) as exc:
        report.gap(name, "snapshot_unavailable", exc)


def system_snapshot(report):
    commands = [
        ("processes", ["/usr/bin/ps", "-eo", "pid,ppid,user,lstart,etimes,args", "--forest"]),
        ("sockets", ["/usr/bin/ss", "-panetu"]),
        ("timers", ["/usr/bin/systemctl", "list-timers", "--all", "--no-pager"]),
        ("unit-files", ["/usr/bin/systemctl", "list-unit-files", "--no-pager"]),
        ("logins", ["/usr/bin/last", "-Fai", "-n", "200"]),
        ("php-packages", ["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Abbrev}\n"]),
        ("journal", ["/usr/bin/journalctl", "--since", parse_time(report.args.since).strftime("%Y-%m-%d %H:%M:%S UTC"),
                     "--no-pager", "--output=short-iso", "-n", "20000"]),
    ]
    for name, argv in commands:
        report.progress("Collecting " + name, force=True)
        snapshot(report, name, argv)
    report.gap("journal/logins", "bounded_system_snapshots", "Journal: last 20000 entries since --since; logins: last 200. Inspect older/off-host logs separately.")
    try:
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            try:
                exe = os.readlink(entry.path + "/exe")
                if re.search(r"php|apache|httpd|lshttpd|litespeed|frankenphp|nginx", exe, re.I) or exe.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")):
                    report.emit("process-executables", {"pid": int(entry.name), "executable": exe})
                    if exe.endswith(" (deleted)"):
                        report.finding(entry.path, {"severity": "REVIEW", "rule": "deleted_running_executable",
                                                   "reason": "May be an old worker after a package update, or an unlinked payload.", "executable": exe})
            except FileNotFoundError:
                pass  # Processes commonly exit while /proc is enumerated.
            except OSError as exc:
                report.gap(entry.path, "process_executable_unavailable", exc)
    except OSError as exc:
        report.gap("/proc", "process_inventory_unavailable", exc)


def existing_paths(paths):
    return [path for path in paths if os.path.lexists(path)]


def scan_targets(report, record=True):
    """Use the same scope, classification and de-duplication for both passes."""
    args = report.args
    seen = set()
    # Explicit imports take precedence over ordinary file/log classification.
    # Counting does not open them; missing/unreadable inputs are recorded on import.
    for kind, paths in (("zeek", args.zeek_notice), ("suricata", args.suricata_eve)):
        for path in paths:
            if path not in seen:
                seen.add(path)
                yield path, None, kind
    roots = [args.home] + args.extra_root
    for root in roots:
        for path, st in walk_files(root, report, record=record):
            if path in seen:
                continue
            seen.add(path)
            yield path, st, "log" if LOG_NAME.search(Path(path).name) else "file"
    if args.user_mode:
        for root in args.log_root:
            for path, st in walk_files(root, report, record=record):
                if path not in seen and (LOG_NAME.search(Path(path).name) or root == path):
                    seen.add(path)
                    yield path, st, "log"
        return
    # Scan temp locations for dropped scripts/binaries without executing them.
    for root in existing_paths(["/tmp", "/var/tmp", "/dev/shm"]):
        for path, st in walk_files(root, report, record=record):
            if path in seen:
                continue
            seen.add(path)
            yield path, st, "temp"
    persistence = ["/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly",
                   "/etc/cron.monthly", "/var/spool/cron", "/etc/systemd/system", "/etc/rc.local",
                   "/etc/ld.so.preload", "/etc/profile", "/etc/profile.d", "/etc/passwd", "/etc/group",
                   "/etc/sudoers", "/etc/sudoers.d", "/etc/ssh", "/root/.ssh/authorized_keys",
                   "/root/.ssh/authorized_keys2", "/root/.bashrc", "/root/.profile", "/root/.config/systemd/user"]
    config = ["/etc/nginx-rc", "/etc/nginx", "/etc/apache2-rc", "/etc/apache2", "/etc/php",
              "/usr/local/lsws/conf"]
    # Native RunCloud PHP configuration and logs live below /etc/phpXXrc and /RunCloud.
    for entry in os.scandir("/etc"):
        if re.fullmatch(r"php\d+rc", entry.name) and entry.is_dir(follow_symlinks=False):
            config.append(entry.path)
    for root, is_config in [(p, False) for p in existing_paths(persistence)] + [(p, True) for p in existing_paths(config)]:
        for path, st in walk_files(root, report, record=record):
            if path in seen:
                continue
            seen.add(path)
            yield path, st, "config" if is_config else "persistence"
    log_roots = existing_paths(["/var/log", "/usr/local/lsws/logs"]) + args.log_root
    packages = "/RunCloud/Packages"
    if os.path.isdir(packages):
        for entry in os.scandir(packages):
            if re.fullmatch(r"php\d+rc", entry.name) and entry.is_dir(follow_symlinks=False):
                log_roots += existing_paths([entry.path + "/var/log"])
                conf = entry.path + "/etc"
                if os.path.isdir(conf):
                    for path, st in walk_files(conf, report, record=record):
                        if path not in seen:
                            seen.add(path)
                            yield path, st, "config"
    for root in log_roots:
        for path, st in walk_files(root, report, record=record):
            if path not in seen and (LOG_NAME.search(Path(path).name) or root == path):
                seen.add(path)
                yield path, st, "log"


def run_scan(report):
    if report.args.user_mode:
        report.gap(report.args.home, "user_scope_only",
                   "Only the selected user files and explicit extra/log roots are inspected. System snapshots, global logs, persistence and other accounts are not checked.")
    else:
        system_snapshot(report)
    if report.args.assess_php:
        assess_php(report)
    if not report.args.no_precount:
        report.counting = True
        report.total_items = 0
        report.progress("Counting files", force=True)
        try:
            for _ in scan_targets(report, record=False):
                report.total_items += 1
                report.progress()
        except OSError as exc:
            # Counting is advisory; the real pass still records coverage failures.
            report.gap("precount", "precount_incomplete", exc)
            report.total_items = None
        finally:
            report.counting = False
    report.scan_started = time.monotonic()
    report.progress("Scanning files", force=True)
    for path, st, kind in scan_targets(report):
        if report.total_items is not None:
            report.total_items = max(report.total_items, report.completed_items + 1)
        phase = "Scanning logs" if kind in ("log", "zeek", "suricata") else "Scanning files"
        report.progress(phase)
        if kind in ("zeek", "suricata"):
            import_sensor_log(path, kind, report)
        elif kind == "log":
            scan_log(path, report)
        else:
            scan_file(path, report, persistence=kind == "persistence", config=kind == "config")
            if kind == "temp" and st.st_mode & 0o111:
                report.finding(path, {"severity": "REVIEW", "rule": "executable_in_temp",
                                      "reason": "Executable file in a temporary directory; verify its owner and purpose."})
        report.completed_items += 1
        report.progress(phase)
    for path in sorted(set(report.vendor_baseline) - report.vendor_checked):
        report.gap(path, "vendor_baseline_unverified", "Not compared: missing, unreadable, skipped, or outside the selected file scope")
        report.emit("vendor-integrity", dict(report.vendor_baseline[path], path=path, status="unverified", actual_sha256=None))
        report.counts["vendor_unverified"] += 1
    report.scan_complete = True
    if report.total_items is not None:
        report.total_items = report.completed_items
    report.progress("Scan complete", force=True)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--home", help="Scan all regular files below this directory (root: /home; user: account home/webapps)")
    p.add_argument("--extra-root", action="append", default=[], help="Additional real directory/file to inspect; repeatable")
    p.add_argument("--log-root", action="append", default=[], help="Additional log directory or log file; repeatable")
    p.add_argument("--since", type=parse_time, default=dt.datetime.now(UTC) - dt.timedelta(days=14),
                   help="Recent-file/journal start; signatures and retained logs are NOT date-filtered. Default: 14 days ago")
    p.add_argument("--patched-at", type=parse_time, help="Optional UTC patch time; annotates mtime only, not compromise time")
    p.add_argument("--output-parent", help="Existing directory owned by you (root: private /root; user: account home, not writable by others)")
    p.add_argument("--vendor-baseline", help="Optional private JSON manifest of trusted vendor release hashes; no downloads or application code execution")
    p.add_argument("--assess-php", action="store_true", help="Opt in: assess installed PHP runtime package versions; does not execute PHP or certify serving workers/backports")
    p.add_argument("--zeek-notice", action="append", default=[], metavar="FILE", help="Opt in: import Corelight PHP2SHELL notices from existing Zeek JSON/TSV logs; repeatable")
    p.add_argument("--suricata-eve", action="append", default=[], metavar="FILE", help="Opt in: import Corelight PHP2Shell alerts from existing Suricata EVE JSON logs; repeatable")
    p.add_argument("--no-precount", action="store_true", help="Start scanning sooner; omit file-count percentage and ETA")
    p.add_argument("--quick", action="store_true", help="Use smaller read/sample limits for a faster first pass; reduces coverage")
    p.add_argument("--notify-url", type=notification_url, help="POST a small JSON result summary to this HTTP(S) URL after the scan")
    p.add_argument("--notify-findings", action="store_true",
                   help="Include every saved finding's path, rule and review metadata in the JSON POST (requires --notify-url)")
    p.add_argument("--notify-token-file", help="Private file owned by the invoking user containing a bearer token for --notify-url")
    p.add_argument("--notify-timeout", type=notification_timeout, default=10, help="Notification deadline in seconds (1-60; default 10)")
    p.add_argument("--max-file-mib", type=bounded_int, help="Leading bytes per non-log file; default 16 MiB, or 1 with --quick")
    p.add_argument("--max-log-mib", type=bounded_int, help="Decompressed bytes per log; default 512 MiB, or 32 with --quick")
    p.add_argument("--max-total-log-mib", type=bounded_int, help="Total decompressed log budget; default 8192 MiB, or 512 with --quick")
    p.add_argument("--log-samples", type=bounded_int, help="Saved excerpts per log; default 200, or 50 with --quick; counting continues")
    actions = p.add_mutually_exclusive_group()
    actions.add_argument("--quarantine", metavar="REPORT_DIR",
                         help="No scan: choose HIGH files from a previous report (add --include-review for REVIEW) and move them into quarantine")
    actions.add_argument("--restore", action="store_true",
                         help="No scan: choose quarantined files and put them back exactly as they were")
    actions.add_argument("--purge", action="store_true",
                         help="No scan: choose quarantined files and permanently delete them")
    p.add_argument("--include-review", action="store_true",
                   help="Also list REVIEW files in the post-scan or --quarantine selection (default: HIGH only); reports, callbacks and scan exit codes always include REVIEW")
    p.add_argument("--quarantine-root", metavar="DIR",
                   help="Limit the post-scan or --quarantine file selection to this absolute directory and its children; does not change scan scope")
    p.add_argument("--quarantine-dir", default=QUARANTINE_DIR,
                   help="Root-only quarantine folder outside scanned trees (default " + QUARANTINE_DIR + ")")
    return p


def parse_options(argv=None):
    argument_parser = parser()
    args = argument_parser.parse_args(argv)
    args.user_mode = hasattr(os, "geteuid") and os.geteuid() != 0
    if args.user_mode:
        import pwd
        account_home = pwd.getpwuid(os.geteuid()).pw_dir
        args.home = args.home or os.path.join(account_home, "webapps")
        args.output_parent = args.output_parent or account_home
    else:
        args.home = args.home or "/home"
        args.output_parent = args.output_parent or "/root"
    if args.notify_token_file and not args.notify_url:
        argument_parser.error("--notify-token-file requires --notify-url")
    if args.notify_findings and not args.notify_url:
        argument_parser.error("--notify-findings requires --notify-url")
    if (args.quarantine or args.restore or args.purge) and args.notify_url:
        argument_parser.error("--notify-url applies to scans, not to --quarantine/--restore/--purge")
    if (args.quarantine or args.restore or args.purge) and (args.assess_php or args.zeek_notice or args.suricata_eve):
        argument_parser.error("Optional PHP assessment and sensor imports apply only to scans")
    if args.include_review and (args.restore or args.purge):
        argument_parser.error("--include-review applies to the post-scan or --quarantine selection, not --restore/--purge")
    if args.quarantine_root:
        if args.restore or args.purge:
            argument_parser.error("--quarantine-root applies to the post-scan or --quarantine selection, not --restore/--purge")
        if not os.path.isabs(args.quarantine_root):
            argument_parser.error("--quarantine-root must be an absolute directory path")
        args.quarantine_root = os.path.abspath(args.quarantine_root)
    args.zeek_notice = list(dict.fromkeys(os.path.abspath(path) for path in args.zeek_notice))
    args.suricata_eve = list(dict.fromkeys(os.path.abspath(path) for path in args.suricata_eve))
    if set(args.zeek_notice) & set(args.suricata_eve):
        argument_parser.error("A sensor file must be supplied as either Zeek or Suricata, not both")
    if any(inside(os.path.abspath(args.quarantine_dir), p) for p in ("/home", "/tmp", "/var/tmp", "/dev/shm")):
        argument_parser.error("--quarantine-dir must be outside scanned trees")
    limits = {"max_file_mib": (16, 1), "max_log_mib": (512, 32),
              "max_total_log_mib": (8192, 512), "log_samples": (200, 50)}
    for name, values in limits.items():
        if getattr(args, name) is None:
            setattr(args, name, values[1 if args.quick else 0])
    return args


def read_notification_token(path):
    if not path:
        return None
    handle, _ = open_regular(os.path.abspath(path))
    with handle:
        info = os.fstat(handle.fileno())
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("Notification token file must be owned by the invoking user and private (mode 0600 or 0400)")
        data = handle.read(4097)
    if len(data) > 4096:
        raise ValueError("Notification token file exceeds 4096 bytes")
    token = data.decode("ascii").strip()
    if not token or any(ord(char) < 33 or ord(char) > 126 for char in token):
        raise ValueError("Notification token must contain one nonempty ASCII token without whitespace")
    return token


def read_vendor_baseline(path):
    """A supplied manifest is a reference, never authority to widen the scan or skip rules."""
    if not path:
        return {}
    handle, _ = open_regular(os.path.abspath(path))
    with handle:
        info = os.fstat(handle.fileno())
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("Vendor baseline must be owned by the invoking user and private (0600 or 0400)")
        raw = handle.read(8 * MIB + 1)
    if len(raw) > 8 * MIB:
        raise ValueError("Vendor baseline exceeds 8 MiB")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("files"), dict):
        raise ValueError("Vendor baseline requires schema_version 1 and a files object")
    files = data["files"]
    if not files or len(files) > 50000:
        raise ValueError("Vendor baseline requires 1 to 50000 file entries")
    for name, entry in files.items():
        if (not name.startswith("/") or os.path.normpath(name) != name or "/vendor/" not in name
                or any(ord(char) < 32 for char in name) or "\\" in name):
            raise ValueError("Baseline paths must be normalized absolute Linux paths inside vendor/")
        if (not isinstance(entry, dict) or not isinstance(entry.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
            raise ValueError("Each baseline entry requires a lowercase SHA256 hash")
        for label in ("package", "version"):
            if label in entry and (not isinstance(entry[label], str) or len(entry[label]) > 200
                                   or any(ord(char) < 32 for char in entry[label])):
                raise ValueError("Baseline package/version must be short strings without control characters")
    return {name: {key: entry[key] for key in ("sha256", "package", "version") if key in entry}
            for name, entry in files.items()}


def notification_payload(args, report, started, elapsed, complete, finalized, exit_code):
    counts = report.counts if report is not None else collections.Counter()
    severities = report.severities if report is not None else collections.Counter()
    payload = {
        "schema_version": 1, "event": "runcloud-triage.finished", "scanner_version": VERSION,
        "run_id": report.out.name if report is not None else None,
        "hostname": socket.gethostname(), "started_utc": utc(started), "finished_utc": utc(time.time()),
        "duration_seconds": round(max(0, elapsed), 2),
        "scan_scope": "user" if args.user_mode else "system",
        "effective_uid": os.geteuid() if hasattr(os, "geteuid") else None,
        "status": {0: "completed", 1: "review_required", 2: "incomplete"}[exit_code],
        "exit_code": exit_code, "scan_finished": complete, "report_finalized": finalized,
        "verdict": "REVIEW_REQUIRED" if severities["HIGH"] or severities["REVIEW"] else "NO_MATCHING_INDICATORS",
        "counts": {name: counts[name] for name in ("files", "logs")},
        "indicators": {name: severities[name] for name in ("HIGH", "REVIEW", "INFO")},
        "coverage_issues": dict(report.gaps) if report is not None else {},
        "quick_mode": args.quick,
        "optional_checks": optional_checks(args),
        "limits": {name: getattr(args, name) for name in ("max_file_mib", "max_log_mib", "max_total_log_mib", "log_samples")},
    }
    if args.assess_php or args.zeek_notice or args.suricata_eve:
        payload["optional_counts"] = {name: counts[name] for name in (
            "php_packages_assessed", "sensor_logs", "sensor_records", "sensor_records_ignored", "sensor_indicators",
            "php_version_below_upstream_fix", "php_version_at_or_above_upstream_fix",
            "php_version_legacy_requires_vendor_verification", "php_version_unknown")}
    if args.notify_findings:
        findings = report.notification_findings if report is not None else []
        payload.update(findings=findings, findings_count=len(findings), findings_scope="saved_findings",
                       findings_omitted=max(0, sum(severities.values()) - len(findings)))
    return payload


class NoNotificationRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


@contextmanager
def notification_deadline(seconds):
    # Linux CLI runs on the main thread. Bound DNS/header waits as well as sockets.
    if not hasattr(signal, "setitimer"):
        yield
        return
    def expired(signum, frame):
        raise TimeoutError("Notification deadline exceeded")
    started = time.monotonic()
    previous_handler = signal.signal(signal.SIGALRM, expired)
    previous_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        if previous_timer[0]:
            signal.setitimer(signal.ITIMER_REAL, max(0.001, previous_timer[0] - (time.monotonic() - started)), previous_timer[1])


def send_notification(args, payload, token=None):
    headers = {"Content-Type": "application/json; charset=utf-8", "User-Agent": "runcloud-triage/" + VERSION}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    print("Sending completion notification...", flush=True)
    try:
        with notification_deadline(args.notify_timeout):
            request = urllib.request.Request(args.notify_url, data=json.dumps(payload, ensure_ascii=True).encode("utf-8"),
                                             headers=headers, method="POST")
            # Send only to the selected endpoint; do not inherit proxy destinations.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoNotificationRedirects())
            with opener.open(request, timeout=args.notify_timeout) as response:
                code = response.getcode()
                # Never download, display or execute the response body.
                if not 200 <= code < 300:
                    raise ValueError("Non-success response")
        print(f"Notification delivered (HTTP {code}).", flush=True)
        return True
    except urllib.error.HTTPError as exc:
        detail = "HTTP " + str(exc.code)
        exc.close()
    except (OSError, ValueError, http.client.HTTPException) as exc:
        # URLs, headers and response/error bodies can contain secrets.
        detail = type(exc).__name__
    except KeyboardInterrupt:
        detail = "cancelled"
    print("Notification delivery failed (" + detail + "). Scan exit code and local report are unchanged.", file=sys.stderr)
    return False


# Quarantine is the only code that changes files outside the report, and it runs only
# after a person picks files at a terminal. Items are <quarantine>/<id>/{content,item.json};
# actions.jsonl is an append-only log of every quarantine, restore and purge.

class FileChanged(Exception):
    pass


def interactive_terminal():
    return sys.stdin.isatty() and sys.stdout.isatty()


def private_directory(path, create=False):
    """Descriptor for a directory owned by the running (root) user with no group/other access."""
    path = os.path.abspath(path)
    if create:
        parent, name = os.path.split(path)
        dfd = open_directory(parent)
        try:
            os.mkdir(name, 0o700, dir_fd=dfd)
        except FileExistsError:
            pass
        finally:
            os.close(dfd)
    fd = open_directory(path)
    st = os.fstat(fd)
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        os.close(fd)
        raise ValueError(path + " must be owned by root with mode 0700 (or stricter)")
    return fd


def open_private_file(dir_fd, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError(name + " is not a regular file")
    return fd


def report_rows(dir_fd, name):
    """Rows of one JSONL report artifact; an absent artifact has no rows."""
    try:
        fd = open_private_file(dir_fd, name)
    except FileNotFoundError:
        return
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def write_private_json(dir_fd, name, row):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dir_fd)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=True, indent=2) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def log_action(quarantine_fd, action, item):
    fd = os.open("actions.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                 dir_fd=quarantine_fd)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(json.dumps({"utc": utc(time.time()), "action": action, "item": item["id"],
                                 "original_path": item["original_path"], "sha256": item["sha256"],
                                 "run_id": item.get("run_id")}, ensure_ascii=True) + "\n")


def remove_item(quarantine_fd, item_id):
    item_fd = os.open(item_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=quarantine_fd)
    try:
        for name in os.listdir(item_fd):
            os.unlink(name, dir_fd=item_fd)
    finally:
        os.close(item_fd)
    os.rmdir(item_id, dir_fd=quarantine_fd)


def quarantine_candidates(report_dir, high_only=False, quarantine_root=None):
    """File findings of a finished report: one entry per file, optionally HIGH only."""
    dfd = private_directory(report_dir)
    try:
        flagged = collections.OrderedDict()
        for row in report_rows(dfd, "findings.jsonl"):
            # Log evidence (rows with an excerpt) points at a log, not at a file to contain.
            if (row.get("severity") not in SEVERITY_ORDER or "excerpt" in row
                    or row.get("kind", "file") != "file" or not isinstance(row.get("path"), str)):
                continue
            if quarantine_root and not inside(os.path.abspath(row["path"]), quarantine_root):
                continue
            entry = flagged.setdefault(row["path"], {"path": row["path"], "severity": row["severity"], "rules": []})
            if SEVERITY_ORDER[row["severity"]] < SEVERITY_ORDER[entry["severity"]]:
                entry["severity"] = row["severity"]
            if row.get("rule") not in entry["rules"]:
                entry["rules"].append(row.get("rule"))
        if high_only:
            flagged = collections.OrderedDict((path, entry) for path, entry in flagged.items()
                                              if entry["severity"] == "HIGH")
        if flagged:
            # files.jsonl holds what the scan read: full hash, or prefix hash plus size for large files.
            for row in report_rows(dfd, "files.jsonl"):
                if row.get("path") in flagged:
                    flagged[row["path"]]["scanned"] = {name: row.get(name) for name in
                                                       ("sha256", "prefix_sha256", "bytes_read", "size")}
    finally:
        os.close(dfd)
    run_id = os.path.basename(os.path.abspath(report_dir))
    for entry in flagged.values():
        entry["run_id"] = run_id
    return sorted(flagged.values(), key=lambda entry: (SEVERITY_ORDER[entry["severity"]], entry["path"]))


def copy_into_item(source_fd, item_fd, prefix_bytes):
    out = os.open("content", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=item_fd)
    digest, prefix, copied = hashlib.sha256(), hashlib.sha256(), 0
    with os.fdopen(out, "wb") as handle:
        for chunk in iter(lambda: os.read(source_fd, MIB), b""):
            digest.update(chunk)
            if copied < prefix_bytes:
                prefix.update(chunk[:prefix_bytes - copied])
            copied += len(chunk)
            handle.write(chunk)
        handle.flush()
        os.fsync(handle.fileno())
    return digest.hexdigest(), prefix.hexdigest(), copied


def quarantine_file(candidate, quarantine_dir, report_dir=None):
    """Move one flagged file into the quarantine if it is still the file the scan read.

    Returns (moved, message). Raises ValueError if the quarantine folder is not private.
    """
    path = candidate["path"]
    scanned = candidate.get("scanned") or {}
    full, prefix = scanned.get("sha256"), scanned.get("prefix_sha256")
    if not (full or prefix):
        return False, path + ": not quarantined, the report has no content hash to confirm it is the same file"
    changed = path + ": not quarantined, it changed since the scan (review it and scan again)"
    parent, name = os.path.split(path)
    with ExitStack() as stack:
        qfd = private_directory(quarantine_dir, create=True)
        stack.callback(os.close, qfd)
        try:
            # Every ancestor is opened without following links, then the file itself.
            dfd = open_directory(parent)
            stack.callback(os.close, dfd)
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
            stack.callback(os.close, fd)
        except FileNotFoundError:
            return False, path + ": not quarantined, it no longer exists"
        except OSError as exc:
            return False, path + ": not quarantined, it cannot be opened without following links (" + (exc.strerror or str(exc)) + ")"
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return False, path + ": not quarantined, it is no longer a regular file"
        if not full and st.st_size != scanned.get("size"):
            return False, changed
        item_id = dt.datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + os.urandom(4).hex()
        os.mkdir(item_id, 0o700, dir_fd=qfd)
        try:
            item_fd = os.open(item_id, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=qfd)
            try:
                digest, prefix_digest, size = copy_into_item(fd, item_fd, scanned.get("bytes_read") or 0)
                if (digest != full) if full else (prefix_digest != prefix or size != scanned.get("size")):
                    raise FileChanged()
                record = {"schema_version": 1, "id": item_id, "original_path": path, "uid": st.st_uid, "gid": st.st_gid,
                          "mode": oct(stat.S_IMODE(st.st_mode)), "atime_ns": st.st_atime_ns, "mtime_ns": st.st_mtime_ns,
                          "size": size, "sha256": digest, "hard_links": st.st_nlink, "severity": candidate.get("severity"),
                          "rules": candidate.get("rules", []), "run_id": candidate.get("run_id"),
                          "quarantined_utc": utc(time.time()), "scanner_version": VERSION}
                write_private_json(item_fd, "item.json", record)
                os.fsync(item_fd)
            finally:
                os.close(item_fd)
            # Unlink only the same inode that was copied; a replacement since then is left alone.
            now = os.stat(name, dir_fd=dfd, follow_symlinks=False)
            if (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
                raise FileChanged()
            os.unlink(name, dir_fd=dfd)
        except FileChanged:
            remove_item(qfd, item_id)
            return False, changed
        except BaseException:
            try:
                remove_item(qfd, item_id)
            except OSError:
                pass
            raise
        log_action(qfd, "quarantine", record)
    message = path + ": quarantined as " + item_id
    if st.st_nlink > 1:
        others = st.st_nlink - 1
        message += f" (it has {others} other hard link{'s' if others != 1 else ''} that still point to the same content)"
    return True, message


def quarantined_items(quarantine_dir):
    """Items in the quarantine, oldest first; damaged entries are reported and skipped."""
    try:
        qfd = private_directory(quarantine_dir)
    except FileNotFoundError:
        return []
    items = []
    try:
        for name in sorted(os.listdir(qfd)):
            if not QUARANTINE_ITEM.fullmatch(name):
                continue
            try:
                item_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=qfd)
                try:
                    with os.fdopen(open_private_file(item_fd, "item.json"), "r", encoding="utf-8") as handle:
                        record = json.load(handle)
                finally:
                    os.close(item_fd)
                items.append(dict(record, id=name))
            except (OSError, ValueError) as exc:
                print("Skipping damaged quarantine entry " + name + ": " + str(exc), file=sys.stderr)
    finally:
        os.close(qfd)
    return sorted(items, key=lambda item: (item.get("quarantined_utc", ""), item.get("original_path", "")))


def restore_item(item, quarantine_dir):
    """Put a quarantined file back with its owner, mode and times; never overwrite."""
    path = item["original_path"]
    parent, name = os.path.split(path)
    with ExitStack() as stack:
        qfd = private_directory(quarantine_dir)
        stack.callback(os.close, qfd)
        item_fd = os.open(item["id"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=qfd)
        stack.callback(os.close, item_fd)
        source = open_private_file(item_fd, "content")
        stack.callback(os.close, source)
        digest = hashlib.sha256()
        for chunk in iter(lambda: os.read(source, MIB), b""):
            digest.update(chunk)
        if digest.hexdigest() != item["sha256"]:
            return False, path + ": not restored, the quarantined copy does not match its recorded hash"
        os.lseek(source, 0, os.SEEK_SET)
        try:
            dfd = open_directory(parent)
        except OSError as exc:
            return False, path + ": not restored, its folder is missing or reached through a link (" + (exc.strerror or str(exc)) + ")"
        stack.callback(os.close, dfd)
        try:
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        except FileExistsError:
            return False, path + ": not restored, a file already exists at that path"
        try:
            with os.fdopen(out, "wb") as handle:
                for chunk in iter(lambda: os.read(source, MIB), b""):
                    handle.write(chunk)
                handle.flush()
                # Owner first: chown clears set-id bits that chmod then puts back.
                os.fchown(handle.fileno(), item["uid"], item["gid"])
                os.fchmod(handle.fileno(), int(item["mode"], 8))
                os.utime(handle.fileno(), ns=(item["atime_ns"], item["mtime_ns"]))
                os.fsync(handle.fileno())
        except BaseException:
            os.unlink(name, dir_fd=dfd)
            raise
        remove_item(qfd, item["id"])
        log_action(qfd, "restore", item)
    return True, path + ": restored"


def purge_item(item, quarantine_dir):
    qfd = private_directory(quarantine_dir)
    try:
        remove_item(qfd, item["id"])
        log_action(qfd, "purge", item)
    finally:
        os.close(qfd)
    return True, item["original_path"] + ": quarantined copy permanently deleted"


def parse_selection(text, count, high=()):
    """'1 3-5', 'h' (all HIGH), 'a' (all) or blank (none) -> sorted zero-based indexes."""
    chosen = set()
    for token in re.split(r"[\s,]+", text.strip().lower()):
        if not token:
            continue
        if token in ("a", "all"):
            chosen.update(range(count))
        elif token in ("h", "high"):
            chosen.update(high)
        else:
            match = re.fullmatch(r"(\d+)(?:-(\d+))?", token)
            if not match:
                raise ValueError("Unknown choice " + repr(token) + ": use numbers, ranges, h, a or Enter")
            first, last = int(match.group(1)), int(match.group(2) or match.group(1))
            if not 1 <= first <= last <= count:
                raise ValueError(f"Choose numbers between 1 and {count}")
            chosen.update(range(first - 1, last))
    return sorted(chosen)


def choose(items, ask, describe, verb):
    for number, item in enumerate(items, 1):
        print(f"{number:4d}. {describe(item)}")
    high = [index for index, item in enumerate(items) if item.get("severity") == "HIGH"]
    while True:
        answer = ask(verb + " which? Numbers (e.g. 1 3-5), h = all HIGH, a = all, Enter = none: ")
        try:
            return [items[index] for index in parse_selection(answer, len(items), high)]
        except ValueError as exc:
            print(str(exc) + ".")


def apply_each(items, action):
    failed = 0
    for item in items:
        try:
            ok, message = action(item)
        except (OSError, ValueError) as exc:
            ok, message = False, str(exc)
        print(("  OK    " if ok else "  SKIP  ") + message, flush=True)
        failed += not ok
    return 1 if failed else 0


def confirm_and_apply(items, ask, describe, verb, question, accepted, action):
    """Shared prompt: choose, confirm, act. Enter, 'no', Ctrl+C or a closed session change nothing."""
    try:
        chosen = choose(items, ask, describe, verb)
        if chosen and accepted(ask(question.format(count=len(chosen)))):
            return apply_each(chosen, action)
    except (EOFError, KeyboardInterrupt):
        print()
    print("No files changed.", flush=True)
    return 0


def offer_quarantine(report_dir, quarantine_dir, ask=input, candidates=None, include_review=False, quarantine_root=None):
    try:
        if candidates is None:
            candidates = quarantine_candidates(report_dir, high_only=not include_review, quarantine_root=quarantine_root)
    except (OSError, ValueError) as exc:
        print("Cannot read report " + report_dir + ": " + str(exc), file=sys.stderr)
        return 2
    if quarantine_root:
        candidates = [candidate for candidate in candidates if inside(os.path.abspath(candidate["path"]), quarantine_root)]
        print("Quarantine selection limited to: " + quarantine_root)
    if not include_review:
        candidates = [candidate for candidate in candidates if candidate["severity"] == "HIGH"]
        print("Showing HIGH files only. REVIEW files remain in the report; add --include-review to list them too.")
    if not candidates:
        print("No " + ("HIGH/REVIEW" if include_review else "HIGH") + " file findings to quarantine in " + report_dir + ".")
        return 0
    print(f"\n{len(candidates)} flagged file(s). Quarantine moves a file out of its site into {quarantine_dir}, keeping an")
    print("exact copy for --restore. A site that loads the file may show errors until it is restored.")
    return confirm_and_apply(
        candidates, ask, lambda c: f"{c['severity']:<6} {c['path']}  [{', '.join(str(r) for r in c['rules'])}]",
        "Quarantine", "Quarantine {count} file(s) now? [y/N]: ", lambda answer: answer.strip().lower() in ("y", "yes"),
        lambda candidate: quarantine_file(candidate, quarantine_dir, report_dir))


def describe_item(item):
    return (f"{item.get('severity') or '?':<6} {item['original_path']}  quarantined {item.get('quarantined_utc', '?')}, "
            f"{item.get('size', 0):,} bytes")


def offer_items(quarantine_dir, ask, verb, question, accepted, action):
    try:
        items = quarantined_items(quarantine_dir)
    except (OSError, ValueError) as exc:
        print("Cannot open quarantine " + quarantine_dir + ": " + str(exc), file=sys.stderr)
        return 2
    if not items:
        print("The quarantine " + quarantine_dir + " is empty.")
        return 0
    return confirm_and_apply(items, ask, describe_item, verb, question, accepted,
                             lambda item: action(item, quarantine_dir))


def offer_restore(quarantine_dir, ask=input):
    return offer_items(quarantine_dir, ask, "Restore", "Put {count} file(s) back where they were? [y/N]: ",
                       lambda answer: answer.strip().lower() in ("y", "yes"), restore_item)


def offer_purge(quarantine_dir, ask=input):
    return offer_items(quarantine_dir, ask, "Delete",
                       "Permanently delete {count} quarantined file(s)? This cannot be undone. Type DELETE to confirm: ",
                       lambda answer: answer.strip() == "DELETE", purge_item)


def offer_after_scan(report_dir, args, ask=input):
    """After the summary and any notification: offer quarantine at a terminal, and always print the later command."""
    if args.user_mode:
        return
    try:
        candidates = quarantine_candidates(report_dir, high_only=not args.include_review, quarantine_root=args.quarantine_root)
    except (OSError, ValueError):
        return
    if not candidates:
        if args.quarantine_root:
            print("No eligible file findings inside " + args.quarantine_root + ". Other webapps are excluded.", flush=True)
            return
        if not args.include_review:
            print("No HIGH file findings to quarantine. REVIEW findings, if any, remain in the report; add --include-review to list them too.", flush=True)
        return
    command = "/usr/bin/python3 -I " + shlex.quote(os.path.abspath(__file__)) + " --quarantine " + shlex.quote(report_dir)
    if args.include_review:
        command += " --include-review"
    if args.quarantine_root:
        command += " --quarantine-root " + shlex.quote(args.quarantine_root)
    if os.path.abspath(args.quarantine_dir) != QUARANTINE_DIR:
        command += " --quarantine-dir " + shlex.quote(args.quarantine_dir)
    print(f"\n{len(candidates)} flagged file(s) can be quarantined now or later, without scanning again:\n  {command}", flush=True)
    if interactive_terminal():
        offer_quarantine(report_dir, args.quarantine_dir, ask, candidates, include_review=args.include_review,
                         quarantine_root=args.quarantine_root)


def run_quarantine_action(args, ask=input):
    if os.geteuid() != 0:
        print("Quarantine, restore and purge require root. User-account scans are read-only.", file=sys.stderr)
        return 2
    if not interactive_terminal():
        print("--quarantine, --restore and --purge change files only after you choose them: run them in an interactive terminal.",
              file=sys.stderr)
        return 2
    os.umask(0o077)
    quarantine_dir = os.path.abspath(args.quarantine_dir)
    if args.quarantine:
        return offer_quarantine(os.path.abspath(args.quarantine), quarantine_dir, ask, include_review=args.include_review,
                                quarantine_root=args.quarantine_root)
    if args.restore:
        return offer_restore(quarantine_dir, ask)
    return offer_purge(quarantine_dir, ask)


def main():
    args = parse_options()
    if not sys.platform.startswith("linux"):
        print("Run this on the Ubuntu server using /usr/bin/python3 -I.", file=sys.stderr)
        return 2
    if args.quarantine or args.restore or args.purge:
        return run_quarantine_action(args)
    try:
        notify_token = read_notification_token(args.notify_token_file)
    except (OSError, ValueError):
        print("Cannot read notification token: use a private regular file owned by the invoking user with one ASCII token (up to 4096 bytes), without symlinks.", file=sys.stderr)
        return 2
    started, started_monotonic = time.time(), time.monotonic()
    os.umask(0o077)
    for name in ("home", "output_parent"):
        setattr(args, name, os.path.abspath(getattr(args, name)))
    args.extra_root = [os.path.abspath(p) for p in args.extra_root]
    args.log_root = [os.path.abspath(p) for p in args.log_root]
    args.since = args.since.isoformat()
    args.patched_at = args.patched_at.isoformat() if args.patched_at else None
    out = None
    report = None
    complete, finalized, exit_code = False, False, 2
    try:
        baseline = read_vendor_baseline(args.vendor_baseline)
        dfd = open_directory(args.output_parent)
        try:
            st = os.fstat(dfd)
            forbidden_mode = 0o022 if args.user_mode else 0o077
            if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & forbidden_mode:
                raise ValueError("--output-parent must be owned by you and " +
                                 ("not writable by group/others" if args.user_mode else "mode 0700 (or stricter)"))
            if not args.user_mode and any(inside(args.output_parent, p) for p in [args.home, "/tmp", "/var/tmp", "/dev/shm"] + args.extra_root + args.log_root):
                raise ValueError("Output parent must be outside scanned trees")
            host = re.sub(r"[^A-Za-z0-9_.-]", "_", socket.gethostname())[:80]
            folder = "runcloud-triage-" + host + "-" + dt.datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + os.urandom(4).hex()
            os.mkdir(folder, mode=0o700, dir_fd=dfd)
            out = os.path.join(args.output_parent, folder)
        finally:
            os.close(dfd)
        report = Report(out, args)
        report.vendor_baseline = baseline
        try:
            script, _ = open_regular(os.path.abspath(__file__))
            with script:
                report.emit("scanner", {"version": VERSION, "path": os.path.abspath(__file__),
                                        "sha256": hashlib.sha256(script.read()).hexdigest()})
        except OSError as exc:
            report.gap(__file__, "scanner_hash_unavailable", exc)
        print("Writing private report to: " + out, flush=True)
        if args.user_mode:
            print("User-account scan: " + args.home + ". System-wide checks and root-only quarantine are unavailable.", flush=True)
        print("Progress measures scan attempts. HIGH/REVIEW need investigation; INFO provides context. Matches are not confirmed infections.", flush=True)
        if args.quick:
            print("Quick mode: reduced read limits; check coverage.jsonl for content not inspected.", flush=True)
        try:
            os.nice(10)
        except OSError:
            pass
        try:
            run_scan(report)
            complete = True
        except KeyboardInterrupt:
            report.gap("scan", "interrupted", "Partial report only")
        except Exception as exc:
            report.gap("scan", "unexpected_error", f"{type(exc).__name__}: {exc}")
        report.finish(complete)
        finalized = True
        if complete and not any(key in report.gaps for key in ("root_unavailable", "directory_read_error", "traversal_error", "file_read_error", "log_read_error",
                                                             "sensor_log_read_error", "sensor_records_invalid", "php_inventory_unavailable")):
            exit_code = 1 if report.severities["HIGH"] or report.severities["REVIEW"] else 0
    except (OSError, ValueError) as exc:
        if report is not None:
            report.clear_progress()
        print(f"Cannot finish triage: {exc}. Partial report: {out}", file=sys.stderr)
    except KeyboardInterrupt:
        if report is not None:
            report.clear_progress()
        print("Triage interrupted before report finalization.", file=sys.stderr)
    if args.notify_url:
        payload = notification_payload(args, report, started, time.monotonic() - started_monotonic, complete, finalized, exit_code)
        send_notification(args, payload, notify_token)
    if finalized:
        # Offering quarantine never changes the scan's exit code.
        try:
            offer_after_scan(out, args)
        except (EOFError, KeyboardInterrupt):
            print("\nNo files changed.", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
