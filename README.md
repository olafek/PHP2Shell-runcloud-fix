# RunCloud incident triage

A standalone, read-only triage script for **RunCloud on Ubuntu 18.04 and newer**, including servers running **PHP 7.4 and newer**. It runs as root, inspects sites throughout `/home`, and writes a private report for each server.

**It requires Python 3.6 or newer. It does not require, execute, upgrade, or modify PHP.** It uses only Python's standard library and does not install Python packages. By default it makes no network requests or uploads. Optional `--notify-url` sends a small JSON result summary to an endpoint you choose.

This is a first-pass investigation tool for the PHP vulnerabilities announced on 21 October 2026 and for common signs of persistent compromise. **It cannot certify that a server is clean, identify every attack, or prove that a finding was caused by PHP2Shell.** A successful attack may leave no files or retained logs. File timestamps alone cannot establish whether compromise happened before patching.

## 1. Get the scanner from GitHub

The public repository is [olafek/PHP2Shell-runcloud-fix](https://github.com/olafek/PHP2Shell-runcloud-fix). The steps below use `curl` inside your server's SSH session to download the scanner and its checksum. No Git installation, repository clone, or GitHub login is needed.

The download example uses `master` to get the latest published scanner. That branch can change between runs. To use the same scanner version on every server, replace `master` in `TRIAGE_REF` in step 3 with the same full commit hash from the repository.

## 2. Log in and check requirements

Log in as root, or become root with `sudo -i`:

```bash
ssh root@YOUR-SERVER
```

On the server:

```bash
id -u
/usr/bin/python3 --version
command -v curl
```

`id -u` must print `0`. Python must be 3.6 or newer. Ubuntu 18.04's Python 3.6 is supported; the installed PHP version does not matter to the scanner.

If Python or curl is missing, the following installs them. **This optional prerequisite step changes the server; the scanner itself does not install anything.** Old Ubuntu releases may need your existing archive/ESM repository configuration to work. Do not change repository sources just to run a scan without first reviewing that server's maintenance arrangements.

```bash
apt-get update
apt-get install --no-install-recommends python3 curl ca-certificates
```

## 3. Download inside the SSH session

Run these commands as root, one line at a time. Each command is complete on its own line. Keep the scanner outside website directories.

```bash
install -d -o root -g root -m 0700 /root/runcloud-triage
cd /root/runcloud-triage
umask 077

TRIAGE_REF='master'
TRIAGE_RAW_BASE="https://raw.githubusercontent.com/olafek/PHP2Shell-runcloud-fix/$TRIAGE_REF"

curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' "$TRIAGE_RAW_BASE/runcloud-triage.py" -o runcloud-triage.py

curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' "$TRIAGE_RAW_BASE/runcloud-triage.py.sha256" -o runcloud-triage.py.sha256

sha256sum --check runcloud-triage.py.sha256

chmod 0600 runcloud-triage.py runcloud-triage.py.sha256
```

**Continue to step 4 only if both downloads succeeded and the checksum says `OK`.** Do not pipe the remote script into a root shell. No executable bit, service installation, cron job, pip package, or PHP extension is required.

**Optional code review:** `less runcloud-triage.py` displays the source code; it does not run the scanner. Press `q` to exit and continue to step 4. You do not need to edit the file or open it in `nano`.

The checksum detects transfer/file mismatches. A checksum downloaded from the same repository is **not independent authentication** of that repository.

## 4. Run it

**Only if you want the result sent to a site:** create the token file before the first run on each server. Skip this step otherwise. If the receiving site gives you a ready-made token-file line, paste that instead. Otherwise run this, paste the site's token when it waits for input (nothing is shown), and press Enter:

```bash
read -rs NOTIFY_TOKEN && install -m 600 /dev/null /root/runcloud-triage-notify.token && printf '%s\n' "$NOTIFY_TOKEN" > /root/runcloud-triage-notify.token && unset NOTIFY_TOKEN
```

The file is root-only (`0600`) and is reused by later runs, so this is a one-time step per server unless the token changes. Then add `--notify-url 'https://your-site.example/...' --notify-token-file /root/runcloud-triage-notify.token` to the run command below; see [Optional completion callback](#optional-completion-callback).

Basic run on every server:

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py

TRIAGE_EXIT=$?

echo "Triage exit code: $TRIAGE_EXIT"
```

`-I` isolates Python from the current directory and Python environment variables. The script lowers its own CPU priority. On a busy server, you can also give its disk reads idle I/O priority if `ionice` is installed:

```bash
ionice -c3 /usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py
```

For the October incident, choose a recent-file inventory window and optionally supply **that server's actual patch/worker-restart time**:

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --since '2026-10-01T00:00:00Z' --patched-at '2026-10-21T16:00:00Z'
```

The patch time above is an **example**, not an assumed time for your servers. Omit it when unknown. All displayed file times are UTC. `+02:00` timestamps are also accepted. A bare date is interpreted as midnight UTC.

- `--since` controls the recent-file inventory and journal snapshot. Its default is 14 days ago.
- **File signatures are checked regardless of age.** Backdated or old files are not excluded.
- **All discovered retained logs are considered regardless of date**, up to the reported byte limits. This includes evidence predating the recent-file window.
- `--patched-at` labels a file's modification time as before/after the supplied time. It does not determine when an attacker gained access; `ctime` is inode-change time, not creation time.

The terminal prints the exact report directory, collects system snapshots, then counts files before scanning their contents. In an interactive SSH terminal, one progress bar updates in place as work advances, up to four times per second. Redirected/piped output uses plain lines about every 15 seconds and at phase changes. Large servers can take a long time: the scanner reads files across `/home`, including media, dependencies and old releases. Keep the SSH session open or use an existing `tmux`/`screen` session. Ctrl+C attempts to save a clearly marked partial report; a killed process or full disk may prevent finalization.

### Reading the progress bar

The initial `Counting files` phase walks directory metadata without reading file contents. It counts the same eligible files and logs the scan will visit, without following symlinks or including its own report directory. This adds a directory walk; use `--no-precount` below to skip it.

Once counting finishes, a wide terminal might show:

```text
[###-------]  31% 12,496/40,000 | ETA ~00:20:58 | Elapsed 00:09:32 | Files | Matches=123 HIGH=3 REVIEW=20 INFO=100
```

- **31%, 12,496/40,000:** finished scan attempts out of the counted total, combining non-log files and log files. Each log file counts as one item, regardless of how many entries it contains. The current item is counted as finished only when its attempt ends.
- **ETA:** approximate time remaining for file/log scanning, based on average time per finished item. It shows `estimating` until an estimate is available. File sizes, compressed logs, and disk load vary, so the estimate can increase. It excludes report finalization.
- **Elapsed:** time since this run started, including system snapshots and counting.
- **Files / Logs:** the current activity. A large log can keep the same percentage while elapsed time and match counts advance. A narrow terminal trims trailing details to prevent wrapping.
- **Matches / HIGH / REVIEW / INFO:** rule-match totals and their severity breakdown, not infected-file counts. One file can trigger several rules, and repeated log messages contribute multiple matches.

**HIGH** means prioritise source review; **REVIEW** means investigate the context; **INFO** supplies context, such as ordinary PHP fatal errors or successful SSH logins. Even HIGH matches can come from legitimate code or test fixtures. `123` matches does not mean 123 infections or attacks.

Files can appear or disappear between the two passes. The total adjusts as needed, and `100%` appears only when file/log scanning ends; `Writing report` follows. Finished attempts include read failures, partial reads, and logs skipped after the total log byte budget is reached. **100% is not a guarantee of complete coverage**: check `coverage.jsonl`. Indicator counts continue after the per-log evidence sample limit, so they can exceed the number of entries saved in `findings.jsonl`.

Older versions display `Scanning files: 12456 files, 40 logs, 123 indicators` instead: those are cumulative scan attempts and rule matches, with no percentage or ETA. A scan already running keeps its original display. Let it finish, then read `summary.txt`, `findings.jsonl`, and `coverage.jsonl`, where present.

### Speed options

The default scan keeps the original read limits and includes counting for the progress bar. Choose an alternative when needed:

**Faster startup with the same scan scope and read limits:** skip the counting pass. The status line still updates in place and shows finished attempts, elapsed time, and matches, but no percentage or ETA.

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --no-precount
```

**Quick first pass with a progress bar:** use smaller read limits. It still visits the same file paths, but may miss indicators beyond the inspected prefixes or log budget. Review the reported coverage gaps; use the default or larger limits for a fuller investigation.

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --quick
```

| Limit | Default | `--quick` |
| --- | --- | --- |
| Leading content per non-log file | 16 MiB | 1 MiB |
| Decompressed content per log file | 512 MiB | 32 MiB |
| Total decompressed log content | 8 GiB | 512 MiB |
| Saved evidence excerpts per log | 200 | 50 |

**Combine both speed options:** use the quick limits and skip counting.

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --quick --no-precount
```

Explicit limits override the quick defaults regardless of argument order. For example, keep the quick preset but allow up to 128 MiB per log:

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --quick --max-log-mib 128
```

You can also set `--max-file-mib`, `--max-log-mib`, `--max-total-log-mib`, and `--log-samples` individually. Reducing `--log-samples` saves report output; it does not stop match counting within the inspected content. Quick mode helps most when large files/logs dominate; it still traverses all configured paths, so there is no fixed runtime guarantee. `ionice -c3`, shown above, reduces disk priority to limit server impact and can make a scan slower.

### Optional completion callback

Use `--notify-url` to notify your own project when a run ends. This is an **HTTP POST with JSON**, not an ICMP ping or a GET request. It is disabled unless you supply a URL.

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --notify-url 'https://your-project.example/api/triage-results'
```

The callback contains the hostname, run ID, timing, scan outcome, file/log counts, severity totals, coverage-gap counts, and effective read limits. It does not send application file paths, log excerpts, findings, credentials, or report attachments. Use HTTPS for remote endpoints; HTTP is available for local/private testing.

For an authenticated endpoint, create a root-owned, mode `0600` or `0400` regular file containing one bearer token, for example `/root/runcloud-triage-notify.token` (the token step at the start of step 4 does this). Keep it outside scanned directories. Symlinks, empty tokens, internal whitespace, and files larger than 4096 bytes are rejected. A trailing newline is accepted.

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --notify-url 'https://your-project.example/api/triage-results' --notify-token-file /root/runcloud-triage-notify.token --notify-timeout 15
```

This adds `Authorization: Bearer TOKEN` to the request. Avoid credentials in URLs: command-line URLs can appear in process listings and local snapshots. Callback options are redacted in `summary.jsonl`; token contents are never stored there. Notification flags can be combined with `--quick`, `--no-precount`, or custom scan limits.

An example payload for a completed scan with indicators to review:

```json
{
  "schema_version": 1,
  "event": "runcloud-triage.finished",
  "scanner_version": "1.2.0",
  "run_id": "runcloud-triage-web-01-20261022T120000Z-a1b2c3d4",
  "hostname": "web-01",
  "started_utc": "2026-10-22T12:00:00+00:00",
  "finished_utc": "2026-10-22T12:10:00+00:00",
  "duration_seconds": 600.0,
  "status": "review_required",
  "exit_code": 1,
  "scan_finished": true,
  "report_finalized": true,
  "verdict": "REVIEW_REQUIRED",
  "counts": {"files": 12456, "logs": 40},
  "indicators": {"HIGH": 3, "REVIEW": 20, "INFO": 100},
  "coverage_issues": {"file_content_limit": 7, "log_content_limit": 2},
  "quick_mode": false,
  "limits": {"max_file_mib": 16, "max_log_mib": 512, "max_total_log_mib": 8192, "log_samples": 200}
}
```

In your project, accept a POST with `Content-Type: application/json; charset=utf-8`, validate the bearer token if configured, store the result, and return a **2xx** response promptly. `hostname` and `run_id` identify the server and local report folder. The response body is ignored.

| `status` | Meaning / suggested action |
| --- | --- |
| `completed` | Exit 0: no HIGH/REVIEW indicators or hard read failures. Review coverage gaps; this is not a clean bill of health. |
| `review_required` | Exit 1: at least one HIGH/REVIEW indicator. Queue an alert for investigation. |
| `incomplete` | Exit 2: interrupted run, initialization/finalization failure, or hard read/traversal failure. Alert that the scan needs attention. |

Check `status`, `scan_finished`, and `report_finalized` together. For example, traversal can finish with read failures (`scan_finished: true`, `status: incomplete`). An initialization failure may have `run_id: null` and no report. A `NO_MATCHING_INDICATORS` verdict on an incomplete run does not establish safety.

The scanner makes **one delivery attempt**, normally after report finalization, including runs with no indicators. It also attempts a failure callback for initialization/finalization errors or a handled Ctrl+C. Invalid arguments, an unreadable token file, failure of the Linux/root prerequisite, a forced kill, or a server outage can prevent any callback.

`--notify-timeout` sets a 1–60 second delivery deadline (default **10 seconds**) on Linux. Redirects are refused, environment proxy settings are ignored, and HTTPS certificate verification remains enabled. A delivery failure prints a separate message without changing the scan's exit code or local report. There are no automatic retries; a lost response can mean the receiver accepted a request even though delivery is reported as failed. Treat this as a best-effort completion notification, not a guaranteed heartbeat.

## 5. Understand the report

Each run creates a unique directory such as:

```text
/root/runcloud-triage-SERVER-20261022T120000Z-a1b2c3d4/
```

The directory is mode `0700`; report files are private to root. Existing reports are not overwritten. Copy the exact path printed by the scanner:

```bash
TRIAGE_REPORT='/root/runcloud-triage-SERVER-20261022T120000Z-a1b2c3d4'
less "$TRIAGE_REPORT/summary.txt"
less "$TRIAGE_REPORT/findings.jsonl"
less "$TRIAGE_REPORT/coverage.jsonl"
```

Files are created only when there are records for them, so some files may be absent. JSONL means one JSON object per line; strings are escaped so filenames or log content cannot create fake report lines.

| File                        | What to review                                                                                                                                                                                            |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `summary.txt`               | Completion status, overall counts, site/scope counts, coverage issues and first 40 non-INFO indicators.                                                                                                   |
| `summary.jsonl`             | The same summary in machine-readable form, including options and times.                                                                                                                                   |
| `findings.jsonl`            | File rule matches and sampled log evidence, with severity and explanation. File matches include line numbers where available and hashes of fully read files.                                              |
| `coverage.jsonl`            | Unreadable files, failed commands, limits, archives not unpacked, and other incomplete checks. Read this even when no suspicious indicators were found.                                                   |
| `files.jsonl`               | Metadata for inspected non-log files: path, owner IDs, mode, size, modification/change time, PHP-candidate status and hash. Partial reads have a labelled prefix hash, never a misleading full-file hash. |
| `recent-files.jsonl`        | Files with modification or inode-change time since `--since`. Deployments, updates and cache activity normally produce many entries.                                                                      |
| `logs.jsonl`                | Logs inspected, decompressed bytes read, indicator counts, sampled-evidence counts, access-log time range when parseable, and completeness.                                                               |
| `traffic.jsonl`             | POST requests and 5xx responses grouped by UTC hour, logged client IP, method, endpoint and status. Query strings are omitted from aggregation keys.                                                      |
| `persistence.jsonl`         | Cron, local systemd configuration, authorized keys and selected startup-file inventories. Command-bearing text and public SSH-key entries are included for manual review.                                 |
| `configuration.jsonl`       | Configuration metadata and selected web-root, FPM/socket, logging and PHP directives. This is an inventory, not a complete effective-configuration parser.                                                |
| `symlinks.jsonl`            | Links and their targets. Links are not followed; inspect external targets separately.                                                                                                                     |
| `process-executables.jsonl` | Observed web-process executable paths and temporary-location executables from `/proc`.                                                                                                                    |
| `snapshot-*.txt`            | Current processes, sockets, timers, unit files, installed PHP packages, recent SSH logins and a bounded journal snapshot. Review these manually.                                                          |
| `scanner.jsonl`             | Scanner version and its own SHA-256.                                                                                                                                                                      |
| `SHA256SUMS`                | Checksums for completed report artifacts, useful after transfer. They are not a forensic signature from a trusted third party.                                                                            |

### Severities and verdicts

- **HIGH:** prioritise source review. Examples include request data passed directly to an execution function or encoded content passed to `eval`. Test fixtures, documentation and legitimate loaders can match; this is not a confirmed compromise verdict.
- **REVIEW:** investigate context. Examples include PHP in uploads, automatic includes, memory failures, crashed workers or a running deleted executable. Security plugins, normal application failures and package upgrades can explain some matches.
- **INFO:** supporting context, including ordinary fatal errors and successful SSH logins. These are still useful when correlating a timeline.

`REVIEW_REQUIRED` means at least one HIGH or REVIEW indicator was counted. `NO_MATCHING_INDICATORS` means these rules found none; it does **not** mean “safe” or “never attacked.” Always check `scan_finished` and coverage separately.

Log evidence excerpts are sampled per file to keep reports manageable. Counts continue after that sample limit, so summary indicator totals can exceed the number of saved findings. Log excerpts and process/cron text can contain credentials, personal data or tokens. Keep reports private; redact them before sharing.

### Exit codes

| Code | Meaning                                                                                                                                                             |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`  | Scan finished without a hard read/traversal failure and no HIGH/REVIEW indicators were counted. Coverage limits may still exist.                                    |
| `1`  | Scan finished and HIGH/REVIEW indicators were counted. This is a review signal, not a scanner crash.                                                                |
| `2`  | Invalid invocation, initialization failure, interrupted/unexpected failure, or a file/log/traversal read failure. Any available report is partial and needs review. |

Missing inspection commands, byte/sample limits, unexpanded archives and external symlink targets are recorded in coverage; **exit code alone is never a coverage guarantee**.

### What to investigate first

1. Check whether the scan finished and identify important gaps.
2. Inspect HIGH findings without running the affected PHP. Compare hashes/source against a trusted deployment or known-good backup obtained independently of the suspect server.
3. Review unexpected PHP in uploads, recent changes, cron commands, systemd overrides and unfamiliar SSH keys.
4. Correlate error spikes with `traffic.jsonl`, original access/error logs and off-host CDN/WAF logs. Normal access logs often lack request bodies and Content-Type. POST volume, OOM errors and 5xx responses are not proof of this exploit or of a successful attack. Logged IPs may be proxies; do not assume they identify an attacker.
5. Review live processes and connections. These are a point-in-time snapshot and cannot show a connection that has already ended.

If you find credible compromise, preserve reports and original logs and isolate the affected workload as appropriate. Do not simply delete a flagged file and declare the server clean. Investigate the scope, restore/rebuild from trusted sources as warranted, and rotate affected credentials from a trusted machine. Plan application encryption-key changes carefully: blindly replacing a Laravel `APP_KEY` can make existing encrypted data unreadable.

## 6. Coverage and larger/custom servers

The scanner walks **all regular files under `/home`**, not just `/home/runcloud` or one selected site. It groups conventional `/home/USER/webapps/APP` paths by app, and keeps nonstandard paths in an `outside-webapps` scope. It does not exclude `vendor`, `node_modules`, caches, uploads, hidden files or old releases.

It also inspects `/tmp`, `/var/tmp`, `/dev/shm`, common cron/startup/local-systemd/SSH locations, RunCloud and standard Nginx/Apache/PHP configuration, `/var/log`, and common RunCloud PHP/OpenLiteSpeed log locations where present. Plain logs and gzip/bzip2/xz rotations are supported. Journal binary files are not treated as text; `journalctl` supplies a separate snapshot of up to 20,000 recent entries. Login snapshots show at most 200 records. Each inspection command is limited to 30 seconds and 8 MiB of output, with truncation/timeouts reported.

Default limits are **16 MiB per non-log file**, **512 MiB of decompressed content per log**, **8 GiB of decompressed log content in total**, and **200 saved indicator excerpts per log**. Content limits inspect the beginning of a file and record the gap; they do not claim to inspect the remainder. Traversal order is not chronological. Large old logs can consume the log budget before other files are reached. Review coverage and rerun with larger limits or targeted log paths when needed:

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --max-file-mib 64 --max-log-mib 2048 --max-total-log-mib 32768 --log-samples 1000
```

Symlinks are recorded rather than followed, and devices/FIFOs/sockets are never read as files. A release symlink whose real target is under `/home` is covered by the normal traversal of that target. Add actual external deployment directories or custom log paths explicitly:

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --extra-root /srv/myapp/releases --log-root /srv/myapp/logs
```

`--extra-root` and `--log-root` can be repeated. Use actual paths without symlink components. Log directories are searched for common log filenames; pass a custom-named log file directly with `--log-root` if necessary. Compressed application archives/backups are not unpacked.

Containers and custom RunCloud stacks may store files, logs, or effective configuration outside these paths or inside a different namespace. Host-visible `/home` content is scanned, but the script **does not enter containers**, query the RunCloud API, or assert that every configured domain/runtime was discovered. Inventory such locations and provide their host-visible paths or investigate inside the appropriate environment separately.

No database audit, memory capture, rootkit detection, independent file-baseline comparison, or complete historical authentication/persistence audit is performed. The script intentionally does not run Git, Artisan, Composer, WP-CLI, PHP binaries or application commands as root. Local tools and logs can be misleading if the host itself is compromised.

The script writes only its new report directory. It does not alter website content, settings, users, services or jobs, delete/quarantine files, or restart workers. As with other live triage, directory/file reads can affect access times, commands generate normal audit records, and concurrent changes mean this is not an atomic forensic image. It requests no-atime file reads where supported and reports fallback counts.

## 7. Retrieve and retain reports

From your trusted workstation, copy the report directory printed by the run:

```bash
scp -r root@YOUR-SERVER:/root/runcloud-triage-SERVER-20261022T120000Z-a1b2c3d4 ./
```

On a Linux/macOS workstation, enter the downloaded directory and verify it:

```bash
sha256sum --check SHA256SUMS
```

On macOS, use `shasum -a 256 --check SHA256SUMS` if `sha256sum` is unavailable. Preserve the original report and relevant original logs in private storage. Keep the hostname, scanner checksum, collection time and actual patch/restart time with each server's evidence.

## PHP advisory and patch status

The scanner works on older PHP and Ubuntu versions to support investigation. Its ability to run there does not establish that those versions are supported or patched.

The upstream fixes announced on 21 October 2026 are PHP **8.2.35, 8.3.36, 8.4.27 and 8.5.12**. Merely moving to “PHP 8.2” is not enough. RunCloud said it would not publish patched builds for PHP 8.1 and older. PHP 8.2 itself reaches upstream end of life on 31 December 2026; account for that when planning the migration.

This tool inventories installed packages and observed process paths but deliberately **does not certify patch status**. Verify which runtime each site actually serves through, vendor backport information where applicable, and whether all relevant workers were restarted. CLI PHP versions can differ from serving FPM/LSAPI versions.

Sources:

- [PHP security announcement and release details](https://www.php.net/archive/2026.php#2026-10-21-5)
- [PHP: RCE via OOM corruption, CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [PHP: RCE via stale global state, CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [RunCloud's response and older-version policy](https://community.runcloud.io/t/critical-php-vulnerabilities-cve-2026-109618-cve-2026-109619-what-runcloud-is-doing/4814)
- [RunCloud Nginx paths](https://runcloud.io/docs/cheat-sheet-nginx)
- [Laracraft triage article](https://laracraft.tech/en/blog/php2shell-were-you-hit-a-read-only-triage-script-for-your-server)

The Laracraft article is a useful triage starting point. This scanner is a separate implementation focused on whole-`/home` coverage, private per-server reports, age-independent file checks, RunCloud paths, and explicit scan limitations. It does not incorporate or claim to audit the linked Bash script.

## Development checks

No development dependencies are needed:

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile runcloud-triage.py
```

Linux filesystem fixtures test symlink/FIFO handling, age-independent coverage, report generation, compressed logs, limits and read failures. Detection and timestamp tests can also run on Windows; Linux-specific tests are skipped there. Python 3.6 grammar is checked on interpreters that provide AST grammar selection. Testing on a newer interpreter does not substitute for an end-to-end trial on your oldest server image.

Validation for this version: **45 tests passed on Linux with Python 3.10.12**, including isolated command-line runs exercising exit codes 0/1/2, report permissions, quick mode, and callbacks for completed/partial/interrupted runs; counting and ETA; and notification authentication, redirects, deadlines, payload filtering, and failure handling. Notification transport tests use a local HTTP receiver and do not contact external services. Python 3.6 syntax and the APIs used for older-Ubuntu compatibility were checked; an actual Ubuntu 18.04/Python 3.6 runtime was not available for execution here.

### Publishing updates

Keep `runcloud-triage.py`, `runcloud-triage.py.sha256`, `README.md`, and `.gitattributes` in the repository. Tests can also be published; they are not required on the servers. Do not publish server reports, logs, credentials, or the contents of `/root`.

Whenever the script changes, regenerate its checksum before publishing:

```bash
sha256sum runcloud-triage.py > runcloud-triage.py.sha256
```

On Windows PowerShell, the equivalent is:

```powershell
$digest = (Get-FileHash -Algorithm SHA256 -LiteralPath ./runcloud-triage.py).Hash.ToLower()
"$digest  runcloud-triage.py" | Set-Content -Encoding ascii ./runcloud-triage.py.sha256
```

Preserve the script's bytes when uploading; line-ending changes change its checksum. `.gitattributes` keeps consistent LF line endings across workstations. Publish scanner and checksum updates together. For pinned deployments, select a commit containing both matching files.
