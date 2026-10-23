# RunCloud incident triage

A standalone, read-only triage script for **RunCloud on Ubuntu 18.04 and newer**, including servers running **PHP 7.4 and newer**. As root it inspects sites throughout `/home`; as an ordinary RunCloud user it inspects that account's `webapps` directory. Both modes write a private report. The scan itself never changes files: flagged files are moved into a root-only quarantine only when you choose them at the terminal, and can be restored (see [step 6](#6-quarantine-restore-or-delete-flagged-files)).

**It requires Python 3.6 or newer. It does not require, execute, upgrade, or modify PHP.** It uses only Python's standard library and does not install Python packages. By default it makes no network requests or uploads. Optional `--notify-url` sends a small JSON result summary to an endpoint you choose; add `--notify-findings` to include every saved finding's path and review metadata.

This is a first-pass investigation tool for the PHP vulnerabilities announced on 21 October 2026 and for common signs of persistent compromise. **It cannot certify that a server is clean, identify every attack, or prove that a finding was caused by PHP2Shell.** A successful attack may leave no files or retained logs. File timestamps alone cannot establish whether compromise happened before patching.

## 1. Get the scanner from GitHub

The public repository is [olafek/PHP2Shell-runcloud-fix](https://github.com/olafek/PHP2Shell-runcloud-fix). The steps below use `curl` inside your server's SSH session to download the scanner and its checksum. No Git installation, repository clone, or GitHub login is needed.

The download example uses `master` to get the latest published scanner. That branch can change between runs. To use the same scanner version on every server, replace `master` in `TRIAGE_REF` in step 3 with the same full commit hash from the repository.

## 2. Log in and check requirements

For a server-wide scan, log in as root, or become root with `sudo -i`. For an account-only scan without sudo, use [Run as a RunCloud user](#run-as-a-runcloud-user-without-root) instead.

```bash
ssh root@YOUR-SERVER
```

On the server:

```bash
id -u
/usr/bin/python3 --version
command -v curl
```

`id -u` must print `0`. Python must be 3.6 or newer, including Ubuntu 18.04's Python 3.6 and Ubuntu 20.04's Python 3.8. Use the system `/usr/bin/python3`; no Python or PHP upgrade is required. The installed PHP version does not matter to the scanner.

If Python or curl is missing, the following installs them. **This optional prerequisite step changes the server; the scanner itself does not install anything.** Old Ubuntu releases may need your existing archive/ESM repository configuration to work. Do not change repository sources just to run a scan without first reviewing that server's maintenance arrangements.

```bash
apt-get update
apt-get install --no-install-recommends python3 curl ca-certificates
```

## 3. Download inside the SSH session

Paste this entire block as root into a fresh SSH prompt, then press Enter. It works in Bash and `/bin/sh` on Ubuntu 18.04, 20.04 and newer. Each step runs only if the preceding step succeeds. Keep the scanner outside website directories.

```bash
(
    umask 077 &&
    install -d -o root -g root -m 0700 /root/runcloud-triage &&
    cd /root/runcloud-triage &&
    TRIAGE_REF='master' &&
    TRIAGE_RAW_BASE="https://raw.githubusercontent.com/olafek/PHP2Shell-runcloud-fix/$TRIAGE_REF" &&
    curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' "$TRIAGE_RAW_BASE/runcloud-triage.py" -o runcloud-triage.py &&
    curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' "$TRIAGE_RAW_BASE/runcloud-triage.py.sha256" -o runcloud-triage.py.sha256 &&
    sha256sum --check runcloud-triage.py.sha256 &&
    chmod 0600 runcloud-triage.py runcloud-triage.py.sha256 &&
    grep -m1 '^VERSION' runcloud-triage.py
);
```

The parentheses keep `umask` and `cd` inside the block, so afterwards your prompt is back in the folder you started from. Later commands therefore use full paths such as `/root/runcloud-triage/runcloud-triage.py`.

**Continue to step 4 only if both downloads succeeded, the checksum says `OK` and the last line shows the expected `VERSION`.** Do not pipe the remote script into a root shell. No executable bit, service installation, cron job, pip package, or PHP extension is required.

**Optional code review:** `less /root/runcloud-triage/runcloud-triage.py` displays the source code; it does not run the scanner. Press `q` to exit and continue to step 4. You do not need to edit the file or open it in `nano`.

The checksum detects transfer/file mismatches. A checksum downloaded from the same repository is **not independent authentication** of that repository.

## 4. Run it

**Only if you want the result sent to a site:** create the token file before the first run on each server. Skip this step otherwise. If the receiving site gives you a ready-made token-file line, paste that instead. Run each step at a fresh prompt; do not append it to an unexecuted command. Otherwise run this, paste the site's token when it waits for input (nothing is shown), and press Enter. This explicitly starts Bash for its hidden-input `read` option, so it also works when your login shell is `/bin/sh`:

```bash
bash -c 'read -r -s -p "Server Scan Token: " NOTIFY_TOKEN && printf "\n" && install -m 600 /dev/null /root/runcloud-triage-notify.token && printf "%s\n" "$NOTIFY_TOKEN" > /root/runcloud-triage-notify.token';
```

The file is root-only (`0600`) and is reused by later runs, so this is a one-time step per server unless the token changes. Then add `--notify-url 'https://your-site.example/...' --notify-token-file /root/runcloud-triage-notify.token` to the run command below; see [Optional completion callback](#optional-completion-callback).

**If you see `chmod: invalid option -- 'm'`:** two commands were joined without a separator, such as `chmod ... install -m 600 ...`. This is a shell command boundary error on any Ubuntu version. Press Ctrl+C to clear the current input, then run the download and token steps separately. To intentionally join commands, use `&&` between them; a space is not a separator. Keep the final `;` when copying the setup commands above.

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

The terminal prints the exact report directory, collects system snapshots, then counts files before scanning their contents. In an interactive SSH terminal, one progress bar updates in place as work advances, up to four times per second. Redirected/piped output uses plain lines about every 15 seconds and at phase changes. Large servers can take a long time: the scanner reads files across `/home`, including media, dependencies and old releases. For a foreground run, keep the SSH session open or use an existing `tmux`/`screen` session. Use the background option below to let a scan finish after disconnecting. Ctrl+C attempts to save a clearly marked partial report; a killed process or full disk may prevent finalization.

### Run in the background after SSH disconnects

Choose this **instead of the foreground run** when you want to close SSH or protect against an accidental disconnect. It runs one scan to completion, using [GNU `nohup`](https://www.gnu.org/s/coreutils/manual/html_node/nohup-invocation.html) and the standard Ubuntu shell tools available on 18.04 and newer. It does not repeat scans or restart after a server reboot.

Paste the whole block as root:

```bash
(
    umask 077 &&
    RUN_DIR=$(mktemp -d /root/runcloud-background.XXXXXX) &&
    {
        nohup /bin/sh -c 'run_dir=$1; shift; "$@"; result=$?; printf "%s\n" "$result" > "$run_dir/exit-code"; exit "$result"' sh "$RUN_DIR" /usr/bin/python3 -u -I /root/runcloud-triage/runcloud-triage.py < /dev/null > "$RUN_DIR/scan.log" 2>&1 &
        printf '%s\n' "$!" > "$RUN_DIR/pid";
        printf 'Background job: %s\nWatch: tail -f %s/scan.log\nExit code: cat %s/exit-code\n' "$RUN_DIR" "$RUN_DIR" "$RUN_DIR";
    }
);
```

For a callback, add your existing `--notify-url`, `--notify-token-file`, `--notify-findings` and other scan options **after `runcloud-triage.py` and before `< /dev/null`**. Streambrain's Server Scans page provides a background command with its callback options already included.

The launch command returns immediately and prints a unique folder such as `/root/runcloud-background.a1B2c3`. That folder is mode `0700`; its log, launcher PID and eventual exit-code file are mode `0600`. Save the printed path. The first lines of `scan.log` show the separate private report directory, or an error if the scanner could not start. A successful launch alone does not mean the scan succeeded.

**Watch progress and ETA after reconnecting:** log in as root and paste this command. It prints the last 30 log lines, then follows new progress updates from the most recently updated background-run folder. It prints the selected folder so you can confirm which run you are watching:

```bash
RUN_DIR=$(ls -1dt /root/runcloud-background.*/ 2>/dev/null | head -n 1); if [ -n "$RUN_DIR" ]; then printf 'Watching %s\n' "$RUN_DIR"; tail -n 30 -f "$RUN_DIR/scan.log"; else printf 'No background scan folders found.\n'; fi;
```

The log includes percentage, estimated time remaining (`ETA`), elapsed time, file/log phase and match counts. Progress normally updates about every 15 seconds during active processing; it can pause during an individual operation. ETA becomes available after the initial counting phase and some items have been scanned, and can change as the workload changes. Runs started with `--no-precount` show counts and elapsed time without an ETA.

**Ctrl+C stops watching the log; the background scan keeps running.** If several runs exist, an older run finishing can update its folder's timestamp. To watch a specific run, use the folder printed by its launch command instead. Replace `a1B2c3` below with that run's folder:

```bash
tail -n 30 -f /root/runcloud-background.a1B2c3/scan.log
```

Check the saved result after it finishes:

```bash
cat /root/runcloud-background.a1B2c3/exit-code
```

`0` means no matching HIGH/REVIEW indicators, `1` means review is required, and `2` means incomplete/failed; review the report and coverage gaps in every case. Other codes can indicate a launch failure. If `exit-code` is absent, the job may still be running or may have been interrupted; check its log and `ps -p "$(cat /root/runcloud-background.a1B2c3/pid)" -o pid,etime,args`. The PID identifies the waiting launcher and can be reused after it exits.

The configured completion callback still runs. Background scans have no interactive terminal and cannot prompt to quarantine files. Review the report after completion, then use `--quarantine REPORT_DIR` in a new interactive SSH session if needed. Do not start another scan just because the original SSH session closed.

**Reopen the quarantine prompt after a root background scan:** wait until `exit-code` appears, reconnect as root and find the report path in that run's log (replace `a1B2c3` with your saved background folder):

```bash
grep -m1 '^Writing private report to:' /root/runcloud-background.a1B2c3/scan.log
```

Use the printed **report** directory, not the background-log folder:

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --quarantine /root/runcloud-triage-SERVER-20261022T120000Z-a1b2c3d4
```

This reads the saved findings and opens the interactive selection/confirmation prompt without rescanning. Nothing moves until you choose files and confirm. No candidates means there is nothing to select. Review dependency files against their release before quarantining them.

Add `--high-only` to the command above to list only HIGH files. This also works with reports from earlier scanner versions; use scanner 1.7.1+ to open them.

### Run as a RunCloud user without root

Scanner **1.6.0+** also runs as an ordinary RunCloud SSH user. Use the same script; no sudo or separate edition is needed. Log in as the account that owns the websites. Check `/usr/bin/python3 --version` (3.6+) and `command -v curl`; ask the server administrator to install missing prerequisites.

Download into your home directory, outside `webapps`:

```bash
(
    umask 077 &&
    install -d -m 0700 "$HOME/runcloud-triage" &&
    cd "$HOME/runcloud-triage" &&
    TRIAGE_REF='master' &&
    TRIAGE_RAW_BASE="https://raw.githubusercontent.com/olafek/PHP2Shell-runcloud-fix/$TRIAGE_REF" &&
    curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' "$TRIAGE_RAW_BASE/runcloud-triage.py" -o runcloud-triage.py &&
    curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' "$TRIAGE_RAW_BASE/runcloud-triage.py.sha256" -o runcloud-triage.py.sha256 &&
    sha256sum --check runcloud-triage.py.sha256 &&
    chmod 0600 runcloud-triage.py runcloud-triage.py.sha256 &&
    grep -m1 '^VERSION' runcloud-triage.py
);
```

Continue only after the checksum says `OK` and the version is at least 1.6.0. Run in SSH:

```bash
/usr/bin/python3 -I "$HOME/runcloud-triage/runcloud-triage.py"
```

The default scan root is **the invoking account's home directory from the system account database, plus `/webapps`**. Reports go in that account's home, inside a new `0700` folder with `0600` files. Your existing home must belong to you and must not be writable by group or others; `0755` is acceptable. `--home /actual/path` selects another real directory if your layout differs. `--output-parent /private/path` selects an existing report parent owned by you; keep reports outside website directories. The active report is excluded if you explicitly scan a parent containing it; older reports are not automatically excluded.

This scans accessible website files, including `vendor/`, and application logs. `--extra-root` and `--log-root` can add explicit accessible paths. It **does not inspect other accounts by default, global temporary directories, system persistence, global logs or system/process snapshots**. Every user scan records `scan_scope: "user"`, its effective UID and a `user_scope_only` coverage limitation. Permission failures are reported; exit `0` only describes the selected scope. Root is still needed for server-wide investigation and all quarantine/restore/purge actions. The scanner never quarantines automatically.

Optional callback token, owned by this user:

```bash
bash -c 'read -r -s -p "Server Scan Token: " NOTIFY_TOKEN && printf "\n" && install -m 600 /dev/null "$HOME/runcloud-triage-notify.token" && printf "%s\n" "$NOTIFY_TOKEN" > "$HOME/runcloud-triage-notify.token"';
```

Add `--notify-url 'https://your-site.example/...' --notify-token-file "$HOME/runcloud-triage-notify.token" --notify-findings --notify-timeout 30` to the scan command if required.

Or run **one scan in the background**, surviving an SSH disconnect:

```bash
(
    umask 077 &&
    RUN_DIR=$(mktemp -d "$HOME/runcloud-background.XXXXXX") &&
    {
        nohup /bin/sh -c 'run_dir=$1; shift; "$@"; result=$?; printf "%s\n" "$result" > "$run_dir/exit-code"; exit "$result"' sh "$RUN_DIR" /usr/bin/python3 -u -I "$HOME/runcloud-triage/runcloud-triage.py" < /dev/null > "$RUN_DIR/scan.log" 2>&1 &
        printf '%s\n' "$!" > "$RUN_DIR/pid";
        printf 'Background job: %s\nWatch: tail -f %s/scan.log\nExit code: cat %s/exit-code\n' "$RUN_DIR" "$RUN_DIR" "$RUN_DIR";
    }
);
```

Put callback/scan options after the script path and before `< /dev/null`. Reconnect as the **same user** and watch percentage, ETA and elapsed time:

```bash
RUN_DIR=$(ls -1dt "$HOME"/runcloud-background.*/ 2>/dev/null | head -n 1); if [ -n "$RUN_DIR" ]; then printf 'Watching %s\n' "$RUN_DIR"; tail -n 30 -f "$RUN_DIR/scan.log"; else printf 'No background scan folders found.\n'; fi;
```

Ctrl+C stops watching, not the scan. The latest-folder caveat, saved exit code and progress behaviour are the same as in the root background instructions above. This does not repeat or survive a reboot.

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

### Optional PHP assessment and network alert imports

Scanner **1.7.0+** offers three independent options. **All are off by default.** They can be combined with the regular scan, quick mode, callbacks and either root or user-account execution. Streambrain's Server Scans page has unchecked controls that update its foreground/background commands.

| Option | Reads | Adds |
| --- | --- | --- |
| `--assess-php` | Installed runtime entries in `/var/lib/dpkg/status` | PHP version evidence and its limitations |
| `--zeek-notice FILE` | Existing Zeek notice logs: JSON lines or standard tab-separated TSV | Known Corelight `PHP2SHELL::` notices |
| `--suricata-eve FILE` | Existing Suricata EVE JSON lines | Corelight PHP2Shell signature IDs 3000650, 3000651 and 3000652 |

**Optional PHP package assessment:**

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --assess-php
```

This uses installed FPM, CLI, CGI, Apache module and LiteSpeed runtime package metadata, including recognized RunCloud package names. It does not run `php -v`, load extensions, execute application code or request your websites. `php-runtime.jsonl` reports the complete package version, role, advisory reference, and one of:

- `below_upstream_fix`: REVIEW; check whether the vendor backported the fix.
- `at_or_above_upstream_fix`: INFO; the numeric version meets the upstream release threshold, but this does not verify a running website or prove that files are authentic.
- `legacy_requires_vendor_verification`: REVIEW; older branches need vendor-specific evidence, even if their version number is higher than the last official patch.
- `unknown`: INFO; unsupported version syntax, prereleases and unlisted branches are not treated as patched.

The thresholds are the official 21 October 2026 releases: PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12. Every assessment records `serving_runtime_verified: false` and a `php_serving_runtime_unverified` coverage limitation. Verify each site's pool/runtime and worker restarts separately. Containers, source builds and packages outside the recognized names are not assessed. Missing/unreadable package inventory or no recognized runtime packages produces an explicit gap and exit code `2`. A user-account run only reads this system package inventory when you select this option; it still omits the normal server-wide snapshots. [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5)

**Optional imports from sensors already installed:** replace these example paths with your actual log files. Pass either import option, or both:

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --zeek-notice /absolute/path/to/notice.log --suricata-eve /var/log/suricata/eve.json
```

Paths must be readable by the invoking account and have no symlink components. Some sensor installations use a `current` symlink: pass the real dated directory instead. Repeat an option for rotated files; `.gz`, `.bz2` and `.xz` are streamed without extraction. One input path can only be assigned one sensor format. Explicit sensor inputs are inspected once and excluded from the ordinary file/log pass. Other sensor rule IDs are ignored; the ignored-record count is reported. Known alerts are imported as review indicators, without claiming that exploitation succeeded or that no other attacks occurred.

Both imports use `--max-log-mib`, `--max-total-log-mib` and `--log-samples`. All inspected matches count even after the saved sample limit; the omitted count and coverage gap remain visible. Records over 1 MiB are skipped, with a coverage gap. Missing/unreadable logs and malformed or oversized records cause exit `2` rather than a misleading completed result. A byte-budget cutoff is reported as partial coverage. Sensor records are considered regardless of `--since`, like ordinary retained logs.

`network-alerts.jsonl` contains selected metadata: sensor, rule, timestamp, endpoints and event identifier where available. It omits request bodies, cookies, URLs, free-form sensor messages and body samples. The default callback sends optional-check counts; `--notify-findings` also sends the selected finding metadata. The scanner creates no packet capture and installs or starts no sensor. No alerts in the imported files is not a guarantee of traffic coverage.

For user mode, the same options follow your user-installed script:

```bash
/usr/bin/python3 -I "$HOME/runcloud-triage/runcloud-triage.py" --assess-php --zeek-notice "$HOME/scan-inputs/notice.log"
```

For a background command, put the options **after the scanner path and before `< /dev/null`**. Options do not change a scan that is already running. Runtime and network findings have explicit `runtime`/`network` kinds, are shown separately from file evidence in Streambrain, and **are never quarantine candidates**. They are also excluded from automatic file/folder AI dismissal and from file-hash clearances remembered across scans; an admin can still review and clear an individual result.

The version-assessment idea follows [OpenAI's PHP2Shell checker](https://github.com/openai/php2shell-checker), with an independent Python implementation using the official PHP advisory. Sensor identifiers and formats follow [Corelight's PHP2Shell detections](https://github.com/corelight/php2shell-detect). The scanner does not bundle or run their Node.js, Zeek or Suricata code; Python 3.6 and the standard library remain sufficient.

**Optional sensor deployment is a separate step.** Follow Corelight's installation and validation instructions if you want new network telemetry. Zeek requires 7.0+; the upstream Suricata rules were validated with 8.0.6. These sensors need HTTP visibility, including bodies; encrypted traffic needs decryption before inspection. Ordinary Nginx access logs cannot reconstruct that data, and a FastCGI connection from Nginx to PHP is not an HTTP inspection feed. Establish the traffic observation point before deploying a sensor; importing logs works without changing the web server. [Corelight setup](https://github.com/corelight/php2shell-detect#zeek), [Nginx FastCGI](https://nginx.org/en/docs/http/ngx_http_fastcgi_module.html)

### Optional completion callback

Use `--notify-url` to notify your own project when a run ends. This is an **HTTP POST with JSON**, not an ICMP ping or a GET request. It is disabled unless you supply a URL.

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --notify-url 'https://your-project.example/api/triage-results'
```

By default, the callback contains the hostname, run ID, timing, scan outcome, file/log counts, severity totals, coverage-gap counts, and effective read limits. This summary does not send application file paths, log excerpts, findings, credentials, or report attachments. Use HTTPS for remote endpoints; HTTP is available for local/private testing.

For an authenticated endpoint, create a mode `0600` or `0400` regular file owned by the account running the scanner and containing one bearer token. The root example is `/root/runcloud-triage-notify.token` (the token step at the start of step 4 does this); user mode uses `$HOME/runcloud-triage-notify.token`. Keep it outside scanned directories. Symlinks, empty tokens, internal whitespace, and files larger than 4096 bytes are rejected. A trailing newline is accepted.

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --notify-url 'https://your-project.example/api/triage-results' --notify-token-file /root/runcloud-triage-notify.token --notify-timeout 15
```

This adds `Authorization: Bearer TOKEN` to the request. Avoid credentials in URLs: command-line URLs can appear in process listings and local snapshots. Callback options are redacted in `summary.jsonl`; token contents are never stored there. Notification flags can be combined with `--quick`, `--no-precount`, or custom scan limits.

An example payload for a completed scan with indicators to review:

```json
{
  "schema_version": 1,
  "event": "runcloud-triage.finished",
  "scanner_version": "1.5.0",
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

To include the full saved findings list in the same JSON POST, add `--notify-findings` to the scan command:

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --notify-url 'https://your-project.example/api/triage-results' --notify-token-file /root/runcloud-triage-notify.token --notify-findings --notify-timeout 30
```

This adds the following fields to the summary payload (example with one finding):

```json
{
  "findings_scope": "saved_findings",
  "findings_count": 1,
  "findings_omitted": 0,
  "findings": [
    {
      "kind": "file",
      "path": "/home/runcloud/webapps/phpmyadmin/tmp/twig/03/example.php",
      "site": "/home/runcloud/webapps/phpmyadmin",
      "severity": "REVIEW",
      "rule": "php_in_writable_directory",
      "reason": "PHP in an upload/temp directory; verify whether this is expected.",
      "content_complete": true
    }
  ]
}
```

- `findings` includes **every saved HIGH, REVIEW and INFO finding**, in scan order, rather than the first 40 shown in the summary. One file can have several entries for different rules. The quarantine menu groups files separately; JSON array indexes are not quarantine selection numbers.
- Each entry includes its `path`, `site`, `severity`, `rule`, `reason`, and `kind` (`file` or `log`). Where recorded, it also includes `line`, `byte_offset`, `line_or_chunk`, `sha256`, `content_complete`, `mtime_utc`, and `ctime_utc`. A partial file read has `sha256: null`; full and prefix hashes with sizes remain available in the local `files.jsonl` inventory.
- `findings_count` is the array length. `findings_omitted` counts detected matches absent from the array, normally repeated log matches beyond `--log-samples`. The existing `indicators` totals still count those matches. This option does not increase scan/read/sample limits. An incomplete scan can also send the findings saved so far; check `scan_finished`, `report_finalized`, and coverage gaps even if `findings_omitted` is zero.
- Raw file contents, log excerpts, arbitrary evidence fields, and the notification token are excluded from the JSON body. Paths and site names are included, so use a trusted receiver and protect its stored results. Escape these values when displaying them in a web interface.
- The list is retained in memory only when this option is enabled, and is sent in one POST without an additional findings cap. For large reports, account for memory use, the receiver/proxy request-body limit, and `--notify-timeout`. HTTP 413 or another delivery failure does not silently trim the list or change the local report or scan exit code.

The callback runs **before the interactive quarantine prompt**. It reports scan findings, not subsequent quarantine actions, and cannot choose files or trigger quarantine remotely. A scan already running will keep its original notification behavior; use the updated script and flag on the next run.

In your project, accept a POST with `Content-Type: application/json; charset=utf-8`, validate the bearer token if configured, store the result, and return a **2xx** response promptly. `hostname` and `run_id` identify the server and local report folder. The response body is ignored.

| `status` | Meaning / suggested action |
| --- | --- |
| `completed` | Exit 0: no HIGH/REVIEW indicators or hard read failures. Review coverage gaps; this is not a clean bill of health. |
| `review_required` | Exit 1: at least one HIGH/REVIEW indicator. Queue an alert for investigation. |
| `incomplete` | Exit 2: interrupted run, initialization/finalization failure, or hard read/traversal failure. Alert that the scan needs attention. |

Check `status`, `scan_finished`, and `report_finalized` together. For example, traversal can finish with read failures (`scan_finished: true`, `status: incomplete`). An initialization failure may have `run_id: null` and no report. A `NO_MATCHING_INDICATORS` verdict on an incomplete run does not establish safety.

The scanner makes **one delivery attempt**, normally after report finalization, including runs with no indicators. It also attempts a failure callback for initialization/finalization errors or a handled Ctrl+C. Invalid arguments, an unreadable token file, failure of the Linux prerequisite, a forced kill, or a server outage can prevent any callback. Callbacks include `scan_scope` (`system` or `user`) and `effective_uid`; user mode always includes the `user_scope_only` coverage limitation once scanning starts.

`--notify-timeout` sets a 1–60 second delivery deadline (default **10 seconds**) on Linux. Redirects are refused, environment proxy settings are ignored, and HTTPS certificate verification remains enabled. A delivery failure prints a separate message without changing the scan's exit code or local report. There are no automatic retries; a lost response can mean the receiver accepted a request even though delivery is reported as failed. Treat this as a best-effort completion notification, not a guaranteed heartbeat.

## 5. Understand the report

Each run creates a unique directory such as:

```text
/root/runcloud-triage-SERVER-20261022T120000Z-a1b2c3d4/
```

The directory is mode `0700`; report files are private to the account that ran the scan (root for the server-wide examples). Existing reports are not overwritten. Copy the exact path printed by the scanner:

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

**Binary files (since 1.5.0).** Compressed image data contains the bytes `<?=` by chance: in one sample of 3,000 ordinary images over 100 KB, 418 contained them. In a file with NUL bytes in its first 8 KiB (images, fonts, archives and other binary formats), a PHP opening tag therefore only counts when readable, PHP-like text follows it (printable characters including `$`, `(`, `;` or `?>`). Scripts hidden in images, including real images with PHP appended, are still reported as `php_in_other_file_type`, `php_in_writable_directory` and any matching HIGH rule. Text files and PHP-named files are checked as before.

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

For phpMyAdmin, `tmp/twig/...php` paths are consistent with its generated template cache, and `libraries/classes/Plugins/Transformations/TEMPLATE_ABSTRACT` is an upstream PHP source template without a `.php` extension. Vendor `README.md` files can contain PHP examples. Those are plausible explanations for `php_in_writable_directory` and `php_in_other_file_type`, not confirmations that a particular server's copies are safe. The writable-directory rule uses path names such as `tmp` and `uploads`; it is not a test of effective write permissions. [phpMyAdmin temporary-directory documentation](https://docs.phpmyadmin.net/en/master/config.html#cfg_TempDir), [upstream template example](https://github.com/phpmyadmin/phpmyadmin/blob/RELEASE_5_2_2/libraries/classes/Plugins/Transformations/TEMPLATE_ABSTRACT)

Review each file's rules, reasons and available line numbers in `findings.jsonl`. Compare distributed files with a trusted copy of the **same installed release/dependency version**. Generated cache files need source review and comparison with the templates that produced them; their hashed names do not authenticate their contents. Prioritize unexpected executable code, unexplained changes and corroborating persistence or log evidence. Do not quarantine a file solely because it is listed: `h` selects all HIGH files, and HIGH is a review priority, not a confirmed malware verdict. Press Enter to defer quarantine while investigating.

If you find credible compromise, preserve reports and original logs and isolate the affected workload as appropriate. Do not simply delete a flagged file and declare the server clean: quarantine (step 6) contains a file, it does not clean a server. Investigate the scope, restore/rebuild from trusted sources as warranted, and rotate affected credentials from a trusted machine. Plan application encryption-key changes carefully: blindly replacing a Laravel `APP_KEY` can make existing encrypted data unreadable.

### Verify dependency files against a trusted release

`vendor/` remains in the scan. Since 1.6.0, the request-callable rule ignores confirmed PHP comments, including Symfony's `$_SERVER['HTTP_HOST'] (deprecated ...)` documentation. The case-sensitive `Session/Storage` directory is also distinguished from Laravel's lowercase `storage/`. These changes do not exempt Symfony files from other checks or from executable request-callable detection. No heuristic match automatically quarantines a file.

For stronger evidence, supply **hashes obtained independently from the exact official dependency release** with `--vendor-baseline /private/vendor-baseline.json`. Check the package version and commit in your trusted deployment's `composer.lock`; get that release on a clean machine. Do not build the baseline from the suspected server's current files or assume its package metadata is trustworthy. A local `composer install` is not an integrity check for an existing `vendor/` tree. See [Composer's reproducible dependency instructions](https://getcomposer.org/doc/01-basic-usage.md#installing-with-composer-lock) and [its notes on existing vendor contents](https://getcomposer.org/doc/articles/caching.md).

Example manifest format (replace the placeholder with the trusted file's 64-character lowercase SHA256, and use the actual server path/package/version):

```json
{
  "schema_version": 1,
  "files": {
    "/home/ACCOUNT/webapps/APP/vendor/symfony/http-foundation/Session/Storage/NativeSessionStorage.php": {
      "sha256": "REPLACE_WITH_TRUSTED_FILE_SHA256",
      "package": "symfony/http-foundation",
      "version": "REPLACE_WITH_EXACT_RELEASE"
    }
  }
}
```

Use `sha256sum /path/to/trusted/release/Session/Storage/NativeSessionStorage.php` on the clean machine to obtain the hash. Transfer the manifest securely, make it owned by the account running the scanner and mode `0600` or `0400`, and keep it outside website directories. It may contain up to 50,000 file entries within 8 MiB. Paths must be absolute, normalized Linux paths under `vendor/`; the manifest does not expand the scan's selected roots.

```bash
# Root example; user mode uses the same option with paths in that user's home.
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --vendor-baseline /root/vendor-baseline.json
```

`vendor-integrity.jsonl` records `match`, `mismatch` or `unverified` for each supplied file. Full-content mismatches produce a **HIGH `vendor_content_mismatch` review indicator**, including the expected hash and release labels. Legitimate local patches can also differ. Matching a supplied hash does not suppress any detection rule or establish that the whole dependency is safe. Missing, unreadable, out-of-scope and partially read files remain unverified and produce coverage gaps; increase the read limit if necessary. Files absent from the manifest get the ordinary heuristic scan but no release-integrity claim. Without a manifest, dependency integrity remains unverified. The scanner downloads no dependency code and never runs PHP, Composer, plugins or application scripts.

## 6. Quarantine, restore or delete flagged files

By default, when a scan finishes in an interactive SSH terminal, after the summary and any notification, it lists every file with a HIGH or REVIEW finding (log evidence is not listed) and asks which to quarantine:

```text
   1. HIGH   /home/runcloud/webapps/app/public/x.php  [request_to_execution]
   2. REVIEW /home/runcloud/webapps/app/wp-content/uploads/y.php  [php_in_writable_directory]
Quarantine which? Numbers (e.g. 1 3-5), h = all HIGH, a = all, Enter = none:
```

Then answer `y` to confirm. Enter, `n`, Ctrl+C or a closed session change nothing. Redirected, piped or scheduled runs never ask; like every run with flagged files, they print the command to use later. The scan's exit code is the same either way.

**Show only HIGH files in SSH (scanner 1.7.1+):** add `--high-only` to the scan command:

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --high-only
```

The final quarantine list then excludes REVIEW-only files. A file with both HIGH and REVIEW findings is listed once as HIGH, with all its rules retained. Selection numbers and `a` (all) apply only to the displayed HIGH files; you still choose and confirm before anything moves. If there are no HIGH file findings, it says so and skips selection. All REVIEW findings remain in the report, summary counts and configured callback, and still contribute to the scan's exit code. The option does not affect detection, restore or purge, and does not enable quarantine for user-account scans.

Streambrain offers an unchecked **Show only HIGH files in the SSH quarantine prompt** option. For a background command, add `--high-only` after the scanner path and before `< /dev/null`; the printed command for reopening quarantine keeps that option. It does not change a scan already running, but you can use it when reopening any saved report:

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --quarantine /root/runcloud-triage-SERVER-20261022T120000Z-a1b2c3d4 --high-only
```

Omit `--high-only` when reopening the report to see both HIGH and REVIEW files again.

If the SSH session closed, or you want to decide later, use the report folder the scan printed. Nothing is scanned again:

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --quarantine /root/runcloud-triage-SERVER-20261022T120000Z-a1b2c3d4
```

To put quarantined files back, or to delete quarantined copies for good:

```bash
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --restore
/usr/bin/python3 -I /root/runcloud-triage/runcloud-triage.py --purge
```

- **Only the file the scan read is moved.** It must still have the SHA-256 in the report or, for a file larger than the read limit, the same leading-bytes hash and size. Changed, missing or replaced files are skipped and listed as `SKIP`; scan again to review them.
- **Links are never followed.** Every folder on the way is opened without following symlinks, and only the recorded path is touched. If the file has other hard links, the message says so: those names still point to the same content (find them with `find / -xdev -inum INODE`, using the inode from `files.jsonl`).
- **Each file becomes one quarantine item**: `/root/runcloud-quarantine/<id>/content` (root-only, mode `0600`, never executable or web-served) plus `item.json` with the original path, owner, group, mode, timestamps, size, SHA-256, findings and report run ID. Later scans do not read this folder. `--quarantine-dir DIR` selects another root-owned `0700` folder outside `/home` and the temp directories; pass the same option to `--restore` and `--purge`.
- **A site that loads a quarantined file may show errors** until you restore it or deploy a clean copy.
- **`--restore`** checks the quarantined copy's hash, then writes it back with the original owner, group, mode and timestamps. It never overwrites: if something now exists at that path, or its folder is gone, the item stays in quarantine.
- **`--purge`** permanently deletes the chosen quarantined copies after you type `DELETE`.
- Every quarantine, restore and purge is appended to `/root/runcloud-quarantine/actions.jsonl`.
- These commands run only as root in an interactive terminal. Exit codes: `0` when every chosen file succeeded or nothing was chosen, `1` when any was skipped, `2` for an unusable report or quarantine folder, or no terminal.

## 7. Coverage and larger/custom servers

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

No database audit, memory capture, rootkit detection or complete historical authentication/persistence audit is performed. Independent vendor comparison requires the optional trusted manifest described above; other files have no baseline verification. The script intentionally does not run Git, Artisan, Composer, WP-CLI, PHP binaries or application commands. Local tools and logs can be misleading if the host itself is compromised.

The script writes only its new report directory. It does not alter website content, settings, users, services or jobs, delete/quarantine files, or restart workers. As with other live triage, directory/file reads can affect access times, commands generate normal audit records, and concurrent changes mean this is not an atomic forensic image. It requests no-atime file reads where supported and reports fallback counts.

## 8. Retrieve and retain reports

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

This tool inventories installed packages and observed process paths but deliberately **does not certify patch status**. The optional `--assess-php` comparison adds version evidence, while keeping the serving runtime unverified. Verify which runtime each site actually serves through, vendor backport information where applicable, and whether all relevant workers were restarted. CLI PHP versions can differ from serving FPM/LSAPI versions.

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

Linux filesystem fixtures test symlink/FIFO handling, age-independent coverage, report generation, compressed logs, limits and read failures. `tests/test_setup.py` checks the README commands in Bash and `/bin/sh` with offline download fixtures, including pasted command boundaries, private permissions, failed downloads and checksum mismatches. Its background fixture verifies that jobs continue after the launching shell exits and a hangup signal arrives, detach all terminal streams, and save exit codes 0/1/2. Run the tests as root in a disposable Linux environment. Detection and timestamp tests can also run on Windows; Linux-specific tests are skipped there. Python 3.6 grammar is checked on interpreters that provide AST grammar selection.

Version 1.7.0 validation includes optional package assessment, Zeek JSON/TSV and Suricata imports, malformed and oversized records, byte/sample limits, callback privacy, and exclusion of runtime/network findings from quarantine. It also covers the Symfony documentation regression and executable calls at the same vendor path, trusted vendor baseline matches/mismatches/unverified coverage, and complete CLI runs as root and an ordinary account in isolated filesystems. The suite retains checks for binary PHP-tag heuristics, scan exit codes 0/1/2, report permissions, counting/ETA, callback failures, background hangup handling, setup commands with spaces in home paths, and the existing quarantine safeguards. Notification transport tests use a local HTTP receiver and do not contact external services.

Older-runtime validation used packages verified against signed Ubuntu archive metadata in isolated chroots under WSL:

| Ubuntu userspace | Python | Test result |
| --- | --- | --- |
| 22.04 (WSL) | 3.10.12 | 99 passed |
| 18.04 | 3.6.9 | 98 passed; 1 skipped (AST grammar selection needs Python 3.8+) |
| 20.04 | 3.8.10 | 99 passed |

Both also passed isolated `--help` and Bash/`/bin/sh` setup checks. Ubuntu's curl 7.58.0 and 7.68.0 accept the download options used here. This validates the older userspace and Python APIs; each server's RunCloud configuration, kernel and external HTTPS endpoint still need on-host validation.

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
