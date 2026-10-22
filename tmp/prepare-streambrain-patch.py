from pathlib import Path
import difflib

root = Path('D:/works/laravel/streambrain')
changes = {}


def replace(relative, before, after):
    if relative not in changes:
        original = (root / relative).read_text(encoding='utf-8')
        changes[relative] = [original, original]
    assert before in changes[relative][1], relative
    changes[relative][1] = changes[relative][1].replace(before, after, 1)


service = 'app/Services/ServerScanReport.php'
replace(service, '''    /**
     * One paste on a server (as root) that (re)creates the 0600 token file with the token
     * already in it. The leading space keeps it out of bash history (HISTCONTROL=ignoreboth);
     * printf is a builtin, so the token never shows in the process list either.
     */''', '''    /** POSIX shell setup for Ubuntu 18.04+: stop if a download or checksum check fails. */
    public static function downloadCommand(): string
    {
        $base = 'https://raw.githubusercontent.com/olafek/PHP2Shell-runcloud-fix/master/';
        $curl = "curl --fail --show-error --silent --location --proto '=https' --proto-redir '=https' ";

        return '(umask 077 && install -d -o root -g root -m 0700 /root/runcloud-triage'
            . ' && cd /root/runcloud-triage'
            . ' && ' . $curl . self::shellQuote($base . 'runcloud-triage.py') . ' -o runcloud-triage.py'
            . ' && ' . $curl . self::shellQuote($base . 'runcloud-triage.py.sha256') . ' -o runcloud-triage.py.sha256'
            . ' && sha256sum --check runcloud-triage.py.sha256'
            . ' && chmod 0600 runcloud-triage.py runcloud-triage.py.sha256);';
    }

    /**
     * One paste on a server (as root) that (re)creates the 0600 token file with the token
     * already in it. A leading space avoids Bash history only with ignorespace/ignoreboth.
     * The final separator also permits joining this command to the next copied step.
     */''')
replace(service, '''self::shellQuote($token));''', '''self::shellQuote($token)) . ';';''')

controller = 'app/Http/Controllers/Backend/ServerScansController.php'
replace(controller, '''        $tokenFileCommand = $token !== '' ? ServerScanReport::tokenFileCommand($token) : null;''', '''        $downloadCommand = ServerScanReport::downloadCommand();
        $tokenFileCommand = $token !== '' ? ServerScanReport::tokenFileCommand($token) : null;''')
replace(controller, "compact('scans', 'tokenFileCommand', 'scanCommand')", "compact('scans', 'downloadCommand', 'tokenFileCommand', 'scanCommand')")

view = 'resources/views/admin/server-scans/index.blade.php'
replace(view, '''                        anything in the full JSON. To make a server report here, after downloading the scanner over SSH
                        (README step 3), paste these two lines as root:''', '''                        anything in the full JSON. To make a server report here, open an SSH session as root and run
                        these three steps in order. Ubuntu 18.04, 20.04 and newer with Python 3.6+ are supported;
                        the scanner does not require a PHP upgrade.
                    </p>
                    <p class="small mb-2">
                        Check <code>/usr/bin/python3 --version</code> and <code>command -v curl</code> first.
                        Copy one step into a <strong>fresh terminal prompt</strong>, press Enter, and wait for it to finish
                        before copying the next. Keep the final <code>;</code> on setup commands.
                        Continue after step 1 only when the checksum says <code>OK</code>.
                        <a href="https://github.com/olafek/PHP2Shell-runcloud-fix#2-log-in-and-check-requirements" target="_blank" rel="noopener noreferrer">Full setup instructions</a>''')
replace(view, "['1. Create the token file' => $tokenFileCommand, '2. Run the scan' => $scanCommand]", "['1. Download and verify' => $downloadCommand, '2. Create the token file' => $tokenFileCommand, '3. Run the scan' => $scanCommand]")
replace(view, '''                            Line 1 contains the <strong>Server Scan Token</strong> (Settings) and starts with a space so it
                            stays out of the shell history. If you change the token, re-run line 1 on every server.''', '''                            Step 2 creates a root-only token file and contains the <strong>Server Scan Token</strong> (Settings).
                            Its leading space keeps it out of Bash history only when <code>HISTCONTROL</code> includes
                            <code>ignorespace</code> or <code>ignoreboth</code>. The README also offers a hidden token prompt.
                            If you change the token, re-run step 2 on every server.
                        </p>
                        <p class="text-muted small mb-3">
                            <code>chmod: invalid option -- 'm'</code> means two commands were joined without a separator.
                            Press Ctrl+C to clear any unexecuted input, then paste each step separately.
                            When joining commands yourself, use <code>&amp;&amp;</code> between them.''')

unit = 'tests/Unit/ServerScanReportTest.php'
replace(unit, '''    public function test_token_file_command_creates_the_private_file_with_the_token_in_it(): void''', '''    public function test_download_command_checks_both_downloads_before_finishing_setup(): void
    {
        $command = ServerScanReport::downloadCommand();

        $this->assertStringStartsWith('(umask 077 && install -d', $command);
        $this->assertSame(2, substr_count($command, ' && curl --fail'));
        $this->assertStringContainsString("--proto '=https' --proto-redir '=https'", $command);
        $this->assertStringEndsWith(' && sha256sum --check runcloud-triage.py.sha256'
            . ' && chmod 0600 runcloud-triage.py runcloud-triage.py.sha256);', $command);
    }

    public function test_token_file_command_creates_the_private_file_with_the_token_in_it(): void''')
replace(unit, "// Leading space keeps the token out of root's bash history (HISTCONTROL=ignoreboth).", "// The separator prevents this step from running into the scan command when pasted together.")
before = changes.get(unit, ['', (root / unit).read_text(encoding='utf-8')])[1]
changes[unit][1] = before.replace('> /root/runcloud-triage-notify.token",', '> /root/runcloud-triage-notify.token;",')

feature = 'tests/Feature/ServerScansAdminTest.php'
replace(feature, '''            ->assertSee("install -m 600 /dev/null /root/runcloud-triage-notify.token''', '''            ->assertSeeInOrder(['1. Download and verify', '2. Create the token file', '3. Run the scan'])
            ->assertSee('fresh terminal prompt')
            ->assertSee('Ubuntu 18.04, 20.04 and newer with Python 3.6+')
            ->assertSee(ServerScanReport::downloadCommand())
            ->assertSee("install -m 600 /dev/null /root/runcloud-triage-notify.token''')
changes[feature][1] = changes[feature][1].replace('> /root/runcloud-triage-notify.token")', '> /root/runcloud-triage-notify.token;")')

patch = ''.join(''.join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                          fromfile='a/' + path, tofile='b/' + path))
                for path, (before, after) in changes.items())
Path('tmp/streambrain-setup.patch').write_bytes(patch.encode('utf-8'))
print('Prepared patch:', ', '.join(changes))
