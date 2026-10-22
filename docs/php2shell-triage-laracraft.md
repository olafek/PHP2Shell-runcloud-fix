# PHP2Shell: You patched, but were you hit?

**Source:** Laracraft  
**Author:** Zacharias Creutznacher  
**Published:** 21 October 2026  
**Original article:** https://laracraft.tech/en/blog/php2shell-were-you-hit-a-read-only-triage-script-for-your-server

> This is a structured Markdown adaptation of the Laracraft article, preserving its technical guidance while paraphrasing the prose.

## Context

PHP released fixes for the PHP2Shell vulnerabilities:

- **CVE-2026-109618**
- **CVE-2026-109619**

Both issues affect PHP's handling of `multipart/form-data` requests and can be triggered before application-level PHP code executes.

### Patched PHP releases

| PHP branch | Fixed version |
|---|---:|
| PHP 8.5 | 8.5.12 |
| PHP 8.4 | 8.4.27 |
| PHP 8.3 | 8.3.36 |
| PHP 8.2 | 8.2.35 |

PHP 8.1 and older are end of life. Source-level backports were made available for PHP 7.4, 8.0, and 8.1, but there are no official upstream packages for those releases.

The important point is that patching closes the vulnerability going forward, but it does not establish whether the server was compromised before the patch was installed.

According to the article, exploitation attempts were observed before the official fixes were released.

---

## What can and cannot be detected

There are two broad outcomes from exploitation.

### 1. Memory disclosure

An attacker may be able to expose PHP worker memory.

Potentially exposed information can include:

- passwords
- session tokens
- API keys
- application secrets
- TLS/private-key material present in memory

This may leave little or no persistent evidence on disk.

A clean filesystem therefore cannot prove that no memory disclosure occurred.

### 2. Remote code execution

If an attacker achieved code execution, there is a better chance of finding evidence.

Typical indicators include:

- modified application files
- newly created PHP files or webshells
- unexpected cron jobs
- added SSH keys
- unusual recent SSH logins
- unexplained outbound connections
- changes inside a Git checkout

The article describes the supplied script as **triage rather than full forensic analysis**.

---

## Triage script

The read-only script referenced by the article is available here:

https://gist.github.com/Sairahcaz/2c22b4a68fd5b75e410c7f9f69f485a0

Raw script:

https://gist.githubusercontent.com/Sairahcaz/2c22b4a68fd5b75e410c7f9f69f485a0/raw/php2shell-triage.sh

### Download it

```bash
curl -fsSL -o php2shell-triage.sh \
  https://gist.githubusercontent.com/Sairahcaz/2c22b4a68fd5b75e410c7f9f69f485a0/raw/php2shell-triage.sh
```

### Read it before running it

```bash
less php2shell-triage.sh
```

Because the script is intended to run as root, do not pipe an unknown remote script directly into `sudo bash`.

### Run it

```bash
sudo bash php2shell-triage.sh
```

### Run it against a specific Laravel application

```bash
sudo bash php2shell-triage.sh /home/forge/example.com/current
```

### Remove it afterwards

```bash
rm php2shell-triage.sh
```

---

## What the script checks

The script performs five main groups of checks.

### 1. PHP versions

It looks at available CLI and PHP-FPM binaries and compares their versions with the fixed PHP releases.

The PHP-FPM version is particularly important because that is normally the PHP runtime actually serving the website.

The CLI version can differ from the FPM version.

---

### 2. PHP-FPM memory-exhaustion errors

It searches PHP-FPM logs, including rotated compressed logs, for errors involving:

```text
Allowed memory size
```

A few memory-limit errors may be normal on a production application.

A concentrated spike around the exploitation window deserves closer investigation.

---

### 3. POST request volume

The script identifies busy POST targets around 21 October 2026.

Normal access logs usually do not include the HTTP `Content-Type`, so POST requests alone do not prove that a malicious `multipart/form-data` request was received.

They can still help identify suspicious targets, especially endpoints that normally do not accept uploads or large POST bodies.

---

### 4. Unexpected application files

For Laravel applications, the script checks for unexpected PHP files in locations such as:

```text
public/
storage/
```

It also uses:

```bash
git status
```

when the deployment is a Git checkout.

For a Laravel application, unexpected changes in a normally clean Git working tree are a strong signal that something needs investigation.

If Git is not available, recent PHP file modification times can still provide useful clues.

This is particularly useful with deployment systems that create timestamped or zero-downtime releases.

---

### 5. Persistence and access indicators

The script looks at items such as:

- cron entries
- SSH `authorized_keys`
- recent SSH logins
- currently established network connections
- connections using unusual ports

The final result is summarised as flags, warnings, or a relatively clean result.

---

## How to interpret the output

Internet-facing servers routinely receive automated scanning traffic.

Examples of noisy requests can include attempts against unrelated technologies and paths, such as:

```text
/cgi-bin/
```

or probes involving parameters intended for completely different PHP vulnerabilities.

These are not automatically evidence of PHP2Shell exploitation.

Likewise, legitimate deployment or server-management systems may create SSH login records from infrastructure-provider IP addresses.

The most important results to investigate are explicit flags such as:

- an unpatched PHP-FPM version
- an unexpected PHP file
- unexplained application changes
- a burst of relevant PHP-FPM fatal errors
- unknown cron jobs or SSH keys

---

## Distribution package caveat

The script compares PHP versions against upstream PHP release numbers.

Some Linux distributions backport security patches without changing the apparent upstream version number.

That means a version check can produce a false positive on distribution-maintained PHP packages.

For Debian or Ubuntu packages, inspect the package changelog:

```bash
apt changelog php8.3-fpm | grep -E '109618|109619'
```

For RPM-based systems:

```bash
rpm -q --changelog php-fpm | grep -E '109618|109619'
```

Verify whether the installed distribution package includes fixes for:

```text
CVE-2026-109618
CVE-2026-109619
```

---

## Missing PHP extensions after upgrading

After a PHP upgrade, an application may temporarily report errors caused by extensions that have not yet been installed or enabled for the new PHP version.

For example, Laravel may fail if `mbstring` is unavailable.

Check:

```bash
php -m | grep mbstring
```

If necessary, install the package corresponding to the PHP version in use, for example:

```bash
apt install php8.2-mbstring
```

Use the package version appropriate for the PHP-FPM runtime actually serving the site.

A missing extension after an upgrade is not itself evidence of PHP2Shell exploitation.

---

## Cloudflare considerations

Cloudflare deployed protections for known exploit vectors.

However, those protections only help when attackers are forced through Cloudflare.

Check for DNS records that expose the origin directly, including common names such as:

```text
staging
ftp
direct
```

Where practical, restrict inbound HTTP and HTTPS traffic on the origin server so that ports `80` and `443` are reachable only from Cloudflare's published IP ranges.

Cloudflare IP ranges:

https://www.cloudflare.com/ips/

---

## After patching

A useful response sequence is:

1. Patch PHP.
2. Verify which PHP-FPM version each site actually uses.
3. Run the read-only triage checks.
4. Review any explicit flags.
5. Compare application files against Git or trusted deployments/backups.
6. Inspect PHP-FPM, web-server, SSH, cron, and system logs.
7. Review unexpected outbound connections or persistence mechanisms.
8. Rotate secrets that may have been present in PHP worker memory.

Potential secrets to rotate include:

- Laravel `APP_KEY`
- database credentials
- third-party API credentials
- service tokens
- origin TLS/private-key material where appropriate

When rotating a Laravel `APP_KEY`, the previous key can be retained through Laravel's supported previous-key mechanism where required so existing encrypted data can still be decrypted.

---

## Important limitation

A clean result from this script does **not** prove that the server was never exploited.

It is most useful for detecting obvious or persistent compromise, including:

- outdated PHP runtimes
- dropped webshells
- modified application code
- persistence mechanisms
- suspicious log patterns

A sophisticated attacker who obtained code execution and removed evidence may not be detectable using a script running on the potentially compromised host itself.

For higher-confidence incident response, logs and evidence stored outside the affected server are preferable.

---

## References

- Original Laracraft article:  
  https://laracraft.tech/en/blog/php2shell-were-you-hit-a-read-only-triage-script-for-your-server

- PHP2Shell triage script:  
  https://gist.github.com/Sairahcaz/2c22b4a68fd5b75e410c7f9f69f485a0

- Cloudflare IP ranges:  
  https://www.cloudflare.com/ips/
