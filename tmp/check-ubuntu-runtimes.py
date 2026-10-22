"""Temporary isolated compatibility check using signed Ubuntu archive packages."""
import concurrent.futures
import hashlib
import lzma
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import urllib.request

BASE = "https://archive.ubuntu.com/ubuntu/"
SOURCE = Path("/mnt/d/works/server/PHP2Shell-runcloud-fix")
WORK = Path("/var/tmp/triage-ubuntu-compat-20261022")
WORK.mkdir(exist_ok=True, mode=0o700)
print("Validation workspace:", WORK, flush=True)


def download(relative):
    for attempt in range(3):
        try:
            with urllib.request.urlopen(BASE + relative, timeout=30) as response:
                return response.read()
        except (OSError, TimeoutError):
            if attempt == 2:
                raise
            print("Retrying", relative, flush=True)


def index(suite):
    release = WORK / (suite + "-InRelease")
    if not release.exists():
        release.write_bytes(download("dists/" + suite + "/InRelease"))
    subprocess.run(["gpgv", "--keyring", "/usr/share/keyrings/ubuntu-archive-keyring.gpg", str(release)], check=True)
    name = "main/binary-amd64/Packages.xz"
    match = re.search(r"^ ([0-9a-f]{64})\s+\d+ " + re.escape(name) + r"$", release.read_text(), re.M)
    index_path = WORK / (suite + "-Packages.xz")
    if not index_path.exists():
        index_path.write_bytes(download("dists/" + suite + "/" + name))
    content = index_path.read_bytes()
    assert hashlib.sha256(content).hexdigest() == match.group(1)
    packages = {}
    for paragraph in lzma.decompress(content).decode().split("\n\n"):
        fields = dict(line.split(": ", 1) for line in paragraph.splitlines() if ": " in line and not line.startswith(" "))
        if "Package" in fields:
            packages[fields["Package"]] = fields
    return packages


def check(suite, version):
    packages = index(suite)
    packages.update(index(suite + "-updates"))
    selected = {}
    pending = ["python" + version, "coreutils", "bash", "dash", "curl"]
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        package = packages[name]
        selected[name] = package
        for dependency in (package.get("Pre-Depends", "") + "," + package.get("Depends", "")).split(","):
            choices = [re.split(r"[\s:(]", item.strip())[0] for item in dependency.split("|")]
            if not any(choices):
                continue
            found = next((choice for choice in choices if choice in packages), None)
            if found is None:
                found = next((key for key, value in packages.items()
                              if any(choice in value.get("Provides", "").split(", ") for choice in choices)), None)
            if found is None:
                raise RuntimeError("Unresolved dependency " + dependency)
            pending.append(found)
    root = WORK / suite
    root.mkdir(exist_ok=True)
    def fetch(package):
        path = WORK / Path(package["Filename"]).name
        if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == package["SHA256"]:
            return path
        print("Downloading", package["Package"], flush=True)
        data = download(package["Filename"])
        assert hashlib.sha256(data).hexdigest() == package["SHA256"]
        path.write_bytes(data)
        return path
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        archives = list(pool.map(fetch, selected.values()))
    for archive in archives:
        subprocess.run(["dpkg-deb", "--extract", str(archive), str(root)], check=True)
    if not (root / "bin/sh").is_symlink():
        (root / "bin/sh").symlink_to("dash")
    (root / "etc/passwd").write_text("root:x:0:0:root:/root:/bin/bash\n")
    (root / "etc/group").write_text("root:x:0:\n")
    (root / "tmp").mkdir(exist_ok=True, mode=0o1777)
    (root / "dev").mkdir(exist_ok=True)
    if not (root / "dev/null").exists():
        os.mknod(str(root / "dev/null"), 0o666 | 0o020000, os.makedev(1, 3))
    testdir = root / "work"
    testdir.mkdir(exist_ok=True)
    shutil.copy2(str(SOURCE / "runcloud-triage.py"), str(testdir))
    shutil.copy2(str(SOURCE / "README.md"), str(testdir))
    shutil.copytree(str(SOURCE / "tests"), str(testdir / "tests"), ignore=shutil.ignore_patterns("__pycache__"), dirs_exist_ok=True)
    python = "/usr/bin/python" + version
    subprocess.run(["chroot", str(root), python, "--version"], check=True)
    subprocess.run(["chroot", str(root), python, "-I", "/work/runcloud-triage.py", "--help"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["chroot", str(root), python, "-m", "unittest", "discover", "-s", "/work/tests", "-v"], check=True)
    for shell in ("/bin/bash", "/bin/dash"):
        command = "cd /work && chmod 0600 runcloud-triage.py; install -m 600 /dev/null /tmp/notify.token && printf '%s\\n' 'dummy-test-token' > /tmp/notify.token;"
        subprocess.run(["chroot", str(root), shell, "-c", command], check=True)
        assert (root / "tmp/notify.token").read_text() == "dummy-test-token\n"
        assert (root / "tmp/notify.token").stat().st_mode & 0o777 == 0o600
    print("PASS:", suite, version, "scanner suite, --help, bash/dash setup commands", flush=True)


for suite, version in (("bionic", "3.6"), ("focal", "3.8")):
    check(suite, version)
