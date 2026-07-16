# Anglerfish

**Unified Package Manager for Pentest Box.**

Debian/Ubuntu boxes used for pentesting end up with tools scattered across `apt`, `go install`, `pipx`, hand-built tarballs in `/opt`, and random shell scripts — each manager unaware of the others, occasionally clobbering the same binary name. Anglerfish wraps all of that behind one CLI and one editable catalog, so installing, listing, and removing your toolset is one consistent command regardless of where the tool actually comes from.

Built for pentesters running Debian or Ubuntu who want a clean, reproducible way to turn a fresh box into a working toolkit.

> **Status: beta / active development.** Interfaces and the bundled catalog may change between releases.

## What it is

- **`anglerfi.sh`** — the CLI. Parses commands, dispatches to `apt`, `go install`, `pipx`, or a manual tarball/jar/deb installer, and can lock down the firewall.
- **`package.json`** — the tool catalog. Editable list of what's installable and how, grouped into `meta` bundles (`web`, `mobile`, `infra`) you can install in one shot.

## Install

### Option A — `.deb` (recommended)

Grab the latest build from [GitHub Actions artifacts](../../actions/workflows/build-deb.yml) or a [tagged release](../../releases), then:

```bash
sudo apt install ./anglerfish_<version>_all.deb
```

`apt` (not `dpkg -i`) resolves dependencies (`jq`, `wget`, `curl`, `tar`, `unzip`, `python3`, `iptables`, `iptables-persistent`) automatically. This installs:

- `/usr/bin/anglerfi.sh` — the CLI, root:root 755
- `/etc/anglerfish/package.json` — the catalog, root:root 644, marked as a conffile (your edits survive upgrades)

### Option B — run from source

```bash
git clone git@github.com:zyg0th/anglerfi.sh.git
cd anglerfi.sh
chmod +x anglerfi.sh
./anglerfi.sh -l              # unprivileged actions work as-is
```

When run this way, the script falls back to the `package.json` sitting next to it.

**Privileged actions (`apt`/`manual` installs and removes, `--firewall`, `--setup`) require both the script and the catalog to be root-owned and not group/other-writable** — the script refuses otherwise, on purpose (see [Security notes](#security-notes)). A fresh git checkout is owned by you, not root, so those commands will fail until you fix ownership:

```bash
sudo chown root:root anglerfi.sh package.json
sudo chmod 755 anglerfi.sh
sudo chmod 644 package.json
sudo ./anglerfi.sh --setup
```

If you don't want to chown your working copy, use Option A instead — the `.deb` sets this up for you.

## Usage

```
anglerfi.sh -i, --install <package|meta> [-v|--version <ver>]
                                           install a package or a full meta group
anglerfi.sh -r, --remove  <package|meta>   remove a package or a full meta group
anglerfi.sh -l, --list [-a|--all]          list installed packages (--all: include missing ones too)
anglerfi.sh --firewall <desktop|server>    configure iptables, persisted via iptables-persistent
anglerfi.sh -s, --setup                    install go/pipx/cargo toolchains
anglerfi.sh -h, --help                     show this help
```

### Examples

```bash
anglerfi.sh -i nmap              # single package (apt-backed) - prompts for sudo itself
anglerfi.sh -i nmap -v 7.94      # pin a specific apt version instead of whatever's current
anglerfi.sh -i nuclei -v v3.2.0  # same, for a go-backed package (rewrites the @version suffix)
anglerfi.sh -i reflutter -v 0.8.5 # same, for a pipx-backed package (forces reinstall at that pin)
anglerfi.sh -i web               # everything in the "web" meta group
anglerfi.sh -l                   # what's actually installed
anglerfi.sh -l --all             # installed + missing, full catalog
anglerfi.sh -r caido             # remove a manually-installed tool
anglerfi.sh --firewall desktop   # deny all inbound except 8000/8080
anglerfi.sh --firewall server    # deny all inbound except 22
```

`-v`/`--version` only applies to a single `apt`/`go`/`pipx` package — it's rejected outright for meta groups (which package would it even pin?) and for `manual` installs (those are hash-pinned to one specific artifact; edit `package.json` if you need a different release).

You don't need to prefix `sudo` yourself — the script only elevates the specific commands that need root (`apt-get`, writes under `/opt`/`/etc`, `iptables`, ...) and prompts for your password right when it hits one. `go install` and friends run as your own user throughout, so binaries land in your own `$GOPATH`, not root's.

## The catalog (`package.json`)

Five sections:

- **`meta`** — named bundles (`web`, `mobile`, `infra`) mapping to a list of package names. `-i web` expands and installs each member.
- **`apt`** — thin wrapper around `apt-get install`. `check` decides if it's already present.
- **`go`** — wraps `go install <module>@version`.
- **`manual`** — for anything with no package manager: downloads a tarball/jar/deb, verifies it against a pinned `hash` (sha256), then runs `post_install` (extraction, symlinking into `/usr/local/bin`, `.desktop` file creation, or `apt-get install ./file.deb`) and has a matching `remove` command for clean teardown.
- **`pipx`** — wraps `pipx install <spec>` for Python CLI tools that shouldn't pollute the system `pip`.

All `manual`-kind downloads are pinned to `linux-x86_64`/`amd64` builds — no arm/aarch64 support yet.

Bundled today: `nmap`, `nuclei`, `httpx`, `ffuf`, `sqlmap`, `gobuster`, `wpscan`, `caido`, `subfinder`, `masscan`, `amass`, `netexec`, `jadx`, `adb`, `apktool`, `scrcpy`, `android-studio`, `uber-apk-signer`, `apkeditor`, `reflutter`, `frida-tools`, `pidcat`, `hermes-dec`, `palera1n`.

Edit `package.json` to add your own tools or change what a meta group installs.

## Security notes

- **Selective elevation, not a root-only process.** The script runs as your own user and only re-execs the specific commands that need root (via `sudo`) — `apt-get`, writes under `/opt`/`/etc`, `iptables`. `go install` and catalog lookups never elevate, so tools land in your own `$GOPATH`, not root's, even if you happen to launch the whole script with `sudo` yourself (it detects `$SUDO_USER` and drops back down for those calls).
- **The catalog is trusted config, not user input.** Every `install`/`post_install`/`remove`/`check` field runs as root when a privileged action needs it. Treat `/etc/anglerfish/package.json` like `/etc/sudoers` — root-owned, not group/world-writable.
- **The script enforces this itself, at runtime.** Right before any privileged action, it verifies both `anglerfi.sh` and `package.json` are owned by root with no group/other write bit — and refuses otherwise. This closes the obvious privesc: a low-privileged user pointing `$ANGLERFISH_PKG` at their own file, or editing a writable script/catalog, can't get root to run anything through it. The `.deb` sets correct ownership automatically; a source checkout needs `chown root:root` on both files before privileged commands will run (see [Option B](#option-b-run-from-source)).
- **Refuses to run if setuid/setgid.** Linux's `execve()` already drops those bits on `#!`-interpreted scripts, but that's kernel behavior, not a guarantee this script controls. `anglerfi.sh` isn't meant to gain privilege that way (it uses `sudo`, per-command, explicitly) — so it checks its own mode at startup and exits before doing anything if either bit is set.
- **Manual installs are hash-verified.** Downloaded artifacts are checked against a pinned sha256 before anything is unpacked or symlinked; a mismatch aborts and deletes the file.
- **PATH is pinned at startup** (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`) and every external binary the script calls (`jq`, `apt-get`, `go`, `tar`, `sha256sum`, ...) is resolved once against that fixed path — a malicious directory prepended to `$PATH` can't shadow them.

## License

See [LICENSE](LICENSE).
