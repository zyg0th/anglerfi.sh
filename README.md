# Anglerfish

**Unified Package Manager for Pentest Box.**

Debian/Ubuntu boxes used for pentesting end up with tools scattered across `apt`, `go install`, `pip`, hand-built tarballs in `/opt`, and random shell scripts — each manager unaware of the others, occasionally clobbering the same binary name. Anglerfish wraps all of that behind one CLI and one editable catalog, so installing, listing, and removing your toolset is one consistent command regardless of where the tool actually comes from.

Built for pentesters running Debian or Ubuntu who want a clean, reproducible way to turn a fresh box into a working toolkit.

> **Status: beta / active development.** Interfaces and the bundled catalog may change between releases.

## What it is

- **`anglerfi.sh`** — the CLI. Parses commands, dispatches to `apt`, `go install`, or a manual tarball/jar installer, and can lock down the firewall.
- **`package.json`** — the tool catalog. Editable list of what's installable and how, grouped into `meta` bundles (`web`, `mobile`, `infra`) you can install in one shot.

## Install

### Option A — `.deb` (recommended)

Grab the latest build from [GitHub Actions artifacts](../../actions/workflows/build-deb.yml) or a [tagged release](../../releases), then:

```bash
sudo apt install ./anglerfish_<version>_all.deb
```

`apt` (not `dpkg -i`) resolves dependencies (`jq`, `wget`, `curl`, `tar`, `iptables`, `iptables-persistent`) automatically. This installs:

- `/usr/bin/anglerfi.sh` — the CLI, root:root 755
- `/etc/anglerfish/package.json` — the catalog, root:root 644, marked as a conffile (your edits survive upgrades)

### Option B — run from source

```bash
git clone git@github.com:zyg0th/anglerfi.sh.git
cd anglerfi.sh
chmod +x anglerfi.sh
sudo ./anglerfi.sh --setup     # installs jq/go/pip/pipx/cargo toolchains
```

When run this way, the script falls back to the `package.json` sitting next to it.

## Usage

```
anglerfi.sh -i, --install <package|meta>   install a package or a full meta group
anglerfi.sh -r, --remove  <package|meta>   remove a package or a full meta group
anglerfi.sh -l, --list [-a|--all]          list installed packages (--all: include missing ones too)
anglerfi.sh --firewall <desktop|server>    configure iptables, persisted via iptables-persistent
anglerfi.sh -s, --setup                    install go/pip/pipx/cargo toolchains
anglerfi.sh -h, --help                     show this help
```

### Examples

```bash
sudo anglerfi.sh -i nmap              # single package (apt-backed)
sudo anglerfi.sh -i web               # everything in the "web" meta group
anglerfi.sh -l                        # what's actually installed
anglerfi.sh -l --all                  # installed + missing, full catalog
sudo anglerfi.sh -r caido             # remove a manually-installed tool
sudo anglerfi.sh --firewall desktop   # deny all inbound except 8000/8080
sudo anglerfi.sh --firewall server    # deny all inbound except 22
```

## The catalog (`package.json`)

Four sections:

- **`meta`** — named bundles (`web`, `mobile`, `infra`) mapping to a list of package names. `-i web` expands and installs each member.
- **`apt`** — thin wrapper around `apt-get install`. `check` decides if it's already present.
- **`go`** — wraps `go install <module>@version`.
- **`manual`** — for anything with no package manager: downloads a tarball/jar, verifies it against a pinned `hash` (sha256), then runs `post_install` (extraction, symlinking into `/usr/local/bin`, `.desktop` file creation) and has a matching `remove` command for clean teardown.

Bundled today: `nmap`, `nuclei`, `httpx`, `ffuf`, `sqlmap`, `nikto`, `gobuster`, `wpscan`, `caido`, `subfinder`, `masscan`, `amass`, `netexec`, `jadx`, `adb`, `apktool`, `scrcpy`, `android-studio`, `uber-apk-signer`, `apkeditor`.

Edit `package.json` to add your own tools or change what a meta group installs.

## Security notes

- **The catalog is trusted config, not user input.** Every `install`/`post_install`/`remove`/`check` field runs as root. Treat `/etc/anglerfish/package.json` like `/etc/sudoers` — root-owned, not group/world-writable. If you edit it as an unprivileged user, that's a self-inflicted privesc.
- **Manual installs are hash-verified.** Downloaded artifacts are checked against a pinned sha256 before anything is unpacked or symlinked; a mismatch aborts and deletes the file.
- **PATH is pinned at startup** (`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`) and every external binary the script calls (`jq`, `apt-get`, `go`, `tar`, `sha256sum`, ...) is resolved once against that fixed path — a malicious directory prepended to `$PATH` can't shadow them.

## License

See [LICENSE](LICENSE).
