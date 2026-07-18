# Anglerfish

[![Build .deb](https://github.com/zyg0th/anglerfi.sh/actions/workflows/build-deb.yml/badge.svg)](https://github.com/zyg0th/anglerfi.sh/actions/workflows/build-deb.yml)

**Unified Package Manager for Offensive Security Box.**

Debian/Ubuntu boxes used for offensive security work end up with tools scattered across `apt`, `go install`, `pipx`, hand-built tarballs in `/opt`, and random shell scripts — each manager unaware of the others, occasionally clobbering the same binary name. Anglerfish wraps all of that behind one CLI and one editable catalog, so installing, listing, and removing your toolset is one consistent command regardless of where the tool actually comes from.

Built for offensive security practitioners running Debian or Ubuntu who want a clean, reproducible way to turn a fresh box into a working toolkit.

> **Status: beta / active development.** Interfaces and the bundled catalog may change between releases.

## What it is

- **`anglerfi.sh`** — the CLI. Parses commands, dispatches to `apt`, `go install`, `pipx`, or a manual tarball/jar/deb installer, and can lock down the firewall.
- **`package.json`** — the tool catalog. Editable list of what's installable and how, grouped into `meta` bundles (`web`, `mobile`, `infra`, `references`) you can install in one shot.

## Install

### Option A — `.deb` (recommended)

Grab the latest build from [GitHub Actions artifacts](../../actions/workflows/build-deb.yml) or a [tagged release](../../releases), then:

```bash
sudo apt install ./anglerfish_<version>_all.deb
```

`apt` (not `dpkg -i`) resolves dependencies (`jq`, `wget`, `curl`, `tar`, `unzip`, `python3`, `git`, `iptables`, `iptables-persistent`) automatically. This installs:

- `/usr/bin/anglerfi.sh` — the CLI, root:root 755
- `/usr/bin/af` — a symlink to `anglerfi.sh`, so you don't have to type the whole name
- `/etc/anglerfish/package.json` — the catalog, root:root 644, marked as a conffile (your edits survive upgrades)
- `man anglerfi.sh` / `man af` — full reference for every flag, catalog kind, and the `-pkg`/`+pkg` meta-composition syntax

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
anglerfi.sh -i, --install <package|meta> [-v|--version <ver>] [-pkg ...] [+pkg ...]
                                           install a package or a full meta group
                                           (-pkg excludes a member from a meta group; +pkg adds an extra package to the run)
anglerfi.sh -r, --remove  <package|meta>   remove a package or a full meta group
anglerfi.sh -l, --list [-a|-all|--all]     list installed packages (--all: include missing ones too)
anglerfi.sh --firewall <desktop|server>    configure iptables, persisted via iptables-persistent
anglerfi.sh -s, --setup                    install go/pipx/git/cargo toolchains
anglerfi.sh -h, --help                     show this help
```

### Examples

```bash
anglerfi.sh -i nmap              # single package (apt-backed) - prompts for sudo itself
anglerfi.sh -i nmap -v 7.94      # pin a specific apt version instead of whatever's current
anglerfi.sh -i nuclei -v v3.2.0  # same, for a go-backed package (rewrites the @version suffix)
anglerfi.sh -i reflutter -v 0.8.5 # same, for a pipx-backed package (forces reinstall at that pin)
anglerfi.sh -i web               # everything in the "web" meta group
anglerfi.sh -i web -zaproxy +burpsuite-pro # "web", but skip zaproxy and add burpsuite-pro for this run
anglerfi.sh -i web +infra +osint # merge three meta groups into one run (deduplicated)
anglerfi.sh -l                   # what's actually installed
anglerfi.sh -l --all             # installed + missing, full catalog
anglerfi.sh -r caido             # remove a manually-installed tool
anglerfi.sh --firewall desktop   # deny all inbound except 8000/8080
anglerfi.sh --firewall server    # deny all inbound except 22
```

`-v`/`--version` only applies when exactly one package ends up being installed (after any `-pkg`/`+pkg` are applied) — it's rejected for anything that resolves to more or fewer than one, and for `manual` installs (those are hash-pinned to one specific artifact; edit `package.json` if you need a different release).

`-pkg`/`+pkg` customize a meta group for a single run without touching `package.json`: `-pkg` drops a member, `+pkg` installs an extra package alongside it. Both can repeat and combine freely, and `+pkg` expands to a whole meta group's members if the name given is itself a meta (so `-i web +infra +osint` merges three groups into one run) — the final list is always deduplicated. Both flags are rejected against a single (non-meta) package — there's no member to drop or run alongside.

You don't need to prefix `sudo` yourself — the script only elevates the specific commands that need root (`apt-get`, writes under `/opt`/`/etc`, `iptables`, ...) and prompts for your password right when it hits one. `go install` and friends run as your own user throughout, so binaries land in your own `$GOPATH`, not root's.

## The catalog (`package.json`)

Six sections:

- **`meta`** — named bundles (`web`, `mobile`, `infra`, `references`, `osint`, `dev`, `wireless`) mapping to a list of package names. `-i web` expands and installs each member. Wordlists/guides live in their own `references` bundle instead of being forced onto everyone installing `web`/`mobile`/`infra` — nobody should have to eat a 3.4GB SecLists clone just to get `ffuf`.
- **`apt`** — thin wrapper around `apt-get install`. `check` decides if it's already present. Optional `pre_install` runs once before the install (e.g. adding a vendor's apt repo + GPG key) for packages that aren't in the default Debian/Ubuntu repos but ship their own — no hash to pin or re-check on every upstream release, since the vendor's repo is the trust mechanism from then on (see `code`, VS Code's real apt package name).
- **`go`** — wraps `go install <module>@version`.
- **`pipx`** — wraps `pipx install <spec>` for Python CLI tools that shouldn't pollute the system `pip`.
- **`git`** — shallow-clones (`--depth 1`) a `repo` into `/opt/<name>`, optionally at a specific `ref` (tag/branch), then runs `post_clone` (symlinking, wrapper scripts). No hash pinning — trades that off for tools that are meant to track upstream (e.g. `searchsploit`'s own `-u` update path expects a real git checkout it can `git pull`). Use this instead of `manual` when the upstream project *is* the git repo (a script/source tree you'd otherwise `git clone` by hand), not when the real artifact is a separately-built release binary.
- **`manual`** — for anything with no package manager: downloads a tarball/jar/deb, verifies it against a pinned `hash` (sha256), then runs `post_install` (extraction, symlinking into `/usr/local/bin`, `.desktop` file creation, or `apt-get install ./file.deb`) and has a matching `remove` command for clean teardown.

All `manual`-kind downloads are pinned to `linux-x86_64`/`amd64` builds — no arm/aarch64 support yet.

Bundled today: `nmap`, `nuclei`, `httpx`, `ffuf`, `sqlmap`, `gobuster`, `wpscan`, `caido`, `subfinder`, `masscan`, `amass`, `netexec`, `smbmap`, `python3-impacket`, `hashcat`, `john`, `hydra`, `jadx`, `adb`, `apktool`, `scrcpy`, `android-studio`, `uber-apk-signer`, `apkeditor`, `reflutter`, `frida-tools`, `hermes-dec`, `palera1n`, `pidcat`, `searchsploit`, `feroxbuster`, `seclists`, `payloadsallthethings`, `internalallthethings`, `hardwareallthethings`, `mastg`, `wstg`, `gtfobins`, `lolbas`, `sherlock`, `maigret`, `holehe`, `theharvester`, `libimage-exiftool-perl`, `gau`, `waybackurls`, `clang`, `gcc`, `neovim`, `code` (VS Code), `responder`, `netcat-openbsd`, `socat`, `sliver-client`, `sliver-server`, `metasploit-framework`, `wireshark`, `tcpdump`, `bettercap`, `aircrack-ng`, `wifite`, `reaver`, `bluez-tools`, `libnfc-bin`, `mfoc`, `podman`, `vagrant`, `docker-ce`, `virtualbox-7.2`, `burpsuite-pro`, `zaproxy`.

`docker-ce` and `virtualbox-7.2` use `pre_install` to register their vendors' own apt repos (Docker's and Oracle's, respectively) — same pattern as `code`, same reasoning: no hash to maintain, `apt upgrade` keeps them current forever after.

`burpsuite-pro` installs the Professional edition binary itself (hash-pinned, silent Install4j install via `-q -dir`) — no license key is stored or required anywhere in the catalog; you activate it yourself on first launch with your own PortSwigger license. The installer already generates a correct `.desktop` entry (with a real icon) pointing at the install directory, so `post_install` just copies that instead of hand-writing one.

`metasploit-framework` runs Rapid7's official `msfinstall` script (hash-pinned) rather than reimplementing its apt-repo/GPG-key dance ourselves — it already does exactly that internally, and re-deriving it by hand would just be another thing to keep in sync with upstream.

`theharvester`'s PyPI package is a stale, unmaintained `0.0.1` stub — the real project (currently `4.11.1`) never publishes proper releases there. Installing it straight would be a textbook dependency-confusion trap, so its `pipx` entry points `package` at `git+https://github.com/laramies/theHarvester.git` instead of the PyPI name, building from the real source (confirmed the resulting wheel's entry points match).

`gtfobins`/`lolbas` are `.desktop` shortcuts, not clones — they just open the live sites (`gtfobins.org`, `lolbas-project.github.io`) in your default browser via `xdg-open`. No git clone, no Ruby/Jekyll toolchain: internet access is already assumed for basically everything else in this catalog, so a local build added nothing but disk and maintenance cost.

> `seclists` is a ~3.4GB clone (it's all wordlist data, no way to shrink that) — `-i seclists` will take a while and eat disk. Nothing else in the catalog is anywhere close to that size.

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
