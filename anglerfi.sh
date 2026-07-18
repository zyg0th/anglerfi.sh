#!/usr/bin/env bash
# Anglerfish - unified package manager wrapper for offensive security toolchains
set -euo pipefail

# Neutralize PATH hijacking: this script runs as root under sudo, so a
# malicious dir prepended to PATH must not be able to shadow any binary
# it invokes (jq, tar, wget, apt-get, ...). Pin a trusted PATH first,
# then resolve every external binary to an absolute path under it.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export DEBIAN_FRONTEND=noninteractive

resolve_bin() {
    local bin="$1"
    command -v "$bin" 2>/dev/null || true
}

JQ="$(resolve_bin jq)"
APT_GET="$(resolve_bin apt-get)"
GO="$(resolve_bin go)"
PIPX="$(resolve_bin pipx)"
GIT="$(resolve_bin git)"
SYSTEMCTL="$(resolve_bin systemctl)"
IPTABLES="$(resolve_bin iptables)"
IPTABLES_SAVE="$(resolve_bin iptables-save)"
SHA256SUM="$(resolve_bin sha256sum)"
SED="$(resolve_bin sed)"
BASH_BIN="$(resolve_bin bash)"
STAT="$(resolve_bin stat)"
READLINK="$(resolve_bin readlink)"

# Only the specific commands that need root get elevated (apt-get, writes
# under /opt, /etc, iptables, ...). Everything else - go install, jq
# lookups, check evals - runs as the invoking user, so e.g. `go install`
# lands in the real user's own $GOPATH instead of root's.
SUDO_BIN="$(resolve_bin sudo)"
ELEV=()
if [ "$(id -u)" -ne 0 ] && [ -n "$SUDO_BIN" ]; then
    ELEV=("$SUDO_BIN")
fi
SUDO_KEEPALIVE_PID=""
APT_UPDATED=0

# If the whole script itself was launched via `sudo ...` (SUDO_USER set),
# HOME is root's, which would send `go install`/`pipx install` into
# /root/go, /root/.local/... instead of the real user's own dirs. Drop
# back to the invoking user for go and pipx calls.
AS_USER=()
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && [ -n "$SUDO_BIN" ]; then
    AS_USER=("$SUDO_BIN" -u "$SUDO_USER" -H)
fi

# Canonicalize through symlinks (e.g. the `af` alias) - `stat` without -L
# reports a symlink's own mode (always 777, since Linux ignores symlink
# permission bits), not the real script's, which would make
# verify_root_owned wrongly refuse everything when invoked via a symlink.
SCRIPT_PATH="$("$READLINK" -f "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(dirname "$SCRIPT_PATH")"
if [ -n "${ANGLERFISH_PKG:-}" ]; then
    PKG_FILE="$ANGLERFISH_PKG"
elif [ -f /etc/anglerfish/package.json ]; then
    PKG_FILE="/etc/anglerfish/package.json"
else
    PKG_FILE="$SCRIPT_DIR/package.json"
fi
if [ "$(id -u)" -eq 0 ]; then
    STATE_DIR="/var/lib/anglerfish"
else
    STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/anglerfish"
fi
STATE_FILE="$STATE_DIR/installed.list"

# A low-privileged user's env var, writable config, or writable script must
# never be allowed to decide what a privileged action runs - that's a
# privesc, not a feature. Enforce root ownership + no group/other write bit
# on whatever path is passed in, right at the elevation boundary.
verify_root_owned() {
    local path="$1" owner perm
    owner="$("$STAT" -c '%u' "$path" 2>/dev/null)" || {
        echo "anglerfi.sh: cannot stat '$path', refusing privileged action" >&2
        exit 1
    }
    perm="$("$STAT" -c '%a' "$path" 2>/dev/null)"
    if [ "$owner" != "0" ]; then
        echo "anglerfi.sh: refusing privileged action - '$path' is not owned by root (uid $owner)" >&2
        exit 1
    fi
    if [ $(( 8#$perm & 8#022 )) -ne 0 ]; then
        echo "anglerfi.sh: refusing privileged action - '$path' is group/world-writable (mode $perm)" >&2
        exit 1
    fi
}

# Linux's execve() already drops set-uid/set-gid on scripts invoked via a
# #! interpreter line, but that's kernel behavior we don't control, not a
# guarantee. A setuid-root shell script is never how this tool is meant to
# gain privilege (it uses sudo, explicitly, per-command) - so if the bit is
# somehow set, refuse to run at all rather than trust the kernel silently
# neutralized it.
check_no_setuid() {
    local perm
    perm="$("$STAT" -c '%a' "$SCRIPT_PATH" 2>/dev/null)" || {
        echo "anglerfi.sh: cannot stat '$SCRIPT_PATH', refusing to run" >&2
        exit 1
    }
    if [ $(( 8#$perm & 8#6000 )) -ne 0 ]; then
        echo "anglerfi.sh: refusing to run - '$SCRIPT_PATH' has the setuid/setgid bit set (mode $perm), this is not a supported way to run anglerfi.sh" >&2
        exit 1
    fi
}

need_privilege() {
    if [ "$(id -u)" -ne 0 ] && [ "${#ELEV[@]}" -eq 0 ]; then
        echo "anglerfi.sh: root privileges required and 'sudo' not found; install sudo or run as root" >&2
        exit 1
    fi
    # If the script itself is editable by a low-privileged user, none of
    # this matters - they'd just rewrite the logic instead of the catalog.
    verify_root_owned "$SCRIPT_PATH"
}

# Like need_privilege, but also for call sites that build an elevated
# command out of PKG_FILE content (install/post_install/remove/check).
need_privilege_from_catalog() {
    need_privilege
    verify_root_owned "$PKG_FILE"
}

# apt-get update is expensive (network round trip) and every run of this
# script is a fresh process, so a plain "once per run" flag would still
# re-update every single invocation. Instead check how stale the actual
# apt cache is - apt touches /var/lib/apt/lists on every successful update
# (by us, cron, unattended-upgrades, whatever), so its mtime is the real
# source of truth, not something we need our own state file to track.
APT_UPDATE_MAX_AGE=86400
apt_cache_is_stale() {
    local stamp now
    stamp="$("$STAT" -c %Y /var/lib/apt/lists 2>/dev/null)" || return 0
    now="$(date +%s)"
    [ $(( now - stamp )) -ge "$APT_UPDATE_MAX_AGE" ]
}

kind_needs_privilege() {
    case "$1" in
        apt|git|manual) return 0 ;;
        *) return 1 ;;
    esac
}

# Scans a newline-separated package list and, if any member needs a
# privileged (apt/git/manual) install or removal, authenticates sudo once
# up front and keeps its timestamp cache alive in the background for the
# rest of the run - so a long batch doesn't stall on a re-prompt for
# whoever isn't sitting at the keyboard anymore. No-op if we're already
# root (ELEV is empty, so nothing downstream calls sudo at all).
prime_sudo_if_needed() {
    local pkg_list="$1" pkg kind needed=0
    [ "${#ELEV[@]}" -eq 0 ] && return 0
    while IFS= read -r pkg; do
        [ -n "$pkg" ] || continue
        kind="$(find_kind "$pkg")"
        if kind_needs_privilege "$kind"; then
            needed=1
            break
        fi
    done <<< "$pkg_list"
    [ "$needed" -eq 1 ] || return 0

    "${ELEV[@]}" -v
    (
        while kill -0 "$$" 2>/dev/null; do
            sleep 60
            "${ELEV[@]}" -n true 2>/dev/null
        done
    ) &
    SUDO_KEEPALIVE_PID=$!
    trap 'kill "$SUDO_KEEPALIVE_PID" 2>/dev/null' EXIT
}

need_jq() {
    [ -n "$JQ" ] || { echo "anglerfi.sh: jq required, run --setup or apt install jq" >&2; exit 1; }
}

ensure_state() {
    mkdir -p "$STATE_DIR"
    touch "$STATE_FILE"
}

usage() {
    cat <<'EOF'
anglerfi.sh - package manager wrapper for offensive security toolchains

Usage:
  anglerfi.sh -i, --install <package|meta> [-v|--version <ver>] [-pkg ...] [+pkg ...]
                                              install a package or a full meta group
                                              (-v pins a version for apt/go/pipx, only when exactly one package resolves; rejected for manual)
                                              (-pkg excludes a member from a meta group; +pkg adds an extra package to the run; both rejected for a single package)
  anglerfi.sh -r, --remove  <package|meta>   remove a package or a full meta group
  anglerfi.sh -l, --list [-a|-all|--all]      list installed packages (--all: include missing ones too)
  anglerfi.sh --firewall <desktop|server>    configure iptables, persisted via iptables-persistent (desktop: allow 8000/8080, server: allow 22)
  anglerfi.sh -s, --setup                    install go/pipx/git/cargo toolchains
  anglerfi.sh -h, --help                     show this help
EOF
}

meta_members() {
    "$JQ" -r --arg m "$1" '.meta[$m][]?' "$PKG_FILE"
}

find_kind() {
    local name="$1"
    if "$JQ" -e --arg n "$name" '.apt[] | select(.name==$n)' "$PKG_FILE" >/dev/null; then
        echo apt; return
    fi
    if "$JQ" -e --arg n "$name" '.go[] | select(.name==$n)' "$PKG_FILE" >/dev/null; then
        echo go; return
    fi
    if "$JQ" -e --arg n "$name" '.pipx[]? | select(.name==$n)' "$PKG_FILE" >/dev/null; then
        echo pipx; return
    fi
    if "$JQ" -e --arg n "$name" '.git[]? | select(.name==$n)' "$PKG_FILE" >/dev/null; then
        echo git; return
    fi
    if "$JQ" -e --arg n "$name" '.manual[] | select(.name==$n)' "$PKG_FILE" >/dev/null; then
        echo manual; return
    fi
    echo none
}

check_installed() {
    local name="$1" kind="$2" chk
    chk="$("$JQ" -r --arg n "$name" ".$kind[] | select(.name==\$n) | .check" "$PKG_FILE")"
    if eval "$chk" >/dev/null 2>&1; then
        return 0
    fi
    if [ "$kind" = go ]; then
        local gobin
        gobin="$("${AS_USER[@]}" "$GO" env GOPATH 2>/dev/null)/bin/$name"
        [ -x "$gobin" ] && return 0
    fi
    if [ "$kind" = pipx ] && [ "${#AS_USER[@]}" -gt 0 ]; then
        "${AS_USER[@]}" "$BASH_BIN" -c "$chk" >/dev/null 2>&1 && return 0
    fi
    return 1
}

install_one() {
    local name="$1" version="${2:-}"
    local kind
    kind="$(find_kind "$name")"

    case "$kind" in
        apt)
            if [ -z "$version" ] && check_installed "$name" apt; then
                echo "anglerfi.sh: $name already installed (apt)"
            else
                need_privilege_from_catalog
                local pre_cmd
                pre_cmd="$("$JQ" -r --arg n "$name" '.apt[] | select(.name==$n) | .pre_install' "$PKG_FILE")"
                if [ -n "$pre_cmd" ] && [ "$pre_cmd" != "null" ]; then
                    "${ELEV[@]}" "$BASH_BIN" -c "$pre_cmd"
                    APT_UPDATED=1
                elif [ "$APT_UPDATED" -eq 0 ] && apt_cache_is_stale; then
                    "${ELEV[@]}" "$APT_GET" update
                    APT_UPDATED=1
                fi
                if [ -n "$version" ]; then
                    "${ELEV[@]}" "$APT_GET" install -y "${name}=${version}"
                else
                    "${ELEV[@]}" "$APT_GET" install -y "$name"
                fi
                echo "$name" >> "$STATE_FILE"
            fi
            ;;
        go)
            if [ -z "$version" ] && check_installed "$name" go; then
                echo "anglerfi.sh: $name already installed (go)"
            else
                [ -n "$GO" ] || { echo "anglerfi.sh: go not found, run --setup first" >&2; exit 1; }
                local gopkg
                gopkg="$("$JQ" -r --arg n "$name" '.go[] | select(.name==$n) | .package' "$PKG_FILE")"
                [ -n "$version" ] && gopkg="${gopkg%@*}@${version}"
                "${AS_USER[@]}" "$GO" install "$gopkg"
                echo "$name" >> "$STATE_FILE"
            fi
            ;;
        pipx)
            if [ -z "$version" ] && check_installed "$name" pipx; then
                echo "anglerfi.sh: $name already installed (pipx)"
            else
                [ -n "$PIPX" ] || { echo "anglerfi.sh: pipx not found, run --setup first" >&2; exit 1; }
                local pipxpkg
                pipxpkg="$("$JQ" -r --arg n "$name" '.pipx[] | select(.name==$n) | .package' "$PKG_FILE")"
                if [ -n "$version" ]; then
                    "${AS_USER[@]}" "$PIPX" install --force "${pipxpkg%%==*}==${version}"
                else
                    "${AS_USER[@]}" "$PIPX" install "$pipxpkg"
                fi
                echo "$name" >> "$STATE_FILE"
            fi
            ;;
        git)
            if [ -z "$version" ] && check_installed "$name" git; then
                echo "anglerfi.sh: $name already installed (git)"
            else
                [ -n "$GIT" ] || { echo "anglerfi.sh: git not found, run --setup first" >&2; exit 1; }
                need_privilege_from_catalog
                local repo ref post_clone target_dir
                repo="$("$JQ" -r --arg n "$name" '.git[] | select(.name==$n) | .repo' "$PKG_FILE")"
                ref="$("$JQ" -r --arg n "$name" '.git[] | select(.name==$n) | .ref' "$PKG_FILE")"
                post_clone="$("$JQ" -r --arg n "$name" '.git[] | select(.name==$n) | .post_clone' "$PKG_FILE")"
                [ -n "$version" ] && ref="$version"
                target_dir="/opt/$name"
                "${ELEV[@]}" rm -rf "$target_dir"
                if [ -n "$ref" ] && [ "$ref" != "null" ]; then
                    "${ELEV[@]}" "$GIT" clone --quiet --depth 1 --branch "$ref" "$repo" "$target_dir"
                else
                    "${ELEV[@]}" "$GIT" clone --quiet --depth 1 "$repo" "$target_dir"
                fi
                [ -n "$post_clone" ] && [ "$post_clone" != "null" ] && "${ELEV[@]}" "$BASH_BIN" -c "$post_clone"
                echo "$name" >> "$STATE_FILE"
            fi
            ;;
        manual)
            if [ -n "$version" ]; then
                echo "anglerfi.sh: '$name' is a manual/hash-pinned install, -v/--version isn't supported - edit package.json if you need a different release" >&2
                exit 1
            fi
            if check_installed "$name" manual; then
                echo "anglerfi.sh: $name already installed (manual)"
            else
                need_privilege_from_catalog
                local install_cmd post_cmd artifact expected_hash actual_hash
                install_cmd="$("$JQ" -r --arg n "$name" '.manual[] | select(.name==$n) | .install' "$PKG_FILE")"
                post_cmd="$("$JQ" -r --arg n "$name" '.manual[] | select(.name==$n) | .post_install' "$PKG_FILE")"
                artifact="$("$JQ" -r --arg n "$name" '.manual[] | select(.name==$n) | .artifact' "$PKG_FILE")"
                expected_hash="$("$JQ" -r --arg n "$name" '.manual[] | select(.name==$n) | .hash' "$PKG_FILE")"
                "${ELEV[@]}" mkdir -p /opt
                "${ELEV[@]}" "$BASH_BIN" -c "$install_cmd"

                if [ -n "$artifact" ] && [ "$artifact" != "null" ] && [ -n "$expected_hash" ] && [ "$expected_hash" != "null" ]; then
                    actual_hash="$("$SHA256SUM" "$artifact" | cut -d' ' -f1)"
                    if [ "$actual_hash" != "$expected_hash" ]; then
                        "${ELEV[@]}" rm -f "$artifact"
                        echo "anglerfi.sh: hash mismatch for '$name' (expected $expected_hash, got $actual_hash), aborting" >&2
                        exit 1
                    fi
                fi

                [ -n "$post_cmd" ] && [ "$post_cmd" != "null" ] && "${ELEV[@]}" "$BASH_BIN" -c "$post_cmd"
                echo "$name" >> "$STATE_FILE"
            fi
            ;;
        none)
            echo "anglerfi.sh: unknown package '$name'" >&2
            exit 1
            ;;
    esac
}

remove_one() {
    local name="$1"
    local kind
    kind="$(find_kind "$name")"

    case "$kind" in
        apt)
            need_privilege_from_catalog
            "${ELEV[@]}" "$APT_GET" remove -y "$name"
            ;;
        go)
            local gobin
            gobin="$("${AS_USER[@]}" "$GO" env GOPATH 2>/dev/null)/bin/$name"
            if [ -e "$gobin" ]; then
                rm -f "$gobin"
                echo "anglerfi.sh: $name removed (go)"
            else
                echo "anglerfi.sh: $name not installed (go), nothing to remove"
            fi
            ;;
        pipx)
            [ -n "$PIPX" ] || { echo "anglerfi.sh: pipx not found" >&2; exit 1; }
            "${AS_USER[@]}" "$PIPX" uninstall "$name"
            ;;
        git)
            need_privilege_from_catalog
            local remove_cmd
            remove_cmd="$("$JQ" -r --arg n "$name" '.git[] | select(.name==$n) | .remove' "$PKG_FILE")"
            if [ -n "$remove_cmd" ] && [ "$remove_cmd" != "null" ]; then
                "${ELEV[@]}" "$BASH_BIN" -c "$remove_cmd"
            else
                "${ELEV[@]}" rm -rf "/opt/$name"
                "${ELEV[@]}" rm -f "/usr/local/bin/$name"
            fi
            ;;
        manual)
            need_privilege_from_catalog
            local remove_cmd
            remove_cmd="$("$JQ" -r --arg n "$name" '.manual[] | select(.name==$n) | .remove' "$PKG_FILE")"
            if [ -n "$remove_cmd" ] && [ "$remove_cmd" != "null" ]; then
                "${ELEV[@]}" "$BASH_BIN" -c "$remove_cmd"
            else
                echo "anglerfi.sh: no 'remove' command defined for '$name', falling back to /opt cleanup" >&2
                "${ELEV[@]}" rm -rf "/opt/$name"
                "${ELEV[@]}" rm -f "/usr/local/bin/$name"
            fi
            ;;
        none)
            echo "anglerfi.sh: unknown package '$name'" >&2
            exit 1
            ;;
    esac
    "$SED" -i "/^$name\$/d" "$STATE_FILE" 2>/dev/null || true
}

# excludes_csv/adds_csv let a meta expansion be customized per-run
# (`-i web -zaproxy +burpsuite-pro`) without editing package.json.
resolve_targets() {
    local target="$1" excludes_csv="${2:-}" adds_csv="${3:-}"
    local members ex ad ad_members
    members="$(meta_members "$target")"
    [ -n "$members" ] || members="$target"
    # Union first (target + every +pkg/+meta), then subtract -pkg from that
    # combined set - otherwise excluding something that only exists via a
    # +meta addition (e.g. `-i web +infra -nmap`, nmap isn't in web at all)
    # would silently fail to remove it.
    if [ -n "$adds_csv" ]; then
        while IFS= read -r ad; do
            if [ -n "$ad" ]; then
                # +<name> expands to every member if <name> is itself a meta
                # group (e.g. `-i web +infra`), otherwise it's a plain package.
                ad_members="$(meta_members "$ad")"
                [ -n "$ad_members" ] || ad_members="$ad"
                members="$(printf '%s\n%s' "$members" "$ad_members")"
            fi
        done <<< "$(echo "$adds_csv" | tr ',' '\n')"
    fi
    if [ -n "$excludes_csv" ]; then
        while IFS= read -r ex; do
            [ -n "$ex" ] && members="$(echo "$members" | grep -vFx "$ex")"
        done <<< "$(echo "$excludes_csv" | tr ',' '\n')"
    fi
    printf '%s\n' "$members" | grep . | sort -u || true
}

cmd_install() {
    local target="$1" version="${2:-}" excludes_csv="${3:-}" adds_csv="${4:-}"
    local resolved count
    if [ -n "$(meta_members "$target")" ]; then
        :
    elif [ -n "$excludes_csv" ] || [ -n "$adds_csv" ]; then
        echo "anglerfi.sh: -pkg/+pkg only make sense against a meta group, '$target' is a single package" >&2
        exit 1
    fi
    resolved="$(resolve_targets "$target" "$excludes_csv" "$adds_csv")"
    count="$(printf '%s\n' "$resolved" | grep -c . || true)"
    if [ "$count" -eq 0 ]; then
        echo "anglerfi.sh: nothing to install - every member of '$target' was excluded" >&2
        exit 1
    fi
    if [ -n "$version" ] && [ "$count" -ne 1 ]; then
        echo "anglerfi.sh: -v/--version only works when exactly one package is being installed (got $count for '$target')" >&2
        exit 1
    fi
    prime_sudo_if_needed "$resolved"
    local pkg failed=()
    while IFS= read -r pkg; do
        [ -n "$pkg" ] || continue
        # Run each package in its own subshell so one failure - however it
        # fails, exit or return - doesn't set -e the whole batch out from
        # under the rest of the meta group (e.g. `-i web` shouldn't skip
        # every package alphabetically after the one that broke).
        if ! ( install_one "$pkg" "$version" ); then
            failed+=("$pkg")
        fi
    done <<< "$resolved"
    if [ "${#failed[@]}" -gt 0 ]; then
        echo "anglerfi.sh: failed to install: ${failed[*]}" >&2
        exit 1
    fi
}

cmd_remove() {
    local target="$1" resolved
    resolved="$(resolve_targets "$target")"
    prime_sudo_if_needed "$resolved"
    local pkg failed=()
    while IFS= read -r pkg; do
        [ -n "$pkg" ] || continue
        if ! ( remove_one "$pkg" ); then
            failed+=("$pkg")
        fi
    done <<< "$resolved"
    if [ "${#failed[@]}" -gt 0 ]; then
        echo "anglerfi.sh: failed to remove: ${failed[*]}" >&2
        exit 1
    fi
}

cmd_list() {
    local show_all="$1"
    local kind name status
    for kind in apt go pipx git manual; do
        "$JQ" -r --arg k "$kind" '.[$k][]? | .name' "$PKG_FILE" | while read -r name; do
            [ -n "$name" ] || continue
            if check_installed "$name" "$kind"; then
                status="installed"
            else
                status="missing"
                [ "$show_all" = "1" ] || continue
            fi
            printf "%-20s %-8s %s\n" "$name" "$kind" "$status"
        done
    done
}

cmd_firewall() {
    case "$1" in
        desktop|server) : ;;
        *)
            echo "anglerfi.sh: --firewall requires 'desktop' or 'server'" >&2
            exit 1
            ;;
    esac
    need_privilege

    if [ -z "$IPTABLES" ]; then
        "${ELEV[@]}" "$APT_GET" install -y iptables
        IPTABLES="$(resolve_bin iptables)"
    fi
    "${ELEV[@]}" "$APT_GET" install -y iptables-persistent >/dev/null 2>&1 || true
    IPTABLES_SAVE="$(resolve_bin iptables-save)"

    "${ELEV[@]}" "$IPTABLES" -F
    "${ELEV[@]}" "$IPTABLES" -X
    "${ELEV[@]}" "$IPTABLES" -P INPUT DROP
    "${ELEV[@]}" "$IPTABLES" -P FORWARD DROP
    "${ELEV[@]}" "$IPTABLES" -P OUTPUT ACCEPT
    "${ELEV[@]}" "$IPTABLES" -A INPUT -i lo -j ACCEPT
    "${ELEV[@]}" "$IPTABLES" -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    case "$1" in
        desktop)
            "${ELEV[@]}" "$IPTABLES" -A INPUT -p tcp --dport 8000 -j ACCEPT
            "${ELEV[@]}" "$IPTABLES" -A INPUT -p tcp --dport 8080 -j ACCEPT
            ;;
        server)
            "${ELEV[@]}" "$IPTABLES" -A INPUT -p tcp --dport 22 -j ACCEPT
            ;;
    esac

    "${ELEV[@]}" mkdir -p /etc/iptables
    # redirection must happen inside the elevated shell, not the caller's,
    # or writing to /etc/iptables/rules.v4 fails before sudo even runs
    "${ELEV[@]}" "$BASH_BIN" -c "\"$IPTABLES_SAVE\" > /etc/iptables/rules.v4"
    if [ -n "$SYSTEMCTL" ]; then
        "${ELEV[@]}" "$SYSTEMCTL" enable netfilter-persistent >/dev/null 2>&1 || true
    fi
}

cmd_setup() {
    need_privilege
    "${ELEV[@]}" "$APT_GET" update
    "${ELEV[@]}" "$APT_GET" install -y jq golang-go pipx git cargo
    JQ="$(resolve_bin jq)"
    GO="$(resolve_bin go)"
    PIPX="$(resolve_bin pipx)"
    GIT="$(resolve_bin git)"
    "$PIPX" ensurepath || true
}

main() {
    check_no_setuid
    ensure_state 2>/dev/null || true
    need_jq

    [ "$#" -eq 0 ] && { usage; exit 1; }

    case "$1" in
        -i|--install)
            [ -n "${2:-}" ] || { echo "anglerfi.sh: --install requires an argument" >&2; exit 1; }
            local install_target="$2" install_version="" install_excludes="" install_adds=""
            shift 2
            while [ "$#" -gt 0 ]; do
                case "$1" in
                    -v|--version)
                        [ -n "${2:-}" ] || { echo "anglerfi.sh: -v/--version requires an argument" >&2; exit 1; }
                        install_version="$2"
                        shift 2
                        ;;
                    -?*)
                        install_excludes="${install_excludes:+$install_excludes,}${1#-}"
                        shift
                        ;;
                    +?*)
                        install_adds="${install_adds:+$install_adds,}${1#+}"
                        shift
                        ;;
                    *)
                        echo "anglerfi.sh: unexpected argument '$1' after --install" >&2
                        exit 1
                        ;;
                esac
            done
            cmd_install "$install_target" "$install_version" "$install_excludes" "$install_adds"
            ;;
        -r|--remove)
            [ -n "${2:-}" ] || { echo "anglerfi.sh: --remove requires an argument" >&2; exit 1; }
            cmd_remove "$2"
            ;;
        -l|--list)
            case "${2:-}" in
                -a|-all|--all) cmd_list 1 ;;
                *) cmd_list 0 ;;
            esac
            ;;
        --firewall)
            [ -n "${2:-}" ] || { echo "anglerfi.sh: --firewall requires 'desktop' or 'server'" >&2; exit 1; }
            cmd_firewall "$2"
            ;;
        -s|--setup)
            cmd_setup
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "anglerfi.sh: unknown option '$1'" >&2
            usage
            exit 1
            ;;
    esac
}

main "$@"
