#!/usr/bin/env bash
# Anglerfish - unified package manager wrapper for pentesting toolchains
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
SYSTEMCTL="$(resolve_bin systemctl)"
IPTABLES="$(resolve_bin iptables)"
IPTABLES_SAVE="$(resolve_bin iptables-save)"
SHA256SUM="$(resolve_bin sha256sum)"
SED="$(resolve_bin sed)"
BASH_BIN="$(resolve_bin bash)"
STAT="$(resolve_bin stat)"

# Only the specific commands that need root get elevated (apt-get, writes
# under /opt, /etc, iptables, ...). Everything else - go install, jq
# lookups, check evals - runs as the invoking user, so e.g. `go install`
# lands in the real user's own $GOPATH instead of root's.
SUDO_BIN="$(resolve_bin sudo)"
ELEV=()
if [ "$(id -u)" -ne 0 ] && [ -n "$SUDO_BIN" ]; then
    ELEV=("$SUDO_BIN")
fi

# If the whole script itself was launched via `sudo ...` (SUDO_USER set),
# HOME is root's, which would send `go install` into /root/go instead of
# the real user's GOPATH. Drop back to the invoking user for go calls.
GO_AS_USER=()
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ] && [ -n "$SUDO_BIN" ]; then
    GO_AS_USER=("$SUDO_BIN" -u "$SUDO_USER" -H)
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"
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
        echo "anglerfi: cannot stat '$path', refusing privileged action" >&2
        exit 1
    }
    perm="$("$STAT" -c '%a' "$path" 2>/dev/null)"
    if [ "$owner" != "0" ]; then
        echo "anglerfi: refusing privileged action - '$path' is not owned by root (uid $owner)" >&2
        exit 1
    fi
    if [ $(( 8#$perm & 8#022 )) -ne 0 ]; then
        echo "anglerfi: refusing privileged action - '$path' is group/world-writable (mode $perm)" >&2
        exit 1
    fi
}

need_privilege() {
    if [ "$(id -u)" -ne 0 ] && [ "${#ELEV[@]}" -eq 0 ]; then
        echo "anglerfi: root privileges required and 'sudo' not found; install sudo or run as root" >&2
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

need_jq() {
    [ -n "$JQ" ] || { echo "anglerfi: jq required, run --setup or apt install jq" >&2; exit 1; }
}

ensure_state() {
    mkdir -p "$STATE_DIR"
    touch "$STATE_FILE"
}

usage() {
    cat <<'EOF'
anglerfi.sh - package manager wrapper for pentesting toolchains

Usage:
  anglerfi.sh -i, --install <package|meta>   install a package or a full meta group
  anglerfi.sh -r, --remove  <package|meta>   remove a package or a full meta group
  anglerfi.sh -l, --list [-a|--all]          list installed packages (--all: include missing ones too)
  anglerfi.sh --firewall <desktop|server>    configure iptables, persisted via iptables-persistent (desktop: allow 8000/8080, server: allow 22)
  anglerfi.sh -s, --setup                    install go/pip/pipx/cargo toolchains
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
    if "$JQ" -e --arg n "$name" '.manual[] | select(.name==$n)' "$PKG_FILE" >/dev/null; then
        echo manual; return
    fi
    echo none
}

check_installed() {
    local name="$1" kind="$2" chk
    chk="$("$JQ" -r --arg n "$name" ".$kind[] | select(.name==\$n) | .check" "$PKG_FILE")"
    eval "$chk" >/dev/null 2>&1
}

install_one() {
    local name="$1"
    local kind
    kind="$(find_kind "$name")"

    case "$kind" in
        apt)
            if check_installed "$name" apt; then
                echo "anglerfi: $name already installed (apt)"
            else
                need_privilege_from_catalog
                "${ELEV[@]}" "$APT_GET" install -y "$name"
                echo "$name" >> "$STATE_FILE"
            fi
            ;;
        go)
            if check_installed "$name" go; then
                echo "anglerfi: $name already installed (go)"
            else
                [ -n "$GO" ] || { echo "anglerfi: go not found, run --setup first" >&2; exit 1; }
                local gopkg
                gopkg="$("$JQ" -r --arg n "$name" '.go[] | select(.name==$n) | .package' "$PKG_FILE")"
                "${GO_AS_USER[@]}" "$GO" install "$gopkg"
                echo "$name" >> "$STATE_FILE"
            fi
            ;;
        manual)
            if check_installed "$name" manual; then
                echo "anglerfi: $name already installed (manual)"
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
                        echo "anglerfi: hash mismatch for '$name' (expected $expected_hash, got $actual_hash), aborting" >&2
                        exit 1
                    fi
                fi

                [ -n "$post_cmd" ] && [ "$post_cmd" != "null" ] && "${ELEV[@]}" "$BASH_BIN" -c "$post_cmd"
                echo "$name" >> "$STATE_FILE"
            fi
            ;;
        none)
            echo "anglerfi: unknown package '$name'" >&2
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
            gobin="$("${GO_AS_USER[@]}" "$GO" env GOPATH 2>/dev/null)/bin/$name"
            echo "PATH: $gobin"
            rm -f "$gobin"
            ;;
        manual)
            need_privilege_from_catalog
            local remove_cmd
            remove_cmd="$("$JQ" -r --arg n "$name" '.manual[] | select(.name==$n) | .remove' "$PKG_FILE")"
            if [ -n "$remove_cmd" ] && [ "$remove_cmd" != "null" ]; then
                "${ELEV[@]}" "$BASH_BIN" -c "$remove_cmd"
            else
                echo "anglerfi: no 'remove' command defined for '$name', falling back to /opt cleanup" >&2
                "${ELEV[@]}" rm -rf "/opt/$name"
                "${ELEV[@]}" rm -f "/usr/local/bin/$name"
            fi
            ;;
        none)
            echo "anglerfi: unknown package '$name'" >&2
            exit 1
            ;;
    esac
    "$SED" -i "/^$name\$/d" "$STATE_FILE" 2>/dev/null || true
}

resolve_targets() {
    local target="$1"
    local members
    members="$(meta_members "$target")"
    if [ -n "$members" ]; then
        echo "$members"
    else
        echo "$target"
    fi
}

cmd_install() {
    local target="$1"
    resolve_targets "$target" | while read -r pkg; do
        [ -n "$pkg" ] && install_one "$pkg"
    done
}

cmd_remove() {
    local target="$1"
    resolve_targets "$target" | while read -r pkg; do
        [ -n "$pkg" ] && remove_one "$pkg"
    done
}

cmd_list() {
    local show_all="$1"
    local kind name status
    for kind in apt go manual; do
        "$JQ" -r --arg k "$kind" '.[$k][] | .name' "$PKG_FILE" | while read -r name; do
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
            echo "anglerfi: --firewall requires 'desktop' or 'server'" >&2
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
    "${ELEV[@]}" "$APT_GET" install -y jq golang-go python3-pip pipx cargo
    JQ="$(resolve_bin jq)"
    GO="$(resolve_bin go)"
    pipx ensurepath || true
}

main() {
    ensure_state 2>/dev/null || true
    need_jq

    [ "$#" -eq 0 ] && { usage; exit 1; }

    case "$1" in
        -i|--install)
            [ -n "${2:-}" ] || { echo "anglerfi: --install requires an argument" >&2; exit 1; }
            cmd_install "$2"
            ;;
        -r|--remove)
            [ -n "${2:-}" ] || { echo "anglerfi: --remove requires an argument" >&2; exit 1; }
            cmd_remove "$2"
            ;;
        -l|--list)
            case "${2:-}" in
                -a|--all) cmd_list 1 ;;
                *) cmd_list 0 ;;
            esac
            ;;
        --firewall)
            [ -n "${2:-}" ] || { echo "anglerfi: --firewall requires 'desktop' or 'server'" >&2; exit 1; }
            cmd_firewall "$2"
            ;;
        -s|--setup)
            cmd_setup
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "anglerfi: unknown option '$1'" >&2
            usage
            exit 1
            ;;
    esac
}

main "$@"
