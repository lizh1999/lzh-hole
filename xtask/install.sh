#!/bin/bash
# Offline macOS/arm64 installer. No downloads, pairing, state reset or network setup.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077

BUNDLE=$(cd -- "$(dirname -- "$BASH_SOURCE")" && pwd -P)
BIN=/usr/local/libexec/lzh-hole
CONFIG=/etc/lzh-hole/config.toml
EXAMPLE=/etc/lzh-hole/config.toml.example
STATE=/var/db/lzh-hole
SOCKET=/var/run/lzh-hole/control.sock
PLIST=/Library/LaunchDaemons/com.lzhhole.daemon.plist
LABEL=system/com.lzhhole.daemon
LAUNCHCTL=/bin/launchctl
IFCONFIG=/sbin/ifconfig
NETSTAT=/usr/sbin/netstat
ROUTE=/sbin/route
STOP_TIMEOUT=30
START_TIMEOUT=20
DRY_RUN=0
YES=0
ENABLE=0
ALLOW_TUN=0
WORK=
KEEP_BACKUP=0
HAD_BIN=0
WAS_LOADED=0
STOP_REQUESTED=0
REPLACED=0
START_ATTEMPTED=0
NEW_PLIST=0
NEW_EXAMPLE=0
COMMITTED=0
OLD_PID=
OLD_TUN=
PEER=

say() { printf '%s\n' "$*"; }
fail() { say "install: $*" >&2; return 1; }
is_root() { [[ $EUID -eq 0 ]]; }
field() { printf '%s\n' "$1" | /usr/bin/plutil -extract "$2" raw -o - -; }
hash_file() { /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'; }
service_loaded() { "$LAUNCHCTL" print "$LABEL" >/dev/null 2>&1; }
process_alive() { [[ -n "$OLD_PID" ]] && kill -0 "$OLD_PID" 2>/dev/null; }
install_file() { /usr/bin/install -m "$1" -o root -g wheel "$2" "$3"; }

usage() {
    say 'Usage: ./install.sh [--dry-run] [--yes] [--enable-service --allow-tun]'
    say 'Default: install binary + example only; restart an already loaded service on upgrade.'
    say 'First service registration/start requires both explicit flags and completed pairing/config.'
    say 'No config/state overwrite, pairing, downloads, quarantine removal or network fallback.'
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=1 ;;
            --yes) YES=1 ;;
            --enable-service) ENABLE=1 ;;
            --allow-tun) ALLOW_TUN=1 ;;
            -h|--help) usage; return 2 ;;
            *) fail "unknown argument: $1"; return 1 ;;
        esac
        shift
    done
    [[ $ENABLE -eq $ALLOW_TUN ]] || { fail '--enable-service and --allow-tun must be supplied together'; return 1; }
}

verify_bundle() {
    local name
    for name in install.sh lzh-hole config.toml.example com.lzhhole.daemon.plist manifest.json SHA256SUMS; do
        [[ -f "$BUNDLE/$name" && ! -L "$BUNDLE/$name" ]] || { fail "missing or symlink payload: $name"; return 1; }
        [[ $(/usr/bin/stat -f %l "$BUNDLE/$name") = 1 ]] || { fail "hard-linked payload: $name"; return 1; }
    done
    # Never let an edited checksum list read arbitrary paths or omit a payload.
    /usr/bin/awk '
        BEGIN {split("install.sh lzh-hole config.toml.example com.lzhhole.daemon.plist manifest.json", names, " ")}
        NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-f]/ || $2 != names[NR] {bad=1}
        END {exit (bad || NR != 5)}
    ' "$BUNDLE/SHA256SUMS" || { fail 'invalid checksum file'; return 1; }
    (cd -- "$BUNDLE" && /usr/bin/shasum -a 256 -c SHA256SUMS) || { fail 'payload checksum failed'; return 1; }
    MANIFEST=$(<"$BUNDLE/manifest.json")
    [[ $(field "$MANIFEST" package) = lzh-hole && $(field "$MANIFEST" target) = aarch64-apple-darwin ]] || { fail 'wrong package or target'; return 1; }
    VERSION=$(field "$MANIFEST" version) || return 1
    EXPECTED_HASH=$(hash_file "$BUNDLE/lzh-hole")
    EXPECTED_CONFIG_HASH=$(hash_file "$BUNDLE/config.toml.example")
    EXPECTED_PLIST_HASH=$(hash_file "$BUNDLE/com.lzhhole.daemon.plist")
}

platform_check() {
    [[ $(/usr/bin/uname -s) = Darwin && $(/usr/bin/uname -m) = arm64 ]] || { fail 'Apple Silicon macOS is required'; return 1; }
    local minimum current tool
    minimum=$(field "$MANIFEST" minimum_macos) || return 1
    [[ "$minimum" =~ ^[0-9]+(\.[0-9]+){1,2}$ ]] || { fail 'invalid minimum macOS version'; return 1; }
    current=$(/usr/bin/sw_vers -productVersion)
    /usr/bin/awk -v have="$current" -v need="$minimum" 'BEGIN {
        split(have,h,"."); split(need,n,"."); for(i=1;i<=3;i++){if(h[i]+0>n[i]+0)exit 0;if(h[i]+0<n[i]+0)exit 1} exit 0
    }' || { fail "macOS $minimum or later is required by this binary"; return 1; }
    for tool in "$LAUNCHCTL" "$IFCONFIG" "$NETSTAT" "$ROUTE" /usr/bin/plutil /usr/bin/install /usr/bin/stat; do
        [[ -x "$tool" ]] || { fail "missing system tool: $tool"; return 1; }
    done
}

safe_path() {
    local path=$1 cursor target
    [[ "$path" = /* && "$path" != *'/../'* && "$path" != */.. && "$path" != *'/./'* ]] || { fail "unsafe path: $path"; return 1; }
    cursor=$path
    while [[ "$cursor" != / ]]; do
        if [[ -L "$cursor" ]]; then
            target=$(/usr/bin/readlink "$cursor")
            # These two OS-owned aliases are part of macOS's standard layout.
            if [[ "$cursor" = /etc && "$target" = private/etc ]] || [[ "$cursor" = /var && "$target" = private/var ]]; then :
            else fail "refusing symlink: $cursor"; return 1; fi
        fi
        cursor=$(/usr/bin/dirname "$cursor")
    done
}

secure_parent() {
    local cursor mode
    cursor=$(/usr/bin/dirname "$1")
    while [[ "$cursor" != / ]]; do
        if [[ -e "$cursor" ]]; then
            [[ -d "$cursor" && $(/usr/bin/stat -Lf %u "$cursor") = 0 ]] || { fail "parent not root-owned directory: $cursor"; return 1; }
            mode=$(/usr/bin/stat -Lf %Lp "$cursor")
            (( (8#$mode & 0022) == 0 )) || { fail "writable installation parent: $cursor"; return 1; }
        fi
        cursor=$(/usr/bin/dirname "$cursor")
    done
}

destination_check() {
    local path
    for path in "$BIN" "$CONFIG" "$EXAMPLE" "$PLIST" "$STATE" "$SOCKET"; do safe_path "$path" || return 1; done
    for path in "$BIN" "$CONFIG" "$EXAMPLE" "$PLIST"; do
        secure_parent "$path" || return 1
        if [[ -e "$path" ]]; then
            [[ -f "$path" && $(/usr/bin/stat -f %l "$path") = 1 && $(/usr/bin/stat -f %u "$path") = 0 ]] || { fail "unsafe existing file: $path"; return 1; }
            local mode
            mode=$(/usr/bin/stat -f %Lp "$path")
            (( (8#$mode & 0022) == 0 )) || { fail "writable existing file: $path"; return 1; }
        fi
    done
}

validate_plist() {
    [[ -f "$PLIST" ]] || { fail 'loaded service has no plist'; return 1; }
    local json i expected program
    json=$(/usr/bin/plutil -convert json -o - "$PLIST") || return 1
    # launchd uses Program instead of ProgramArguments[0] when it is present.
    if program=$(field "$json" Program 2>/dev/null); then
        [[ "$program" = "$BIN" ]] || { fail 'custom Program would execute a different binary; refusing upgrade'; return 1; }
    fi
    [[ $(field "$json" Label) = com.lzhhole.daemon && $(field "$json" WorkingDirectory) = "$STATE" ]] || { fail 'custom service layout requires manual upgrade'; return 1; }
    i=0
    for expected in "$BIN" daemon --config "$CONFIG" --allow-tun; do
        [[ $(field "$json" "ProgramArguments.$i") = "$expected" ]] || { fail 'custom service arguments require manual upgrade'; return 1; }
        i=$((i+1))
    done
    if field "$json" ProgramArguments.5 >/dev/null 2>&1; then fail 'unexpected service arguments'; return 1; fi
}

preflight() {
    local json
    json=$("$WORK/new-bin" doctor --preflight --config "$CONFIG") || { fail 'offline config/pairing preflight failed; service untouched'; return 1; }
    [[ $(field "$json" state_dir) = "$STATE" && $(field "$json" control_socket) = "$SOCKET" ]] || { fail 'nonstandard state/socket layout requires manual installation'; return 1; }
    PEER=$(field "$json" peer_vip) || return 1
    [[ "$PEER" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { fail 'invalid preflight peer'; return 1; }
}

capture_instance() {
    local json detail
    json=$("$BIN" doctor --socket "$SOCKET") || return 1
    [[ $(field "$json" report.daemon.state) = running ]] || return 1
    OLD_PID=$(field "$json" report.daemon.pid) || return 1
    [[ "$OLD_PID" =~ ^[1-9][0-9]*$ ]] || return 1
    detail=$(field "$json" report.tun.detail) || return 1
    [[ "$detail" =~ ^actual\ (utun[0-9]+)\  ]] || return 1
    OLD_TUN=${BASH_REMATCH[1]}
}

route_present() {
    [[ -n "$PEER" ]] || return 1
    local routes
    routes=$("$NETSTAT" -rn -f inet) || return 2
    printf '%s\n' "$routes" | /usr/bin/awk -v peer="$PEER" '$1==peer || $1==peer"/32" {found=1} END {exit !found}'
}

wait_clean() {
    local deadline=$((SECONDS+STOP_TIMEOUT)) pending rc
    while :; do
        pending=0
        if process_alive || [[ -e "$SOCKET" || -S "$SOCKET" ]]; then pending=1; fi
        if [[ -n "$OLD_TUN" ]] && "$IFCONFIG" "$OLD_TUN" >/dev/null 2>&1; then pending=1; fi
        if route_present; then pending=1; else rc=$?; [[ $rc -eq 1 ]] || return 1; fi
        [[ $pending -eq 0 ]] && return 0
        (( SECONDS < deadline )) || { fail 'stop cleanup timed out; no resources will be deleted'; return 1; }
        /bin/sleep 1
    done
}

wait_ready() {
    local deadline=$((SECONDS+START_TIMEOUT)) json pid
    while :; do
        if service_loaded && json=$("$BIN" doctor --socket "$SOCKET" 2>/dev/null); then
            if [[ $(field "$json" report.daemon.state 2>/dev/null) = running && $(field "$json" report.tun.state 2>/dev/null) = healthy && $(field "$json" report.routes.state 2>/dev/null) = healthy ]]; then
                pid=$(field "$json" report.daemon.pid) || return 1
                [[ "$pid" =~ ^[1-9][0-9]*$ ]] && return 0
            fi
        fi
        (( SECONDS < deadline )) || { fail 'daemon readiness timed out (peer reachability is not required)'; return 1; }
        /bin/sleep 1
    done
}

rollback() {
    say 'Installation failed; restoring the previous binary/service state.' >&2
    if [[ $START_ATTEMPTED -eq 1 ]] && service_loaded; then
        # A starting daemon might not yet have a doctor socket. Capture its PID
        # from launchd; process exit closes its utun descriptor in the kernel.
        if ! capture_instance; then
            local status
            status=$("$LAUNCHCTL" print "$LABEL") || return 1
            OLD_PID=$(printf '%s\n' "$status" | /usr/bin/awk '$1=="pid" && $2=="=" && $3 ~ /^[1-9][0-9]*$/ {print $3;exit}')
            OLD_TUN=
        fi
        "$LAUNCHCTL" bootout "$LABEL" || return 1
    fi
    if [[ $STOP_REQUESTED -eq 1 || $START_ATTEMPTED -eq 1 ]]; then wait_clean || return 1; fi
    if [[ $REPLACED -eq 1 ]]; then
        safe_path "$BIN" || return 1
        if [[ $HAD_BIN -eq 1 ]]; then /bin/mv -f "$WORK/old-bin" "$BIN" || return 1
        else /bin/rm -f "$BIN" || return 1; fi
    fi
    if [[ $NEW_PLIST -eq 1 ]]; then /bin/rm -f "$PLIST" || return 1; fi
    if [[ $NEW_EXAMPLE -eq 1 ]]; then /bin/rm -f "$EXAMPLE" || return 1; fi
    if [[ $WAS_LOADED -eq 1 && $STOP_REQUESTED -eq 1 ]] && ! service_loaded; then
        "$LAUNCHCTL" bootstrap system "$PLIST" || return 1
        wait_ready || return 1
    fi
    say 'Previous binary/service state restored; private state was not rolled back.' >&2
}

finish() {
    local rc=$?
    trap - EXIT INT TERM
    if [[ $rc -ne 0 && $COMMITTED -eq 0 && ( $STOP_REQUESTED -eq 1 || $REPLACED -eq 1 || $NEW_PLIST -eq 1 || $NEW_EXAMPLE -eq 1 ) ]]; then
        if ! rollback; then KEEP_BACKUP=1; say "AUTOMATIC ROLLBACK FAILED. Backup retained at: $WORK" >&2; fi
    fi
    if [[ -n "$WORK" && $KEEP_BACKUP -eq 0 ]]; then /bin/rm -rf -- "$WORK" || rc=1; fi
    exit "$rc"
}

perform_install() {
    local bin_dir config_dir
    bin_dir=$(/usr/bin/dirname "$BIN")
    config_dir=$(/usr/bin/dirname "$CONFIG")
    [[ -d "$bin_dir" ]] || /usr/bin/install -d -m 0755 "$bin_dir"
    [[ -d "$config_dir" ]] || /usr/bin/install -d -m 0755 "$config_dir"
    WORK="$bin_dir/.lzh-hole-install.lock"
    /bin/mkdir -m 0700 "$WORK" || { WORK=; fail 'another installer or retained recovery backup exists'; return 1; }
    trap finish EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # Stage on the destination filesystem and verify before stopping anything.
    install_file 0755 "$BUNDLE/lzh-hole" "$WORK/new-bin"
    [[ $(hash_file "$WORK/new-bin") = "$EXPECTED_HASH" ]] || { fail 'staged binary checksum failed'; return 1; }
    install_file 0644 "$BUNDLE/config.toml.example" "$WORK/new-example"
    install_file 0644 "$BUNDLE/com.lzhhole.daemon.plist" "$WORK/new-plist"
    [[ $(hash_file "$WORK/new-example") = "$EXPECTED_CONFIG_HASH" && $(hash_file "$WORK/new-plist") = "$EXPECTED_PLIST_HASH" ]] || { fail 'staged template checksum failed'; return 1; }
    /usr/bin/plutil -lint "$WORK/new-plist"
    if [[ -e "$BIN" ]]; then HAD_BIN=1; /bin/cp -p "$BIN" "$WORK/old-bin"; fi
    if service_loaded; then WAS_LOADED=1; fi
    if [[ $WAS_LOADED -eq 1 || $ENABLE -eq 1 ]]; then
        preflight || return 1
        if [[ -e "$PLIST" ]]; then validate_plist || return 1
        elif [[ $WAS_LOADED -eq 1 ]]; then fail 'loaded service has no installed plist'; return 1; fi
    fi
    if [[ $WAS_LOADED -eq 1 ]]; then
        capture_instance || { fail 'cannot safely snapshot existing instance; refusing to stop it'; return 1; }
        STOP_REQUESTED=1
        "$LAUNCHCTL" bootout "$LABEL"
        wait_clean || return 1
    elif [[ -e "$SOCKET" || -S "$SOCKET" ]]; then
        fail 'unloaded service left a control socket; investigate without deleting it'; return 1
    fi
    safe_path "$BIN"
    REPLACED=1
    /bin/mv -f "$WORK/new-bin" "$BIN"
    [[ $(hash_file "$BIN") = "$EXPECTED_HASH" ]] || { fail 'installed binary checksum failed'; return 1; }
    if [[ ! -e "$EXAMPLE" ]]; then
        NEW_EXAMPLE=1
        install_file 0644 "$WORK/new-example" "$EXAMPLE"
    fi
    if [[ $ENABLE -eq 1 && ! -e "$PLIST" ]]; then
        NEW_PLIST=1
        /bin/mv -f "$WORK/new-plist" "$PLIST"
    fi
    if [[ $WAS_LOADED -eq 1 || $ENABLE -eq 1 ]]; then
        START_ATTEMPTED=1
        "$LAUNCHCTL" bootstrap system "$PLIST"
        wait_ready || return 1
    fi
    COMMITTED=1
    say "Installed lzh-hole $VERSION: $BIN"
    if [[ $WAS_LOADED -eq 1 || $ENABLE -eq 1 ]]; then
        say 'Daemon ready. This does NOT certify peer health, TCP/UDP/ICMP or P0.'
        "$BIN" doctor --socket "$SOCKET" || true
    else
        say 'Service not started. Initialize/pair separately, configure management_uid and relationship-specific ntfy topic.'
        say "Configuration example: $EXAMPLE (existing config/state preserved)."
        say 'After pairing/configuration, explicitly run: ./install.sh --enable-service --allow-tun'
    fi
}

main() {
    local rc=0 answer
    parse_args "$@" || rc=$?
    [[ $rc -eq 2 ]] && return 0
    [[ $rc -eq 0 ]] || return "$rc"
    verify_bundle
    platform_check
    [[ $("$BUNDLE/lzh-hole" --version) = "lzh-hole $VERSION" ]] || { fail 'binary version differs from manifest'; return 1; }
    destination_check
    say "Package: lzh-hole $VERSION; install location: $BIN"
    if service_loaded; then
        say 'Plan: upgrade and RESTART the existing system service (temporarily interrupts the overlay).'
    elif [[ $ENABLE -eq 1 ]]; then
        say 'Plan: register/start system launchd service; allow dedicated utun and peer /32 route.'
    else
        say 'Plan: install binary/example only; do NOT register/start service or create a TUN.'
    fi
    say 'Existing configuration, identity, pairing, sequence, peer high-water and ntfy pacing are preserved.'
    [[ $DRY_RUN -eq 1 ]] && { say 'Dry run: no sudo, writes, service changes or preflight access to private state.'; return 0; }
    if [[ $YES -eq 0 ]]; then
        [[ -t 0 ]] || { fail 'noninteractive use requires explicit --yes'; return 1; }
        printf 'Proceed? [y/N] '
        IFS= read -r answer || return 1
        [[ "$answer" = y || "$answer" = Y ]] || { fail 'cancelled'; return 1; }
    fi
    if ! is_root; then
        local args=(--yes)
        [[ $ENABLE -eq 0 ]] || args+=(--enable-service --allow-tun)
        exec /usr/bin/sudo /bin/bash "$BUNDLE/install.sh" "${args[@]}"
    fi
    # Recheck after elevation, and avoid restarting a byte-identical installation.
    destination_check
    if [[ $ENABLE -eq 0 && -f "$BIN" && -f "$EXAMPLE" && $(hash_file "$BIN") = "$EXPECTED_HASH" ]]; then
        say 'Same binary already installed; no service restart or state changes.'
        return 0
    fi
    perform_install
}

# Sourcing is used only by isolated mock tests; there is no environment-based test mode.
if [[ "$BASH_SOURCE" = "$0" ]]; then main "$@"; fi
