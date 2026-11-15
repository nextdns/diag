#!/bin/sh
# Exercises the launcher path selection without downloading or prompting.
set -eu
cd "$(dirname "$0")"
RUN_SH_LIB=1
# shellcheck disable=SC1091
. ./run.sh

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

test_darwin_reuses_one_path() {
    uname() {
        if [ "${1:-}" = "-s" ]; then
            printf '%s\n' Darwin
        else
            printf '%s\n' arm64
        fi
    }
    HOME=/tmp/nextdns-diag-test-home
    select_bin
    want="${HOME}/Library/Caches/nextdns/nextdns-diag"
    if [ "$BIN_STABLE" != 1 ] || [ "$bin_path" != "$want" ]; then
        fail "darwin path BIN_STABLE=$BIN_STABLE bin_path=$bin_path"
    fi
    if [ -e "$bin_path" ]; then
        fail "select_bin created $bin_path"
    fi
    first=$bin_path
    select_bin
    if [ "$bin_path" != "$first" ] || [ "$BIN_STABLE" != 1 ]; then
        fail "darwin path was not reused ($bin_path)"
    fi
}

test_other_os_uses_a_fresh_temp_file() {
    uname() {
        if [ "${1:-}" = "-s" ]; then
            printf '%s\n' Linux
        else
            printf '%s\n' x86_64
        fi
    }
    HOME=/tmp/nextdns-diag-test-home
    select_bin
    first=$bin_path
    case "$first" in
    *nextdns-diag-*) ;;
    *) fail "expected a mktemp name, got $first" ;;
    esac
    if [ "$BIN_STABLE" != 0 ] || [ ! -f "$first" ]; then
        fail "linux path BIN_STABLE=$BIN_STABLE file=$first"
    fi
    select_bin
    second=$bin_path
    if [ "$second" = "$first" ]; then
        fail "temp path was reused"
    fi
    rm -f "$first" "$second"
}

test_darwin_without_home_is_not_stable() {
    uname() {
        printf '%s\n' Darwin
    }
    HOME=
    select_bin
    if [ "$BIN_STABLE" != 0 ]; then
        fail "empty HOME was treated as stable ($bin_path)"
    fi
    rm -f "$bin_path"
}

test_darwin_reuses_one_path
test_other_os_uses_a_fresh_temp_file
test_darwin_without_home_is_not_stable
printf '%s\n' OK
