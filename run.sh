#!/bin/sh

main() {
    set -e

    echo
    echo "Welcome to NextDNS network diagnostic tool."
    echo
    echo "This tool will download a small binary to capture latency and routing information"
    echo "regarding the connectivity of your network with NextDNS. In order to perform a"
    echo "traceroute, root permission is required. You may therefore be asked to provide"
    echo "your password for sudo."
    echo
    echo "The source code of this tool is available at https://github.com/nextdns/diag"
    echo
    printf "Do you want to continue? (press enter to accept)"
    read -r _

    GOARCH=$(detect_goarch)
    GOOS=$(detect_goos)
    RELEASE=$(get_release)

    url="https://github.com/nextdns/diag/releases/download/v${RELEASE}/diag_${RELEASE}_${GOOS}_${GOARCH}"
    bin_path=/tmp/nextdns-diag-$$
    trap cleanup EXIT
    curl -sL "$url" > "$bin_path"
    chmod 755 "$bin_path"
    asroot "$bin_path"
}

cleanup() {
    rm -f "$bin_path"
}

detect_goarch() {
    if [ "$FORCE_GOARCH" ]; then
        echo "$FORCE_GOARCH"; return 0
    fi
    case $(uname -m) in
    x86_64|amd64)
        echo "amd64"
        ;;
    i386|i686)
        echo "386"
        ;;
    arm)
        # Freebsd does not include arm version
        case "$(sysctl -b hw.model 2>/dev/null)" in
        *A9*)
            echo "armv7"
            ;;
        *)
            # Unknown version, fallback to the lowest
            echo "armv5"
            ;;
        esac
        ;;
    armv5*)
        echo "armv5"
        ;;
    armv6*|armv7*)
        if grep -q vfp /proc/cpuinfo 2>/dev/null; then
            echo "armv$(uname -m | sed -e 's/[[:alpha:]]//g')"
        else
            # Soft floating point
            echo "armv5"
        fi
        ;;
    aarch64)
        case "$(uname -o 2>/dev/null)" in
        ASUSWRT-Merlin*)
            # XXX when using arm64 build on ASUS AC66U and ACG86U, we get Go error:
            # "out of memory allocating heap arena metadata".
            echo "armv7"
            ;;
        *)
            echo "arm64"
            ;;
        esac
        ;;
    armv8*|arm64)
        echo "arm64"
        ;;
    mips*)
        # TODO: detect hardfloat
        echo "$(uname -m)$(detect_endiannes)_softfloat"
        ;;
    *)
        log_error "Unsupported GOARCH: $(uname -m)"
        return 1
        ;;
    esac
}

detect_goos() {
    if [ "$FORCE_GOOS" ]; then
        echo "$FORCE_GOOS"; return 0
    fi
    case $(uname -s) in
    Linux)
        echo "linux"
        ;;
    Darwin)
        echo "darwin"
        ;;
    FreeBSD)
        echo "freebsd"
        ;;
    NetBSD)
        echo "netbsd"
        ;;
    OpenBSD)
        echo "openbsd"
        ;;
    *)
        log_error "Unsupported GOOS: $(uname -s)"
        return 1
    esac
}

get_release() {
    out=$(curl -A curl -s "https://api.github.com/repos/nextdns/diag/releases/latest")
    v=$(echo "$out" | grep '"tag_name":' | esed 's/.*"([^"]+)".*/\1/' | sed -e 's/^v//')
    if [ -z "$v" ]; then
        log_error "Cannot get latest version: $out"
    fi
    echo "$v"
}

esed() {
    if (echo | sed -E '' >/dev/null 2>&1); then
        sed -E "$@"
    else
        sed -r "$@"
    fi
}

asroot() {
    # Some platform (merlin) do not have the "id" command and $USER report a non root username with uid 0.
    if [ "$(grep '^Uid:' /proc/$$/status 2>/dev/null|cut -f2)" = "0" ] || [ "$USER" = "root" ] || [ "$(id -u 2>/dev/null)" = "0" ]; then
        "$@"
    elif [ "$(command -v sudo 2>/dev/null)" ]; then
        sudo "$@"
    else
        echo "Root required"
        su -m root -c "$*"
    fi
}

log_error() {
    printf "\033[31mERROR: %s\033[0m\n" "$*" >&2
}

main
