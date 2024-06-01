#!/bin/bash

toolchain_url="https://opensource.interpretica.io/toolchain"

linux_win32_toolchain_filename="llvm-mingw-20220323-ucrt-ubuntu-18.04-x86_64.tar.xz"
macos_win32_toolchain_filename="llvm-mingw-20220323-ucrt-macos-universal.tar.xz"
linux_macos_toolchain_filename="llvm-osxcross-ubuntu-x86_64.tar.xz"
unix_win32_toolchain_def="unix-mingw32.cmake"
unix_macos_toolchain_def="unix-macos.cmake"

function get_native_arch() {
    if [ "$(uname -a | grep arm64)" != "" ] ; then
        echo arm64
    else
        echo x86_64
    fi
}

function get_toolchain() {
    local target_plat="$1"
    local target_arch="$2"

    local native_plat="$(get_native_plat)"
    local native_arch="$(get_native_arch)"
    local tc=""

    if [ "$target_plat" == "" ] ; then
        target_plat="${native_plat}"
    fi

    if [ "$target_arch" == "" ] ; then
        if [ "$target_plat" == "win32" ] ; then
            target_arch="x86_64"
        else
            target_arch="$(get_native_arch)"
        fi
    fi

    tc="${native_plat}_${native_arch}_${target_plat}_${target_arch}"
    echo "$tc"
}

function get_toolchain_url() {
    local tc="$1"

    case "$tc" in
        linux_x86_64_macos_x86_64|linux_x86_64_macos_arm64)
            # Give osxcross built for Linux
            echo "${toolchain_url}/${linux_macos_toolchain_filename}"
            ;;
        macos_x86_64_win32_x86_64|macos_arm64_win32_x86_64)
            # Give universal MacOS -> Win32 toolchain
            echo "${toolchain_url}/${macos_win32_toolchain_filename}"
            ;;
        linux_x86_64_win32_x86_64)
            # Give MinGW clang toolchain
            echo "${toolchain_url}/${linux_win32_toolchain_filename}"
            ;;
        macos_arm64_macos_arm64|macos_arm64_macos_x86_64|macos_x86_64_macos_arm64|macos_x86_64_macos_x86_64)
            # Native Mac - toolchain is not needed
            echo ""
            ;;
        linux_x86_64_linux_x86_64)
            # Native Linux - toolchain is not needed
            echo ""
            ;;
        *)
            echo "Unsupported toolchain" >&2
            return 1
            ;;
    esac

    return 0
}

function get_toolchain_def() {
    local tc="$1"

    case "$tc" in
        linux_x86_64_macos_arm64|linux_x86_64_macos_x86_64)
            # Build for MacOS on Linux
            echo $unix_macos_toolchain_def
            ;;
        macos_x86_64_win32_x86_64|macos_arm64_win32_x86_64|linux_x86_64_win32_x86_64)
            # Build for Windows
            # For MacOS host, we use universal MinGW toolchain
            # For Linux host, we use MinGW Clang toolchain
            echo $unix_win32_toolchain_def
            ;;
        linux_x86_64_linux_x86_64)
            # Same Linux platform, nothing special is needed
            echo ""
            ;;
        macos_x86_64_macos_x86_64|macos_arm64_macos_arm64)
            # Same MacOS platform, nothing special needed
            echo ""
            ;;
        macos_x86_64_macos_arm64|macos_arm64_macos_x86_64)
            # Cross MacOS platform, nothing special is needed
            echo ""
            ;;
        *)
            echo "Unsupported toolchain" >&2
            return 1
            ;;
    esac

    return 0
}

function get_toolchain_osx_archs() {
    local tc="$1"

    case "$tc" in
        macos_x86_64_macos_arm64|macos_arm64_macos_arm64|linux_x86_64_macos_arm64)
            echo "arm64"
            ;;
        macos_arm64_macos_x86_64|macos_x86_64_macos_x86_64|linux_x86_64_macos_x86_64)
            # Cross MacOS platform, nothing special is needed
            echo "x86_64"
            ;;
        *)
            echo ""
            ;;
    esac

    return 0
}