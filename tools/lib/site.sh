#!/bin/bash

# Make up site name based on top dir
function lib_load_site()
{
    local site="$1"

    lib_core_export_var FULL_SITE_PATH "${TOP_DIR}/site/site-${site}.cmake"
    return 0
}


function lib_site_get()
{
    local site_var

    lib_core_import_var site_var FULL_SITE_PATH important
    eval $1=\${site_var}
    return 0
}

# Get component address from site
function lib_site_get_component_addr()
{
    local var="$1"
    local site="$2"
    local line

    line="$(cat "${site}" | grep "set(${var}")"
    line="$(echo $line | awk '{print $2}')"

    # Truncate extra symbols
    if [[ "$line" == *")" ]] ; then
        echo line: $line >&2
        line="${line:0:$((${#line} - 1))}"
    fi
    if [[ "$line" == "\""* ]] ; then
        line="${line:1}"
    fi
    if [[ "$line" == *"\"" ]] ; then
        line="${line:0:$((${#line} - 1))}"
    fi

    echo "$line"
    return 0
}

# Load component to the first argument
function lib_site_load_component()
{
    local var="$2"
    local site

    lib_site_get site
    eval $1=\$\(lib_site_get_component_addr "${var}" "${site}"\)
    return 0
}

# Get a platform-specific component
function lib_site_get_platform_component_var()
{
    local var="$1"
    local platform="$2"
    local site="$3"
    local name
    local new_var

    # Choose a correct platform suffix
    case "$platform" in
        linux)
            name="LINUX"
            ;;
        win32)
            name="WIN32"
            ;;
        macos)
            name="MACOS"
            ;;
        *)
            name="UNKNOWN"
            ;;
    esac

    # Test variable if site is provided
    new_var="${var}_${name}"
    if [ -n "${site}" ] ; then
        local tested="$(lib_site_get_component_addr ${new_var} ${site})"

        if [ -z "${tested}" ] ; then
            echo "${var}"
            return 0
        fi
    fi

    echo "${new_var}"
    return 0
}

# Library sanity check
function lib_site_sanity_check()
{
    local comp
    local comp_addr

    comp="$(lib_site_get_platform_component_var SITE_URL_LLVM_PREBUILT linux)"
    comp_addr=$(lib_site_get_component_addr "${comp}" "site/site-public.cmake")

    if [ "${comp_addr}" == "" ] ; then
        echo "Failed to get component address"
    fi
    return 0
}
