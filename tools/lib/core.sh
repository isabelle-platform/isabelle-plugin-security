#!/bin/bash

# Fail with error message
function fail()
{
    echo $@ 1>&2
    exit 1
}

function get_native_plat() {
    if [ "$(uname -a | grep Linux)" != "" ] ; then
        echo linux
    elif [ "$(uname -a | grep Darwin)" != "" ] ; then
        echo macos
    else
        echo win32
    fi
}

# Load a specific scripting library
function load_library()
{
    . ${TOOLS_DIR}/lib/$1.sh
    return 0
}

# Make absolute path from relative
function make_absolute()
{
    local top_dir="$1"
    local path="$2"

    echo "${top_dir}/${path}"

    return 0
}

# Export global variable
function lib_core_export_var()
{
    export ${1}="$2"
    return 0
}

# Import global variable and fail if it is not available
function lib_core_import_var()
{
    local var="$2"
    local important="$3"

    eval $1=\$$var
    val="$1"
    if [ "${val}" == "" ] && [ "${important}" == "important" ] ; then
        fail "No variable ${var} is loaded"
    fi
    return 0
}

function lib_core_normalize_bool()
{
    if [ "$1" == "1" ] ; then
        echo "yes"
    else
        echo "no"
    fi
}

function lib_core_normalize_filepath()
{
    dir="$(dirname $1)"
    if [ -z "${dir}" ] ; then
        dir=$(pwd)
    else
        cd "$(dirname $1)"
        dir=$(pwd)
    fi
    echo "${dir}/$(basename $1)"
}

# Determine project's top directory
lib_core_export_var TOP_DIR     "$(cd "$(dirname "$(which "$0")")"/.. ; pwd -P)"
lib_core_export_var TOOLS_DIR   "${TOP_DIR}/tools"
