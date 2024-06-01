#!/bin/bash
# Get current version
# Usage: get_version.sh
# Script is supposed to be run from main folder.

. $(cd "$(dirname "$(which "$0")")"/.. ; pwd -P)/tools/lib/core.sh
load_library version
if [ "$1" == "full" ] ; then
    get_full_version "${TOP_DIR}"
else
    get_version "${TOP_DIR}" "$1"
fi
