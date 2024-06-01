#!/bin/bash

function get_version()
{
	local top_dir="$1"
	local verkind="$2"

	if [ -n "${verkind}" ] ; then
		cat ${top_dir}/tools/_version_$verkind
	else
		echo $(get_version ${top_dir} major).$(get_version ${top_dir} minor).$(get_version ${top_dir} patchlevel)
	fi
}

function get_mods()
{
    local top_dir="$1"
    cd "${top_dir}" || return 1
    git diff-index --quiet HEAD -- || echo "/mod"
    return 0
}

function get_commit_hash()
{
    local top_dir="$1"
    cd "${top_dir}" || return 1
    echo $(git rev-parse --short HEAD)
    return 0
}

function get_full_version()
{
	local top_dir="$1"

	echo $(get_version "${top_dir}")-$(get_commit_hash "${top_dir}")
}