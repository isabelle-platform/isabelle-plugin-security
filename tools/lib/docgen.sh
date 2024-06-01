#!/bin/bash

# Cleanup the build directory
function cleanup_docgen()
{
    local build_dir="$1"

    rm -rf "${build_dir}/html"
    rm -rf "${build_dir}/latex"
    rm -rf "${build_dir}/rst"
    rm -rf "${build_dir}/xml"
    rm -rf "${build_dir}/doxyrest"
    rm -rf "${build_dir}/sphinx_theme"

    return 0
}

# Get documentation folder
function document_folder()
{
    local top_dir="$1"

    if [ -d "${top_dir}/docs" ] ; then
        echo "${top_dir}/docs"
    else
        echo "${top_dir}/doc"
    fi

    return 0
}

# Download and unpack doxyrest
function doxyrest_download()
{
    local folder="$1"
    local tmp_folder="$2"
    local doxy_path

    local plat="$(get_native_plat)"

    local comp=$(lib_site_get_platform_component_var SITE_URL_DOXYREST_PREBUILT $plat)

    lib_site_load_component doxy_path ${comp}

    if [ ! -d "${folder}" ] ; then
        wget "${doxy_path}" -O "${tmp_folder}/doxyrest.tar.xz" || \
            fail "Failed to download doxyrest"
        mkdir -p "${folder}" || \
            fail "Failed to create a folder for doxyrest"
        tar xvf "${tmp_folder}/doxyrest.tar.xz" \
            --strip-components=1 -C "${folder}" || \
            fail "Failed to unpack doxyrest"
    fi

    return 0
}

# Invoke doxyrest
function doxyrest_invoke()
{
    local doxyrest_path="$1"
    local doc_folder="$2"
    local plat="$(get_native_plat)"

    export PATH=${doxyrest_path}/bin:${PATH}

    if [ "$plat" == "linux" ] ; then
        doxyrest "--config=${doc_folder}/doxyrest-config.lua" \
               "--frame-dir=${doxyrest_path}/share/doxyrest/frame/cfamily" \
               "--frame-dir=${doxyrest_path}/share/doxyrest/frame/common" || \
        fail "Failed to get doxyrest documentation"
    else
        docker run --platform linux/amd64 \
               -w ${TOP_DIR} \
               -v ${TOP_DIR}:${TOP_DIR} \
               -it interpretica/doxyrest \
               doxyrest "--config=${doc_folder}/doxyrest-config.lua" \
               "--frame-dir=${doxyrest_path}/share/doxyrest/frame/cfamily" \
               "--frame-dir=${doxyrest_path}/share/doxyrest/frame/common" || \
        fail "Failed to get doxyrest documentation"
    fi
}

# Download theme
function theme_download()
{
    local folder="$1"
    local theme

    lib_site_load_component theme SITE_REPO_SPHINX_THEME

    if [ ! -d "${folder}" ] ; then
        git clone "${theme}" "${folder}" || \
            fail "Failed to clone theme"
        mkdir -p "${THEME_PATH}" || \
            fail "Failed to create a folder for theme"
        pushd "${folder}" > /dev/null
            cp -R -L sphinx_redactor_theme $THEME_PATH/interpretica_theme || \
                fail "Failed to move theme"
        popd > /dev/null
    fi

    return 0
}

# Copy static materials if they are present
function static_material_copy()
{
    local top_dir="$1"
    local dest="$2"
    local docs="$(document_folder ${top_dir})"

    cp -R ${docs}/sphinx/* \
          ${docs}/*.rst \
          ${docs}/*.c \
          ${docs}/*.cpp \
          ${docs}/*.txt \
          ${build_folder}/rst/ || fail "Failed to copy static materials"
    return 0
}

# Build documentation using doxygen
function doxygen_build()
{
    local build_dir="$1"

    pushd "${build_dir}" > /dev/null
    ninja doc || fail "Failed to generate documentation: $(pwd)"
    popd > /dev/null

    return 0
}

# Build documentation with Sphinx
function sphinx_build()
{
    local build_dir="$1"
    local mode="$2"
    local dev="$3"

    case "${mode}" in
        html)
            sphinx-build -b html \
                         "${build_dir}/rst" \
                         "${build_dir}/html" || \
                fail "Failed to build html documentation"
            ;;
        pdf)
            sphinx-build -M latexpdf \
                         "${build_dir}/rst" \
                         "${build_dir}/latex" || \
                fail "Failed to build pdf documentation"
            ;;
    esac
}

function documentation_merge()
{
    local name="$1"
    local build_dir="$2"
    local target_build_dir="$3"

    mkdir -p "${build_dir}/rst/${name}"
    cp -R ${target_build_dir}/rst/* "${build_dir}/rst/${name}/"
    return 0
}