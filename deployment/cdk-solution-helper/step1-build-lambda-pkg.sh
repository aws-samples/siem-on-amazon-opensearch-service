#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

source_template_dir="${PWD}/.."
source_dir="$source_template_dir/../source"

if ! (python3 -m pip > /dev/null 2>&1); then
    echo "No pip3. Install python3."
    echo "exist!"
    exit
fi

echo "------------------------------------------------------------------------------"
echo "[Packing] pip and Source Folder"
echo "------------------------------------------------------------------------------"
python3 -m pip install wheel pip==21.1.3 --user > /tmp/siem.log 2>&1
is_in_pyenv=$(grep -c 'not visible in this virtualenv' /tmp/siem.log)

if [ "${is_in_pyenv}" -gt 0 ]; then
    python3 -m pip install wheel pip==21.1.3
else
    cat /tmp/siem.log
fi
rm /tmp/siem.log

function pip_zip_for_lambda () {
    lib_name=$1
    if [ -e "${lib_name}.zip" ]; then
      echo "rm ${lib_name}.zip"
      rm "${lib_name}.zip"
    fi
    cd "${lib_name}" || exit
    mv README.md README.md.org
    echo "# cleanup installed libs in current dir"
    for dir in *.dist-info; do
        basename="${dir%-[0-9]*.dist-info}"
        echo "rm -fr ${dir} ${basename} ${basename//_/} ${basename}.py"
        rm -fr "${dir}" "${basename}" "${basename//_/}" "${basename}.py"
    done
    for dir in *.egg-info; do
        basename="${dir%-[0-9]*.egg-info}"
        echo "rm -fr ${dir} ${basename} ${basename}.py"
        rm -fr "${dir}" "${basename}" "${basename}".py
    done
    if [ -e requirements.txt ]; then
        python3 -m pip install -t . -r requirements.txt -U
    fi

    find . -name __pycache__ -print0 | xargs -0 rm -fr
    rm -f .DS_Store
    echo "# delete python libraries which are already installed in lambda environment"
    echo "rm -fr boto* future* urllib3* dateutil* python_dateutil* s3transfer* six* jmespath*"
    rm -fr boto* future* urllib3* dateutil* python_dateutil* s3transfer* six* jmespath*
    echo "# Delete unused and architecture dependent lib"
    echo "rm -fr async_timeout* aiosignal* aiohttp* examples frozenlist* multidict* wrapt* yarl*"
    rm -fr async_timeout* aiosignal* aiohttp* examples frozenlist* multidict* wrapt* yarl*
    if [ -d requests_aws4auth ]; then
        mv LICENSE README.md HISTORY.md requests_aws4auth-*-info/
    fi
    if [ -d aws_lambda_powertools ]; then
        mv THIRD-PARTY-LICENSES aws_lambda_powertools-*-info/
    fi
    mv -f README.md.org README.md
    echo "cp -f $source_template_dir/../LICENSE $source_template_dir/../CODE_OF_CONDUCT.md $source_template_dir/../CONTRIBUTING.md ${source_dir}/lambda/$1/"
    cp -f "$source_template_dir/../LICENSE" "$source_template_dir/../CODE_OF_CONDUCT.md" "$source_template_dir/../CONTRIBUTING.md" "${source_dir}/lambda/$1/"
    echo "zip -r -9 ../$1.zip *"
    zip -r -9 ../"$1".zip ./* > /dev/null
    echo "rm ${source_dir}/lambda/$1/LICENSE ${source_dir}/lambda/$1/CODE_OF_CONDUCT.md ${source_dir}/lambda/$1/CONTRIBUTING.md"
    rm "${source_dir}/lambda/$1/LICENSE" "${source_dir}/lambda/$1/CODE_OF_CONDUCT.md" "${source_dir}/lambda/$1/CONTRIBUTING.md"
    cd ..
}

cd "${source_dir}"/lambda || exit

echo 'rm -f deploy_es/dashboard.ndjson.zip'
rm -f deploy_es/dashboard.ndjson.zip
echo 'zip deploy_es/dashboard.ndjson.zip -jD ../saved_objects/dashboard.ndjson'
zip deploy_es/dashboard.ndjson.zip -jD ../saved_objects/dashboard.ndjson

echo "# start packing es_loader"
pip_zip_for_lambda "es_loader"
echo "# start packing es_loader_stopper"
pip_zip_for_lambda "es_loader_stopper"
echo "# start packing deploy_es"
pip_zip_for_lambda "deploy_es"
echo "# start packing geoip_downloader"
pip_zip_for_lambda "geoip_downloader"
echo "# start packing ioc_database"
pip_zip_for_lambda "ioc_database"
echo "# start packing index_metrics_exporter"
pip_zip_for_lambda "index_metrics_exporter"
