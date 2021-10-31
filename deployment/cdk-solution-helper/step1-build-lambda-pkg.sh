#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

source_template_dir="${PWD}/.."
source_dir="$source_template_dir/../source"

if !(type pip3 > /dev/null 2>&1); then
    echo "No pip3. Install python3."
    echo "exist!"
    exit
fi

echo "------------------------------------------------------------------------------"
echo "[Packing] pip and Source Folder"
echo "------------------------------------------------------------------------------"
python3 -m pip install wheel pip==21.1.3 --user
function pip_zip_for_lambda () {
    if [ -e $1.zip ]; then
      echo "rm $1.zip"
      rm $1.zip
    fi
    cd $1
    mv README.md README.md.org
    echo "# delete old pip version"
    for dir in `ls -v -r -d *.dist-info 2>/dev/null`; do
        echo "rm -r" $(echo "${dir}" | sed -e 's/-.*.dist-info/*/')
        rm -r $(echo "${dir}" | sed -e 's/-.*.dist-info/*/')
        echo "rm -r" $(echo "${dir}" | sed -e 's/-.*.dist-info/*/' | sed -e 's/_//')
        rm -r $(echo "${dir}" | sed -e 's/-.*.dist-info/*/' | sed -e 's/_//')
    done
    for dir in `ls -v -r -d *.egg-info 2>/dev/null`; do
        echo "rm -r" $(echo "${dir}" | sed -e 's/-.*.egg-info/*/')
        rm -r $(echo "${dir}" | sed -e 's/-.*.egg-info/*/')
    done
    if [ -e requirements.txt ]; then
        python3 -m pip install -t . -r requirements.txt -U
    fi
    find . -name __pycache__ | xargs rm -fr
    rm -f .DS_Store
    #rm -fr *dist-info
    echo "# delete python libraries which are already installed in lambda environment"
    echo "rm -fr boto* aiohttp* future* urllib3* dateutil* python_dateutil* s3transfer* six* jmespath* yarl*"
    rm -fr boto* aiohttp* future* urllib3* dateutil* python_dateutil* s3transfer* six* jmespath* yarl*
    if [ -d requests_aws4auth ]; then
        mv LICENSE README.md HISTORY.md requests_aws4auth-*-info/
    fi
    mv -f README.md.org README.md
    echo "cp -f $source_template_dir/../LICENSE $source_template_dir/../CODE_OF_CONDUCT.md $source_template_dir/../CONTRIBUTING.md ${source_dir}/lambda/$1/"
    cp -f $source_template_dir/../LICENSE $source_template_dir/../CODE_OF_CONDUCT.md $source_template_dir/../CONTRIBUTING.md ${source_dir}/lambda/$1/
    echo "zip -r -9 ../$1.zip *"
    zip -r -9 ../$1.zip * > /dev/null
    echo "rm ${source_dir}/lambda/$1/LICENSE ${source_dir}/lambda/$1/CODE_OF_CONDUCT.md ${source_dir}/lambda/$1/CONTRIBUTING.md"
    rm ${source_dir}/lambda/$1/LICENSE ${source_dir}/lambda/$1/CODE_OF_CONDUCT.md ${source_dir}/lambda/$1/CONTRIBUTING.md
    cd ..
}

cd ${source_dir}/lambda

echo 'rm -f deploy_es/dashboard.ndjson.zip'
rm -f deploy_es/dashboard.ndjson.zip
echo 'zip deploy_es/dashboard.ndjson.zip -jD ../saved_objects/dashboard.ndjson'
zip deploy_es/dashboard.ndjson.zip -jD ../saved_objects/dashboard.ndjson

echo "# start packing es_loader"
pip_zip_for_lambda "es_loader"
echo "# start packing deploy_es"
pip_zip_for_lambda "deploy_es"
echo "# start packing geoip_downloader"
pip_zip_for_lambda "geoip_downloader"
