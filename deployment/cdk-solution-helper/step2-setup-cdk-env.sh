#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

source_template_dir="$PWD/../"
source_dir="$source_template_dir/../source"
cdk_version=$(grep aws-cdk.core "${source_dir}/cdk/requirements.txt" | awk -F'==' '{print $2}')

is_ami2=$(grep -oi Karoo /etc/system-release 2> /dev/null)
if [ -z "$is_ami2" ]; then
    echo "Not AMI2."
    read -rp "Do you realy continue? (y/N): " yn
    case "$yn" in [yY]*) ;; *) echo "abort." ; exit ;; esac
fi

if ! (type pip3 > /dev/null 2>&1); then
    echo "No pip3. Install python3."
    echo "exist!"
    exit
fi

echo "python3 -m pip install boto3 --user"
python3 -m pip install boto3 --user > /tmp/siem.log 2>&1
is_in_pyenv=$(grep -c 'not visible in this virtualenv' /tmp/siem.log)

if [ "${is_in_pyenv}" -gt 0 ]; then
    python3 -m pip install boto3
else
    cat /tmp/siem.log
fi
rm /tmp/siem.log

echo "Install Node.js"
curl -s -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
# shellcheck disable=SC1090
source ~/.nvm/nvm.sh
nvm install --lts node
nvm alias default lts/*
node -e "console.log('Running Node.js ' + process.version)"
nvm use lts/*
echo "Install CDK"
echo "npm install -g aws-cdk@${cdk_version}"
npm install -g aws-cdk@"${cdk_version}"

cd "${source_dir}/cdk" || exit
python3 -m venv .env
# shellcheck disable=SC1091
source .env/bin/activate
echo "python3 -m pip install -r requirements.txt"
python3 -m pip install -r requirements.txt

BACK=$RANDOM
if [ -e cdk.json ]; then
    mv cdk.json cdk.json.$BACK
fi

cp cdk.json.public.sample cdk.json
cdk synth aes-siem -o "${source_template_dir}"/cdk-solution-helper/cdk.out 1>/dev/null

if [ -e cdk.json.$BACK ]; then
    mv -f cdk.json.$BACK cdk.json
fi
