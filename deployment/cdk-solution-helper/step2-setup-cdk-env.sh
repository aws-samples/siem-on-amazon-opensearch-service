#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

repo_root="${PWD}/../.."
source_template_dir="$PWD/../"
source_dir="$source_template_dir/../source"
cdk_version=$(grep aws-cdk-lib "${source_dir}/cdk/requirements.txt" | awk -F'==' '{print $2}')

is_al2=$(grep -oi Karoo /etc/system-release 2> /dev/null)
is_al2023=$(grep -oi "Amazon Linux release 2023" /etc/system-release 2> /dev/null)
if [ -z "$is_al2023" ] && [ -z "$is_al2" ]; then
    echo "neither Amazon Linux 2023 nor Amazon Linux 2."
    read -rp "Do you realy continue? (y/N): " yn
    case "$yn" in [yY]*) ;; *) echo "abort." ; exit ;; esac
fi

if ! (type pip3 > /dev/null 2>&1); then
    echo "No pip3. Install python3."
    echo "exist!"
    exit
fi

# CDK
if [[ "${AWS_EXECUTION_ENV}" = "CloudShell" ]]; then
  sudo npm install -g aws-cdk@"${cdk_version}"
else
  echo "Install Node.js"
  curl -s -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.5/install.sh | bash
  # shellcheck disable=SC1090
  source ~/.nvm/nvm.sh
  if [ -n "$is_al2" ]; then
    nvm install 16
    nvm alias default 16
    node -e "console.log('Running Node.js ' + process.version)"
    nvm use 16
  elif [ -n "$is_al2023" ]; then
    nvm install 20
    nvm alias default 20
    node -e "console.log('Running Node.js ' + process.version)"
    nvm use 20
  else
    nvm install 18
    nvm alias default 18
    node -e "console.log('Running Node.js ' + process.version)"
    nvm use 18
  fi
  echo "Install CDK"
  echo "npm install -g aws-cdk@${cdk_version}"
  npm install -g aws-cdk@"${cdk_version}"
fi

# create virtual venv
cd "$repo_root" || exit
if [ ! -d .venv ]; then
  echo "create .venv"
  echo "python3 -m venv .venv"
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python3 -m pip install wheel pip==22.2.2

# shellcheck disable=SC1091
echo "python3 -m pip install -r ${source_dir}/cdk/requirements.txt"
python3 -m pip install -r "${source_dir}/cdk/requirements.txt"

# Delete CDK v1
cd "${source_dir}/cdk" || exit
if [ -d .env ]; then
  echo "CDK v1 exists."
  echo "rm -fr .env"
  rm -fr .env
fi
if [ -d "${source_template_dir}/cdk-solution-helper/cdk.out" ]; then
  rm -fr "${source_template_dir}/cdk-solution-helper/cdk.out"
fi
