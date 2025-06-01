#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

shopt -s expand_aliases

pip_ver="25.1.1"

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

# Node.js
echo "AWS_EXECUTION_ENV is ${AWS_EXECUTION_ENV}"
echo -e ""
if [[ "${AWS_EXECUTION_ENV}" = "CloudShell" ]]; then
  echo "This environment is CloudShell"
  echo "Skip Node.js installation"
else
  MAJOR_VER=$(node -v 2>/dev/null | cut -f 2 -d v | cut -f 1 -d ".")
  if [[ -n "$is_al2" && "$MAJOR_VER" == "16" ]] \
      || [[ -n "$is_al2023" && "$MAJOR_VER" == "22" ]] \
      || [ "$MAJOR_VER" == "20" ] || [ "$MAJOR_VER" == "22" ]; then
    echo "Installed Node.js version is $MAJOR_VER "
    echo "Skip Node.js installation"
  else
    echo "Install Node.js"
    # shellcheck disable=SC1090
    nvm -v 2>/dev/null || curl -s -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash && source ~/.nvm/nvm.sh
    MAJOR_VER=$(node -v 2>/dev/null | cut -f 2 -d v | cut -f 1 -d ".")

    if [ -n "$is_al2" ] && [ "$MAJOR_VER" != "16" ]; then
      echo "Start installing Node 16 on Amazon Linux 2"
      nvm install 16
      nvm alias default 16
      nvm use 16
    elif [ -n "$is_al2023" ] && [ "$MAJOR_VER" != "22" ]; then
      echo "Start installing Node 18 on Amazon Linux 2023"
      nvm install 22
      nvm alias default 22
      nvm use 22
    else
      echo "Start installing Node 22"
      nvm install 22
      nvm alias default 22
      nvm use 22
    fi
    echo "nvm alias"
    nvm alias
  fi
fi

node -e "console.log('Running Node.js: ' + process.version)"
echo -e ""

# CDK
echo "Install CDK"
if [[ "${AWS_EXECUTION_ENV}" = "CloudShell" ]]; then
  echo "npm install aws-cdk@${cdk_version}"
  npm install aws-cdk@^2
else
  echo "npm install -g aws-cdk@${cdk_version}"
  npm install -g aws-cdk@^2
fi

# create virtual venv
cd "$repo_root" || exit

if python3 --version |grep '3.11' >/dev/null 2>&1; then
  :
elif [ -f "/usr/bin/python3.11" ]; then
  alias python3='/usr/bin/python3.11'
elif [ -f "/usr/bin/python3.10" ]; then
  alias python3='/usr/bin/python3.10'
elif [ -f "/usr/bin/python3.9" ]; then
  alias python3='/usr/bin/python3.9'
elif [ -f "/usr/bin/python3.8" ]; then
  alias python3='/usr/bin/python3.8'
else
  :
fi

local_version=$(python3 --version)
venv_version=$(.venv/bin/python --version 2>/dev/null)
echo "python local version: $local_version"
echo "python venv version: $venv_version"
if [ -n "$venv_version" ] && [ "$local_version" != "$venv_version" ]; then
  echo "delete .venv to install newer version"
  rm -fr .venv
fi
if [ ! -d .venv ]; then
  echo "create .venv"
  echo "python3 -m venv .venv"
  python3 -m venv .venv
fi
unalias python3 2>/dev/null
# shellcheck disable=SC1091
source .venv/bin/activate
python3 -m pip install wheel pip=="$pip_ver" --disable-pip-version-check --no-python-version-warning

# shellcheck disable=SC1091
echo "python3 -m pip install -r ${source_dir}/cdk/requirements.txt --disable-pip-version-check --no-python-version-warning"
python3 -m pip install -r "${source_dir}/cdk/requirements.txt" --disable-pip-version-check --no-python-version-warning

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
