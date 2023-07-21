#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# bash <(curl -s -o- https://raw.githubusercontent.com/aws-samples/siem-on-amazon-opensearch-service/main/deployment/auto_setup_on_cloudshell.sh)
# or add git commit id at the end of line
# bash <(curl -s -o- https://raw.githubusercontent.com/aws-samples/siem-on-amazon-opensearch-service/main/deployment/auto_setup_on_cloudshell.sh) develop

###############################################################################
# helper Function
###############################################################################
LOG_OUT="$HOME/auto_setup_on_cloudshell-$(date "+%Y%m%d_%H%M%S").log"
exec 2> >(tee -a "${LOG_OUT}") 1>&2

export BASEDIR="$HOME/siem-on-amazon-opensearch-service"
export OLDDIR1="$HOME/siem-on-amazon-elasticsearch-service"
export OLDDIR2="$HOME/siem-on-amazon-elasticsearch"

function func_check_freespace() {
  if [ -d "$BASEDIR" ];then
    find "$BASEDIR" -name "*.zip" -print0 | xargs --null rm -f
    rm -fr "${BASEDIR}/source/cdk/.env"
    rm -fr "${BASEDIR}/source/cdk/cdk.out"
  fi
  if [ -d "$OLDDIR1" ];then
    find "$OLDDIR1" -name "*.zip" -print0 | xargs --null rm -f
    rm -fr "${OLDDIR1}/source/cdk/.env"
    rm -fr "${OLDDIR1}/source/cdk/cdk.out"
  fi
  if [ -d "$OLDDIR2" ];then
    find "$OLDDIR2" -name "*.zip" -print0 | xargs --null rm -f
    rm -fr "${OLDDIR2}/source/cdk/.env"
    rm -fr "${OLDDIR2}/source/cdk/cdk.out"
  fi
  free_space=$(df -m "$HOME" | awk '/[0-9]%/{print $(NF-2)}')
  echo "Free space is ${free_space} MB"
  if [ "${free_space}" -le 250 ]; then
    # pip cache
    rm -fr ~/.cache/pip
    # npm cache
    npm cache clean --force
    # multiple node
    num_of_nodes=$(find  ~/.nvm/versions/node/ -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$num_of_nodes" -gt 2 ]; then
      rm -fr ~/.nvm/versions/node/*
      rm -fr "${BASEDIR}/source/lambda"
      rm -fr "${OLDDIR1}/source/lambda"
      rm -fr "${OLDDIR2}/source/lambda"
    fi
  fi
  if [ "${free_space}" -le 250 ]; then
    echo "At least 250 MB of free space needed."
    echo "Exit."
    echo "Delete unnecessary files, or Delete AWS CloudShell home directory."
    exit
  fi
  echo ""
}

function func_migrate_old_repo_to_new_repo () {
  if [ -s "${OLDDIR1}/source/cdk/cdk.json" ]; then
    if [ ! -e "${BASEDIR}/source/cdk/cdk.json" ]; then
      cp "${OLDDIR1}/source/cdk/cdk.json" "${BASEDIR}/source/cdk/cdk.json"
    fi
  fi
  if [ -s "${OLDDIR1}/source/cdk/cdk.context.json" ]; then
    if [ ! -e "${BASEDIR}/source/cdk/cdk.context.json" ]; then
      cp "${OLDDIR1}/source/cdk/cdk.context.json" "${BASEDIR}/source/cdk/cdk.context.json"
    fi
  fi
  if [ -d "$OLDDIR1" ];then
    if [[ $AWS_EXECUTION_ENV = "CloudShell" ]]; then
      rm -fr "${OLDDIR1}/source/lambda"
      tar -zcf "${OLDDIR1}.tgz" -C "$HOME/" "${OLDDIR1##*/}" && rm -fr "$OLDDIR1"
    fi
  fi
  if [ -d "$OLDDIR2" ];then
    if [[ $AWS_EXECUTION_ENV = "CloudShell" ]]; then
      rm -fr "${OLDDIR2}/source/lambda"
      tar -zcf "${OLDDIR2}.tgz" -C "$HOME/" "${OLDDIR2##*/}" && rm -fr "$OLDDIR2"
    fi
  fi
}

function func_put_to_ssm_param () {
  cd "$BASEDIR/source/cdk" || exit
  put_obj=$1
  aws ssm put-parameter \
    --name "/aes-siem/cdk/$put_obj" \
    --overwrite \
    --region "$AWS_DEFAULT_REGION" \
    --value "$(cat "${put_obj}")" \
    --type String
  echo "PUT $put_obj to SSM Parameter store"
}

function func_get_from_param_store () {
  cd "$BASEDIR/source/cdk" || exit
  get_obj=$1
  aws ssm get-parameter \
    --name "/aes-siem/cdk/$get_obj" \
    --region "$AWS_DEFAULT_REGION" \
    --query "Parameter.Value" \
    --output text > "${get_obj}.ssm" 2> /dev/null
  if [ -s "${get_obj}.ssm" ]; then
    echo "GET $get_obj from SSM Parameter store"
  else
    rm "${get_obj}.ssm"
  fi
}

function func_update_param () {
  cd "$BASEDIR/source/cdk" || exit
  file_obj=$1
  func_get_from_param_store "${file_obj}"
  if [ ! -s "$file_obj.ssm" ]; then
    # not file in ssm
    if [ -s "$file_obj" ]; then
      func_put_to_ssm_param "${file_obj}"
    fi
  else
    if [ -s "$file_obj" ]; then
      is_changed=$(diff "$file_obj" "$file_obj".ssm| wc -l)
      if [ "$is_changed" != "0" ]; then
        func_put_to_ssm_param "$file_obj"
      fi
    fi
    rm "$file_obj.ssm"
  fi
}

function func_check_or_get_exiting_cdk_json () {
  suffix=$(date "+%Y%m%d_%H%M%S")
  func_get_from_param_store cdk.json
  if [ -s "cdk.json" ]; then
    if [ -s "cdk.json.ssm" ]; then
      file_diff=$(diff cdk.json.ssm cdk.json | wc -l)
      if [ "$file_diff" != "0" ]; then
        # different file
        echo "cdk.json on local and downloaded cdk.json from SSM parameter store are different."
        echo ""
        diff cdk.json cdk.json.ssm
        echo ""
        echo "Above lines are different"
        echo "  < exist only local cdk.json"
        echo "  > exist only downloaded cdk.json from SSM parameter store"
        mv cdk.json "cdk.json-$suffix"
        mv cdk.json.ssm cdk.json
        echo "cdk.json in local is backupped to cdk.json-$suffix"
        echo ""
      else
        # cdk.json and cdk.json.ssm are same file
        rm cdk.json.ssm
      fi
    else
      # There is no file in ssm paramater stores.
      # This may be first time to execute this script
      func_put_to_ssm_param cdk.json
    fi
  elif [ -f "cdk.json.ssm" ]; then
    # CDK was deployed and cdk.json is stored in ssm, but this is new environment
    mv cdk.json.ssm cdk.json
  fi

  func_get_from_param_store cdk.context.json
  if [ -s "cdk.context.json" ]; then
    if [ -s "cdk.context.json.ssm" ]; then
      file_diff=$(diff cdk.context.json.ssm cdk.context.json | wc -l)
      if [ "$file_diff" != "0" ]; then
        mv cdk.context.json "cdk.context.json-$suffix"
        mv cdk.context.json.ssm cdk.context.json
      else
        # cdk.json and cdk.json.ssm are same file
        rm cdk.context.json.ssm
      fi
    else
      func_put_to_ssm_param cdk.context.json
    fi
  elif [ -f "cdk.context.json.ssm" ]; then
    mv cdk.context.json.ssm cdk.context.json
  fi
}

function func_ask_and_set_env {
  cd "$BASEDIR/source/cdk" || exit
  AES_ENV="vpc"
  while true; do
    read -r -p "Where do you deploy your system? Enter pulic or vpc: default is [vpc]: " AES_ENV
    case $AES_ENV in
      '' | 'vpc' )
        echo deply OpenSearch Service ES in VPC
        export AES_ENV="vpc"
        cp cdk.json.vpc.sample cdk.json
        break;
        ;;
      'public' )
        echo deply OpenSearch Service on public environment
        export AES_ENV="public"
        cp cdk.json.public.sample cdk.json
        break;
        ;;
      * )
        echo Please enter public or vpn.
    esac
  done;
  aws ssm put-parameter \
    --name "/aes-siem/cdk/cdk.json" \
    --region "$AWS_DEFAULT_REGION" \
    --value "$(cat cdk.json)" \
    --type String
}

function func_validate_json () {
  echo "func_validate_json"
  cd "$BASEDIR/source/cdk" || exit
  file_obj=$1
  while true; do
    echo ""
    read -r -p 'Have you modified cdk.json? [Y(=continue) / n(=exit)]: ' ANSWER
    case $ANSWER in
      [Nn]* )
        echo exit. bye;
        exit;
        ;;
      [Yy]* )
        func_get_from_param_store cdk.json
        cp -f cdk.json.ssm cdk.json
        ERROR_MSG="$(jq empty < "${file_obj}" 2>&1 > /dev/null)"
        RESULT="$?"
        case $RESULT in
          0 )
            break;
            ;;
          * )
            echo "";
            echo "Woops. Your cdk.json is currupt json format";
            echo "$ERROR_MSG";
            ;;
        esac
        ;;
    esac
  done;
}

function func_continue_or_exit () {
  while true; do
    read -r -p 'Do you continue or exit? [Y(=continue) / n(=exit)]: ' Answer
    case $Answer in
      [Yy]* )
        echo Continue
        break;
        ;;
      [Nn]* )
        echo exit. bye
        exit;
        ;;
      * )
        echo Please answer YES or NO.
    esac
  done;
}

function func_delete_unnecessary_files() {
  cd "$HOME" || exit
  if [ -d "$BASEDIR" ];then
    find "$BASEDIR" -name "*.zip" -print0 | xargs --null rm -f
    rm -fr "${BASEDIR}/source/cdk/cdk.out"
  fi
}

###############################################################################
# main script
###############################################################################
echo "Auto Installtion Script Started"
date

if [ ! "$1" ]; then
  commitid='main'
else
  commitid=$1
fi

cd ~/ || exit
echo "func_check_freespace"
func_check_freespace

echo "### 1. Setting Up the AWS CDK Execution Environment ###"
echo 'sudo yum groups mark install -y "Development Tools"'
sudo yum groups mark install -y "Development Tools" > /dev/null
echo -e "Done\n"

echo "sudo yum install -y amazon-linux-extras"
sudo yum install -y amazon-linux-extras > /dev/null
echo -e "Done\n"

echo "sudo amazon-linux-extras enable python3.8"
sudo amazon-linux-extras enable python3.8 > /dev/null
echo -e "Done\n"

echo "sudo yum install -y python38 python38-devel git jq"
sudo yum install -y python38 python38-devel git jq > /dev/null
echo -e "Done\n"

sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
if [ ! -f /usr/bin/pip3 ]; then
  sudo update-alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip3.8 1
fi

if [ -d "$BASEDIR" ]; then
  echo "git rebase to get latest commit"
  cd "$BASEDIR" || exit
  git stash
  git fetch > /dev/null
  git checkout main && git pull --rebase > /dev/null
  git checkout develop && git pull --rebase > /dev/null
  git checkout "$commitid"
  cd "$HOME" || exit
else
  echo "git clone siem source code"
  git clone https://github.com/aws-samples/siem-on-amazon-opensearch-service.git > /dev/null
  cd "$BASEDIR" || exit
  git checkout "$commitid"
  cd "$HOME" || exit
fi
cd "$BASEDIR" && git log | head -4 && cd "$HOME" || exit
echo -e "Done\n"

echo "### 2. Setting Environment Variables ###"
### set AWS Accont ###
GUESS_CDK_DEFAULT_ACCOUNT=$(aws sts get-caller-identity --query 'Account' --output text)
read -r -p "Enter CDK_DEFAULT_ACCOUNT: default is [$GUESS_CDK_DEFAULT_ACCOUNT]: " TEMP_CDK_DEFAULT_ACCOUNT
export CDK_DEFAULT_ACCOUNT=${TEMP_CDK_DEFAULT_ACCOUNT:-$GUESS_CDK_DEFAULT_ACCOUNT}

### set AWS Region ###
if [[ $AWS_EXECUTION_ENV = "CloudShell" ]]; then
  GUESS_AWS_DEFAULT_REGION=$AWS_DEFAULT_REGION
  unset AWS_REGION
else
  TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 3600")
  GUESS_AWS_DEFAULT_REGION=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone | sed -e s/.$//)
fi
read -r -p "Enter AWS_DEFAULT_REGION to deploy OpenSearch Service: default is [$GUESS_AWS_DEFAULT_REGION]: " TEMP_AWS_DEFAULT_REGION
export AWS_DEFAULT_REGION=${TEMP_AWS_DEFAULT_REGION:-$GUESS_AWS_DEFAULT_REGION}
export CDK_DEFAULT_REGION=$AWS_DEFAULT_REGION

### print env ###
echo ""
echo "Your AWS account is $CDK_DEFAULT_ACCOUNT"
echo "AWS region of installation target is $CDK_DEFAULT_REGION"
echo ""

### Check if cdk.json exists. If no, create new one ###
echo "func_migrate_old_repo_to_new_repo"
func_migrate_old_repo_to_new_repo
echo "func_check_or_get_exiting_cdk_json"
func_check_or_get_exiting_cdk_json
echo -e "Done\n"
if [ ! -f "cdk.json" ]; then
  ### create new one ###
  echo "There is no existing cdk.json"
  echo "func_ask_and_set_env"
  func_ask_and_set_env > /dev/null
  echo -e "Done\n"
fi

echo "### 3. Creating an AWS Lambda Deployment Package ###"
cd "$BASEDIR"/deployment/cdk-solution-helper/ || exit
echo "./step1-build-lambda-pkg.sh"
date
chmod +x ./step1-build-lambda-pkg.sh && ./step1-build-lambda-pkg.sh > /dev/null
echo -e "Done\n"

echo "### 4. Setting Up the Environment for AWS Cloud Development Kit (AWS CDK) ###"
echo "./step2-setup-cdk-env.sh"
date
chmod +x ./step2-setup-cdk-env.sh && ./step2-setup-cdk-env.sh> /dev/null
# shellcheck disable=SC1090
if [[ "${AWS_EXECUTION_ENV}" != "CloudShell" ]]; then
  source ~/.bashrc
  nvm use lts/*
  echo -e "Done\n"
fi
find "$HOME" -name '.cache' -print0 | xargs --null rm -fr

echo "### 5. Setting Installation Options with the AWS CDK ###"
cd "$BASEDIR"/source/cdk/ || exit
# shellcheck disable=SC1091
source ../../.venv/bin/activate
echo "cdk bootstrap"
cdk bootstrap "aws://$CDK_DEFAULT_ACCOUNT/$AWS_DEFAULT_REGION"; status=$?
if [ $status -ne 0 ]; then
  echo "invalid configuration. exit"
  exit
fi
echo -e "Done\n"

echo "################################################"
echo "# Next Procedure"
echo "################################################"
echo "1. Go to Systems Manager / Parameter Store in selected region"
echo "   https://console.aws.amazon.com/systems-manager/parameters/aes-siem/cdk/cdk.json/"
echo "2. Check and Edit cdk.json file in Parameter Store"
echo "   If you want to update SIEM without changes, please just return "
echo "   see more details https://github.com/aws-samples/siem-on-amazon-opensearch-service/blob/main/docs/deployment.md"
echo ""
echo ""
echo ""
echo ""

func_validate_json cdk.json
echo ""
cat cdk.json
echo ""
echo "Install SIEM in $CDK_DEFAULT_REGION"
echo ""
echo "Is this right? Do you want to continue? "
func_continue_or_exit

(sleep 120 && func_update_param cdk.context.json > /dev/null 2>&1 & )
echo "cdk deploy"
date
cdk deploy; status=$?
if [ $status -ne 0 ]; then
  echo "invalid configuration. exit"
  exit
fi
date

echo "func_update_param cdk.context.json"
func_update_param cdk.context.json

echo "func_delete_unnecessary_files"
func_delete_unnecessary_files

echo "The script was done"
date
