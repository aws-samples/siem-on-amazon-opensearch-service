#!/bin/bash

# bash <(curl -s -o- https://raw.githubusercontent.com/aws-samples/siem-on-amazon-elasticsearch/develop/deployment/auto_setup_on_cloudshell.sh)

###############################################################################
# helper Function
###############################################################################

function func_get_cdk_json () {
  aws ssm get-parameter \
    --name "/aes-siem/cdk/cdk.json" \
    --region $AWS_DEFAULT_REGION \
    --query "Parameter.Value" \
    --output text > cdk.json.ssm
  aws ssm get-parameter \
    --name "/aes-siem/cdk/cdk.context.json" \
    --region $AWS_DEFAULT_REGION \
    --query "Parameter.Value" \
    --output text > cdk.context.json.ssm
  if [ ! -s "cdk.json.ssm" ]; then
    rm cdk.json.ssm
  fi
  if [ ! -s "cdk.context.json.ssm" ]; then
    rm cdk.context.json.ssm
  fi
  if [ -s "cdk.json" ]; then
    if [ -f "cdk.json.ssm" ]; then
      file_diff=`diff cdk.json.ssm cdk.json | wc -l`
      if [ $file_diff != "0" ]; then
        # differenct file
        echo "cdk.json on local and downloaded file from SSM parameter store are different."
        while true; do
          read -p 'Continue with local file? or exit? [Y(=continue) / n(=exit)]' Answer
          case $Answer in
            '' | [Yy]* )
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
      fi
    fi
  elif [ -f "cdk.json.ssm" ]; then
    cp cdk.json.ssm cdk.json
  fi
}

function func_ask_and_set_env {
  AES_ENV="vpc"
  while true; do
    read -p "Where do you deploy your system? Enter pulic or vpc: default is [vpc]: " AES_ENV
    case $AES_ENV in
      '' | 'vpc' )
        echo deply Amazon ES in VPC
        export AES_ENV="vpc"
        cp cdk.json.vpc.sample cdk.json
        break;
        ;;
      'public' )
        echo deply Amazon ES on public environment
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
    --region $AWS_DEFAULT_REGION \
    --value "$(cat cdk.json)" \
    --type String
}

function func_continue_or_exit () {
  while true; do
    read -p 'Do you ontinue or exit? [Y(=continue) / n(=exit)]' Answer
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

###############################################################################
# main script
###############################################################################

# 1. Setting Up the AWS CDK Execution Environment
cd ~/
sudo yum groupinstall -y "Development Tools"
sudo yum install -y amazon-linux-extras
sudo amazon-linux-extras enable python3.8
sudo yum install -y python38 python38-devel git jq
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
if [ ! -f /usr/bin/pip3 ]; then
  sudo update-alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip3.8 1
fi

if [ -d "siem-on-amazon-elasticsearch" ]; then
  echo "git rebase"
  cd siem-on-amazon-elasticsearch
  git pull --rebase
else
  echo "git clone"
  git clone https://github.com/aws-samples/siem-on-amazon-elasticsearch.git
fi

if [ -v ${CDK_DEFAULT_ACCOUNT} ]; then
  GUESS_CDK_DEFAULT_ACCOUNT=`aws sts get-caller-identity --query 'Account' --output text`
  read -p "Enter CDK_DEFAULT_ACCOUNT: default is [$GUESS_CDK_DEFAULT_ACCOUNT]: " CDK_DEFAULT_ACCOUNT
  CDK_DEFAULT_ACCOUNT=${CDK_DEFAULT_ACCOUNT:-$GUESS_CDK_DEFAULT_ACCOUNT}
  export CDK_DEFAULT_ACCOUNT
fi

EC2_AWS_DEFAULT_REGION=`curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone | sed -e s/.$//`
GUESS_AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-$EC2_AWS_DEFAULT_REGION}
read -p "Enter AWS_DEFAULT_REGION to deploy Amazon ES: default is [$GUESS_AWS_DEFAULT_REGION]: " AWS_DEFAULT_REGION
AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-$GUESS_AWS_DEFAULT_REGION}
export AWS_DEFAULT_REGION
export CDK_DEFAULT_REGION=$AWS_DEFAULT_REGION
echo "Your AWS account is $CDK_DEFAULT_ACCOUNT"
echo "AWS region of installation target is $AWS_DEFAULT_REGION"

# additional
cd ~/siem-on-amazon-elasticsearch/source/cdk/
func_get_cdk_json
if [ ! -f "cdk.json" ]; then
  func_ask_and_set_env
fi

# 3. Creating an AWS Lambda Deployment Package
cd ~/siem-on-amazon-elasticsearch/deployment/cdk-solution-helper/
chmod +x ./step1-build-lambda-pkg.sh && ./step1-build-lambda-pkg.sh

# 4. Setting Up the Environment for AWS Cloud Development Kit (AWS CDK)
chmod +x ./step2-setup-cdk-env.sh && ./step2-setup-cdk-env.sh
source ~/.bash_profile

# 5. Setting Installation Options with the AWS CDK
cd ../../source/cdk/
source .env/bin/activate
cdk bootstrap

echo "################################################"
echo "# Next Procedure"
echo "################################################"
echo "Open ANOTHER shell and edit cdk.json"
echo "If you just update SIEM, you don't need to edit cdk.json"
echo ""
echo '```'
echo "cd ~/siem-on-amazon-elasticsearch/source/cdk/"
echo "vi cdk.json"
echo '# validation. 0 is OK'
echo 'cat cdk.json.corrupt | jq empty; echo $?'
echo '```'
echo ""
echo ""
echo ""
echo ""
echo "Did you edit cdk.json and continue?"
func_continue_or_exit

source .env/bin/activate
cdk deploy

if [ -f "cdk.json.ssm" ]; then
  file_diff=`diff cdk.json.ssm cdk.json | wc -l`
  if [ $file_diff != "0" ]; then
    # it must be updated
    aws ssm put-parameter \
      --name "/aes-siem/cdk/cdk.json" \
      --overwrite \
      --region $AWS_DEFAULT_REGION \
      --value "$(cat cdk.json)" \
      --type String
  fi
  rm cdk.json.ssm
else
  aws ssm put-parameter \
    --name "/aes-siem/cdk/cdk.json" \
    --overwrite \
    --region $AWS_DEFAULT_REGION \
    --value "$(cat cdk.json)" \
    --type String
fi

if [ -f "cdk.context.json.ssm" ]; then
  file_diff=`diff cdk.context.json.ssm cdk.context.json | wc -l`
  if [ $file_diff != "0" ]; then
    # it must be updated
    aws ssm put-parameter \
      --name "/aes-siem/cdk/cdk.context.json" \
      --overwrite \
      --region $AWS_DEFAULT_REGION \
      --value "$(cat cdk.context.json)" \
      --type String
  fi
  rm cdk.context.json.ssm
else
  aws ssm put-parameter \
    --name "/aes-siem/cdk/cdk.context.json" \
    --overwrite \
    --region $AWS_DEFAULT_REGION \
    --value "$(cat cdk.context.json)" \
    --type String
fi

echo "All script was done"


#echo "1. change directory to CDK dir"
#echo "cd siem-on-amazon-elasticsearch/source/cdk/"
#echo "2. Edit cdk.json."
#echo "3. enable cdk env."
#echo "source .env/bin/activate"
#echo "4. Execute CDK"
#echo "cdk deploy"
#echo "5. push cdk.json to SSM Parameter Store"
#cat << EOF
#aws ssm put-parameter \
#  --name "/aes-siem/cdk/cdk.json" \
#  --overwrite \
#  --region $AWS_DEFAULT_REGION \
#  --value "\$(cat cdk.json)" \
#  --type String
#EOF
