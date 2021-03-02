#!/bin/bash

# curl -s -o- https://raw.githubusercontent.com/aws-samples/siem-on-amazon-elasticsearch/master/deployment/auto_setup_on_cloudshell.sh | bash

###############################################################################
# helper Function
###############################################################################

function func_get_cdk_json () {
  aws ssm get-parameter \
    --name "/aes-siem/cdk/cdk.json" \
    --region $AWS_DEFAULT_REGION \
    --query "Parameter.Value" \
    --output text > cdk.json.ssm
  if [ -f "cdk.json" ]; then
    file_diff=`diff cdk.json.ssm cdk.json | wc -l`
    if [ $file_diff == "0" ]; then
      mv cdk.json.ssm cdk.json
    else
      echo "cdk.json on local and downloaded file from SSM parameter store are different."
      while true; do
        read -p 'Continue with local file? or exit? [Y(=continue)/n(=exit)]' Answer
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
  else
    mv cdk.json.ssm cdk.json
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
if [ -f /usr/bin/pip3 ]; then
  :
else
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
else
  :
fi

EC2_AWS_DEFAULT_REGION=`curl -s http://169.254.169.254/latest/meta-data/placement/availability-zone | sed -e s/.$//`
GUESS_AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-$EC2_AWS_DEFAULT_REGION}
read -p "Enter AWS_DEFAULT_REGION to deploy Amazon ES: default is [$GUESS_AWS_DEFAULT_REGION]: " AWS_DEFAULT_REGION
AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-$GUESS_AWS_DEFAULT_REGION}
export AWS_DEFAULT_REGION
echo "Your AWS account is $CDK_DEFAULT_ACCOUNT"
echo "Installation target AWS region is $AWS_DEFAULT_REGION"

# additional
cd ~/siem-on-amazon-elasticsearch/source/cdk/
func_get_cdk_json
if [ -f "cdk.json" ]; then
  :
else
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
echo "1. change directory to CDK dir"
echo "cd siem-on-amazon-elasticsearch/source/cdk/"
echo "2. Edit cdk.json."
echo "3. enable cdk env."
echo "source .env/bin/activate"
echo "4. Execute 'cdk deploy'"
echo "5. push cdk.json to SSM Parameter Store"
cat << EOF
aws ssm put-parameter \
  --name "/aes-siem/cdk/cdk.json" \
  --overwrite \
  --region $AWS_DEFAULT_REGION \
  --value "\$(cat cdk.json)" \
  --type String
EOF
