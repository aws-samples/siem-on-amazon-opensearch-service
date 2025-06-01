# Advanced Deployment

[View this page in Japanese (日本語)](deployment_ja.md) | [Chinese (简体中文)](deployment_zh-cn.md) | [Back to README](../README.md)

## Table of contents

* [Conditions that require advanced deployment](#conditions-that-require-advanced-deployment)
* [Loading an existing S3 bucket](#loading-an-existing-s3-bucket)
* [Deploying with the AWS CDK](#deploying-with-the-aws-cdk)
* [Updating SIEM with the AWS CDK](#updating-siem-with-the-aws-cdk)

## Conditions that require advanced deployment

Run the AWS Cloud Development Kit (AWS CDK) to deploy SIEM on Amazon OpenSearch Service without using AWS CloudFormation if any of the following is true:

* I want to deploy Amazon OpenSearch Service to an Amazon VPC **private subnet**
  * Deployment to an Amazon VPC public subnet is not supported
* I want to aggregate and analyze logs in a multi-account environment
* I want to import an existing Amazon Simple Storage Service (Amazon S3) bucket into a CloudFormation stack to automatically configure the **S3 bucket policy** with the AWS CDK for receiving multi-account logs. (Existing S3 bucket policy will be overwritten)
* I want to load logs from an existing S3 bucket into SIEM on OpenSearch Service. **I manage the S3 bucket policy myself**
* I want to decrypt logs that are stored encrypted in an S3 bucket with an existing AWS Key Management Service (AWS KMS) customer-managed key. **I manage the key policy for AWS KMS myself**
* I want to change the default S3 bucket name or SIEM on OpenSearch Service domain name when deploying it
  * SIEM on OpenSearch Service domain name: aes-siem
  * S3 bucket name for logs: aes-siem-*[AWS Account ID]*-log
  * S3 bucket name for snapshots: aes-siem-*[AWS Account ID]*-snapshot
  * S3 bucket name for GeoIP download: aes-siem-*[AWS Account ID]*-geo

## Loading an existing S3 bucket

You can load your existing S3 bucket into the CloudFormation stack of SIEM on OpenSearch Service and manage it with the AWS CDK. To do this, you need to add or modify the S3 bucket policy. Note that by following the steps below, **the S3 bucket policy and other bucket configurations** will be overwritten. Also, you can perform the steps below only during the initial installation of SIEM on OpenSearch Service.
Skip these steps if you want to send logs from your existing S3 bucket to SIEM on OpenSearch Service, but still want to manage your S3 bucket policy, etc. by yourself.

### Steps

1. Check the name of the S3 bucket you want to load into the CloudFormation stack
1. You can either git clone a set of source code from [Github](https://github.com/aws-samples/siem-on-amazon-opensearch-service), or download a CloudFormation template that imports a bucket from [here](https://aes-siem.s3.amazonaws.com/siem-on-amazon-opensearch-service-import-exist-s3bucket.template)
1. Edit `deployment/siem-on-amazon-opensearch-service-import-exist-s3bucket.template` in the CloudFormation template that you have cloned from GitHub or downloaded. Change [change-me-to-your-bucket] in BucketName to the name of the S3 bucket you want to load into the stack
1. Navigate to CloudFormation in the AWS Management Console
1. From the [Stacks] menu, choose [**Create stack**] --> [**With existing resources (import resources)**] from the top-right drop-down menu.
1. Chooose [**Next**], and on the [Specify template] screen, upload the edited template `siem-on-amazon-opensearch-service-import-exist-s3bucket.template`, and choose [**Next**]
1. On the [Identify resources] screen, navigate to [Identifier value] and enter [**the name of the S3 bucket you want to import**] into the stack and choose [**Next**]
1. On the [Specify stack details] screen, enter the stack name [**aes-siem**] and then choose [**Next**]
1. On the [Import overview] screen, choose [**Import resources**] to complete
1. Edit cdk.json in the next section: [Deploying with AWS CDK] -->  [5-3. Other common configurations] Set the name of the S3 bucket you want to import into the stack to **s3_bucket_name.log**.

## Deploying with the AWS CDK

### Notices

* The subnet you deploy is a private subnet
* Select three different Availability Zones for the subnet. (Only one instance is deployed per AZ)
* In Amazon VPC, enable both [**DNS hostnames**] and [**DNS resolution**]
* `cdk.json` and `cdk.context.json` are created during the deployment, and ensure to backup these files in AWS Systems Manager Parameter Store or somewhere. It will be required to rerun the CDK used for the deployment of SIEM on OpenSearch Service

### 1. Setting Up the AWS CDK Execution Environment

1. Deploy an Amazon Elastic Compute Cloud (Amazon EC2) instance that runs Amazon Linux 2023 or Amazon Linux 2. The EC instance require at least 2 GB RAM
1. Create a role with Admin permissions in AWS Identity and Access Management (IAM) and attach it to the Amazon EC2 instance
1. Log in to the shell; install the development tools, Python 3.11 and development files, git, jq and tar; and get the source code from GitHub

    For Amazon Linux 2023

    ```shell
    export GIT_ROOT=$HOME
    cd ${GIT_ROOT}
    sudo dnf install -y python3.11 python3.11-devel python3.11-pip git jq tar
    git clone https://github.com/aws-samples/siem-on-amazon-opensearch-service.git
    ```

    For Amazon Linux 2

    > **_Note:_** With this solution, deployment with CDK on Amazon Linux 2 is deprecated

    ```shell
    export GIT_ROOT=$HOME
    cd ${GIT_ROOT}
    sudo yum install -y amazon-linux-extras
    sudo amazon-linux-extras enable python3.8
    sudo yum install -y python38 python38-devel git jq tar
    sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
    git clone https://github.com/aws-samples/siem-on-amazon-opensearch-service.git
    ```

### 2. Setting Environment Variables

```shell
export CDK_DEFAULT_ACCOUNT=<AWS_ACCOUNT> # your AWS account
export AWS_DEFAULT_REGION=<AWS_REGION> # region where the distributable is deployed
```

### 3. Creating an AWS Lambda Deployment Package

The AWS Lambda functions that you use in SIEM on OpenSearch Service make use of third party libraries. The script below will download these libraries and create a deployment package locally. Ensure that you have Python 3 installed.

```shell
cd ${GIT_ROOT}/siem-on-amazon-opensearch-service/deployment/cdk-solution-helper/
deactive 2>/dev/null
chmod +x ./step1-build-lambda-pkg.sh && ./step1-build-lambda-pkg.sh
```

### 4. Setting Up the Environment for AWS Cloud Development Kit (AWS CDK)

The script below will install a variety of software in user mode which is needed to run the AWS CDK.

```bash
chmod +x ./step2-setup-cdk-env.sh && ./step2-setup-cdk-env.sh
source ~/.bashrc
```

Software to be installed:

* Node Version Manager (nvm)
* Node.js
* AWS SDK for Python (Boto3)
* AWS Cloud Development Kit (AWS CDK)

### 5. Setting Installation Options with the AWS CDK

From the root directory of the repository, navigate to the directory containing the AWS CDK code to prepare for configuration of options and installation

```bash
cd ${GIT_ROOT}/siem-on-amazon-opensearch-service/ && source .venv/bin/activate
cd source/cdk && cdk bootstrap $CDK_DEFAULT_ACCOUNT/$AWS_DEFAULT_REGION
```

If the execution fails with an error, verify that your Amazon EC2 instance has the appropriate permissions role assigned.

#### 5-1. Deploying SIEM on OpenSearch Service in an Amazon VPC

If you are deploying SIEM on OpenSearch Service in an Amazon VPC, copy and edit the AWS CDK sample file for Amazon VPC:

```bash
cp cdk.json.vpc.sample cdk.json
```

Edit cdk.json.

Parameters and descriptions for Amazon VPC:

| Parameter | Description |
|----------|----|
| vpc_typ | If you create a new Amazon VPC, enter [**new**], and if you use an existing Amazon VPC, enter [**import**]. The parameter to edit is new_vpc_xxxx for a new VPC and imported_vpc_xxxx for an existing VPC |
| imported_vpc_id | Enter the ID of the Amazon VPC where you want to deploy SIEM on OpenSearch Service |
| imported_vpc_subnets | Enter three or more “VPC subnet IDs” in list form |
| imported_vpc_subnetX | (Deprecated) Enter three parameters, namely [VPC subnet ID], [Availability Zone], and [route table ID] |
| new_vpc_nw_cidr_block | Enter the IP and CIDR block for the new Amazon VPC that you create. The format is the IP address/the number of subnet masks. Example) 192.0.2.0/24 |
| new_vpc_subnet_cidr_mask | Subnet CIDR block. For scalability, we recommend /27 or larger. |

#### 5-2. Deploying OpenSearch Service for public access (outside of Amazon VPC)

If you want to deploy SIEM on OpenSearch Service in a public access environment:

```bash
cp cdk.json.public.sample cdk.json
```

There’s no public-access-specific configuration

#### 5-3. Other common configurations

You can change the following parameters as common configurations. No modification is required if there are no changes.

| Parameter | Initial value | Description |
|------------|-------|-----|
| aes_domain_name | aes-siem | Changes the SIEM on OpenSearch Service domain |
| s3_bucket_name | Changes the S3 bucket name from the initial value |
| log | aes-siem-*[AWS Account ID]*-log | S3 bucket name for logs |
| snapshot | aes-siem-*[AWS Account ID]*-snapshot | S3 bucket name for snapshots |
| geo | aes-siem-*[AWS Account ID]*-geo | S3 bucket name for GeoIP downloads |
| kms_cmk_alias | aes-siem-key | Changes the alias name of the AWS KMS customer-managed key |
| organizations || Automatically generates an S3 bucket policy by using the AWS Organizations information entered here. No input is required if you manage another S3 bucket by yourself |
| .org_id | Organizations ID. Example) o-12345678 |
| .management_id || The AWS account ID that is the administrator account in Organizations |
| .member_ids || The AWS account IDs that are member accounts in Organizations, separated by commas |
| no_organizations || Automatically generates a bucket policy for accounts that are not managed by Organizations, by using the account information entered here. No input is required if you manage another S3 bucket by yourself |
| .aws_accounts || Enter comma-separated AWS account IDs that are not managed by Organizations |
| additional_s3_buckets || Enumerates S3 bucket names separated by commas |
| additional_kms_cmks || Enumerates the ARNs of AWS KMS customer-managed keys, separated by commas |

Finally, validate the JSON file. If JSON is displayed after execution and there is no error, the syntax of the JSON file is fine.

```shell
cdk context  --j
```

### 6. Running the AWS CDK

Deploy the AWS CDK:

```bash
cdk deploy
```

You can specify the same parameters as for the CloudFormation template. The parameters can also be changed from the CloudFormation console after deployment with the CDK command. During the initial installation, you can deploy without any parameters.

| Parameter | Description |
|------------|----|
| **Initial Deployment Parameters** ||
| AllowedSourceIpAddresses | The IP addresses that you want to allow access from when deploying SIEM on OpenSearch Service outside of your Amazon VPC. Multiple addresses are space-separated |
| **Basic Configuration** ||
| DeploymentTarget | Where would you like to deploy the SIEM solution? Value is  `opensearch_managed_cluster`(default) or `opensearch_serverless`. **Serverless is experimental option**|
| DomainOrCollectionName | Amazon OpenSearch Service Domain name or OpenSearch Serverless Collection name|
| SnsEmail | Email address. Alerts detected by SIEM on OpenSearch Service will be sent to this email address via SNS |
| ReservedConcurrency | The maximum number of concurrency executions for es-loader. The default value is `10`. Increase this value if you see delays in loading logs or if you see constant throttling occur even though there are no errors |
| **Log Enrichment - optional** ||
| GeoLite2LicenseKey | Maxmind license key. It will add country information to each IP address |
| OtxApiKey | If you wolud like to download IoC from AlienVault OTX, please enter OTX API Key.|
| EnableTor | Would you like to download Tor IoC? Value is `true` or `false`(default)|
| EnableAbuseCh| Would you like to download IoC from abuse.ch? Value is `true` or `false`(default)|
| IocDownloadInterval| Specify interval in minute to download IoC, default is 720 minutes|
| **Advanced Configuration - optional** ||
| LogBucketPolicyUpdate | Select `update_and_override`(default) or `keep` for the current policy of the Log bucket. Be sure to select `update_and_override` for the first deployment. If you select `update_and_override` when updating, you need to create and manage the bucket policy for writing logs to your S3 Log bucket by yourself |
| VpcEndpointId | Specify VPC Endpoint for OpenSearch managed cluster or OpenSearch Serverless. This should be manually created before deployment. If you specify VPC Endpoint, a few lambda functions and other resources will be deployed into VPC |
| CreateS3VpcEndpoint | Create new S3 VPC Endpoint with SIEM solution. Value is `true`(default) or `false`. If you use existing VPC and already have S3 VPC Endpoint, select `false` |
| CreateSqsVpcEndpoint | Create new SQS VPC Endpoint with SIEM solution. Value is `true`(default) or `false`. If you use existing VPC and already have SQS VPC Endpoint, select `false` |
| CreateSsmVpcEndpoint | Create new Systems Manager VPC Endpoint with SIEM solution. Value is `true`(default) or `false`. If you use existing VPC and already have Systems Manager VPC Endpoint, select `false` |
| CreateStsVpcEndpoint | Create new STS VPC Endpoint with SIEM solution. An STS VPC Endpoint is created only if you choose to integrate with Control Tower or Security Lake. Value is `true`(default) or `false`. If you use existing VPC and already have STS VPC Endpoint, select `false` |
| **Control Tower Integration - optional** | [AWS Control Tower Integration](controltower.md) |
| ControlTowerLogBucketNameList | Specify S3 log bucket names in the Log Archive account. Comma separated list. (e.g., `aws-controltower-logs-123456789012-ap-northeast-1, aws-controltower-s3-access-logs-123456789012-ap-northeast-1` )|
| ControlTowerSqsForLogBuckets | Specify SQS ARN for S3 log buckets in Log Archive Account. (e.g., `arn:aws:sqs:ap-northeast-1:12345678902:aes-siem-ct` )|
| ControlTowerRoleArnForEsLoader | Specify IAM Role ARN to be assumed by aes-siem-es-loader. (e.g., `arn:aws:iam::123456789012:role/ct-role-for-siem` )|
| **Security Lake Integration - optional** | [Amazon Security Lake Integration](securitylake.md) |
| SecurityLakeSubscriberSqs | Specify SQS ARN of Security Lake Subscriber. (e.g., `arn:aws:sqs:us-east-1:12345678902:AmazonSecurityLake-00001111-2222-3333-5555-666677778888-Main-Queue` ` ) |
| SecurityLakeRoleArn | Specify IAM Role ARN to be assumed by aes-siem-es-loader. (e.g., `arn:aws:iam::123456789012:role/AmazonSecurityLake-00001111-2222-3333-5555-666677778888` ) |
| SecurityLakeExternalId | Specify Security Lake external ID for cross account. (e.g., `externalid123` ) |

Syntax) `--parameters Option1=Parameter1 --parameters Option2=Parameter2`
If you have more than one parameter, repeat --parameters

Example of deployment with parameters)

```bash
cdk deploy \
    --parameters AllowedSourceIpAddresses="10.0.0.0/8 192.168.0.1" \
    --parameters GeoLite2LicenseKey=xxxxxxxxxxxxxxxx
```

The deployment takes about 30 minutes. When you're done, go back to README and proceed to “2. Configuring OpenSearch Dashboards.”

### 7. Back up cdk.json and cdk.context.json

Make a backup of cdk.json and cdk.context.json.

Example of backing up to AWS Systems Manager Parameter Store

```sh
aws ssm put-parameter \
  --overwrite \
  --type String \
  --name /siem/cdk/cdk.json \
  --value file://cdk.json

if [ -f cdk.context.json ]; then
  aws ssm put-parameter \
    --overwrite \
    --type String \
    --name /siem/cdk/cdk.context.json \
    --value file://cdk.context.json
fi
```

## Updating SIEM with the AWS CDK

You can update the SIEM repository with the AWS CDK. Ensure that the cdk.json you used during the initial installation is stored in the CDK directory.

> **_Note_: When you update SIEM, Global tenant settings, dashboards, etc. will be overwritten automatically. The configuration files and dashboards used before the update will be backed up to aes-siem-[AWS_Account]-snapshot/saved_objects/ in the S3 bucket, so restore them manually if you want to restore the original settings.**

> **_Note_: S3 bucket policy, KMS key policy, IAM policy, etc. are automatically generated by CDK/CloudFormation. Manual modification is not recommended, but if you have modified it, it will be overwritten, so please back up each and update the difference after updating.**

```sh
export GIT_ROOT=$HOME
cd ${GIT_ROOT}/siem-on-amazon-opensearch-service/ && git stash && git checkout main
git pull --rebase
```

Go back to the [**Deploying with the AWS CDK**] section and rerun [**2. Setting Environment Variables**], [**3. Creating an AWS Lambda Deployment Package**], and [**4. Setting Up the Environment for AWS Cloud Development Kit (AWS CDK)**.]

Note that [5. Setting Installation Options with the AWS CDK] and the subsequent steps **do not need to be followed**. Instead, execute the commands below:

Restore `cdk.json` and `cdk.context.json` saved during installation to `${GIT_ROOT}/siem-on-amazon-opensearch-service/source/cdk/`. There may be no `cdk.context.json`.

Example of restoring from AWS Systems Manager Parameter Store

```sh
cd ${GIT_ROOT}/siem-on-amazon-opensearch-service/source/cdk/
if [ -s cdk.json ]; then
  cp cdk.json cdk.json.`date "+%Y%m%d%H%M%S"`
fi
aws ssm get-parameter \
  --name /siem/cdk/cdk.json \
  --query "Parameter.Value" \
  --output text > cdk.json

if [ -s cdk.context.json ]; then
  cp cdk.context.json cdk.context.json.`date "+%Y%m%d%H%M%S"`
fi
aws ssm get-parameter \
  --name /siem/cdk/cdk.context.json \
  --query "Parameter.Value" \
  --output text > cdk.context.json.new 2> /dev/null
if [ -s cdk.context.json.new ]; then
  mv cdk.context.json.new cdk.context.json
else
  rm cdk.context.json.new
fi
```

> **_Note_) When updating from v2.8.0d prior version, it is necessary to migrate from CDK v1 to CDK v2. Run cdk bootstrap again**

```sh
cd ${GIT_ROOT}/siem-on-amazon-opensearch-service/ && source .venv/bin/activate
cd source/cdk
# Also run `cdk bootstrap` if updating from v2.8.0d or prior version
# cdk bootstrap
cdk deploy
```

Updated diffs will be displayed. Enter [**y**] to confirm. The update will be complete in a few minutes.

[Back to README](../README.md)
