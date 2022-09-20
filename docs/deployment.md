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
* `cdk.json` and `cdk.context.json` are created during the deployment, and ensure to save this file. It will be required to rerun the CDK used for the deployment of SIEM on OpenSearch Service

### 1. Setting Up the AWS CDK Execution Environment

1. Deploy an Amazon Elastic Compute Cloud (Amazon EC2) instance that runs Amazon Linux 2 (x86)
1. Create a role with Admin permissions in AWS Identity and Access Management (IAM) and attach it to the Amazon EC2 instance
1. Log in to the shell; install the development tools, Python 3.8 and development files, git, jq and tar; and get the source code from GitHub

   ```shell
   sudo yum groups mark install -y "Development Tools"
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
cd siem-on-amazon-opensearch-service/deployment/cdk-solution-helper/
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
cd ../../source/cdk/
source .venv/bin/activate
cdk bootstrap
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
| organizations | Automatically generates an S3 bucket policy by using the AWS Organizations information entered here. No input is required if you manage another S3 bucket by yourself |
| .org_id | Organizations ID. Example) o-12345678 |
| .management_id | The AWS account ID that is the administrator account in Organizations |
| .member_ids | The AWS account IDs that are member accounts in Organizations, separated by commas |
| no_organizations | Automatically generates a bucket policy for accounts that are not managed by Organizations, by using the account information entered here. No input is required if you manage another S3 bucket by yourself |
| .aws_accounts | Enter comma-separated AWS account IDs that are not managed by Oarganizations |
| additional_s3_buckets | Enumerates S3 bucket names separated by commas |
| additional_kms_cmks | Enumerates the ARNs of AWS KMS customer-managed keys, separated by commas |

Finally, validate the JSON file. If JSON is displayed after execution and there is no error, the syntax of the JSON file is fine.

```shell
cdk context  --j
```

### 6. Running the AWS CDK

Deploy the AWS CDK:

```bash
cdk deploy --no-rollback
```

You can specify the same parameters as for the CloudFormation template. The parameters can also be changed from the CloudFormation console after deployment with the CDK command.

| Parameter | Description |
|------------|----|
| AllowedSourceIpAddresses | The IP addresses that you want to allow access from when deploying SIEM on OpenSearch Service outside of your Amazon VPC. Multiple addresses are space-separated |
|||
| SnsEmail | Email address. Alerts detected by SIEM on OpenSearch Service will be sent to this email address via SNS |
| ReservedConcurrency | The maximum number of concurrency executions for es-loader. The default value is 10. Increase this value if you see delays in loading logs or if you see constant throttling occur even though there are no errors |
|||
| GeoLite2LicenseKey | Maxmind license key. It will add country information to each IP address |
|OtxApiKey|If you wolud like to download IoC from AlienVault OTX, please enter OTX API Key.|
|EnableTor|Would you like to download Tor IoC? Value is "true" or "false" (default)|
|EnableAbuseCh|Would you like to download IoC from abuse.ch? Value is "true" or "false" (default)|
|IocDownloadInterval|Specify interval in minute to download IoC, default is 720 miniutes|

Syntax) --parameters Option1=Parameter1 --parameters Option2=Parameter2
If you have more than one parameter, repeat --parameters

Example of deployment with parameters)

```bash
cdk deploy --no-rollback \
    --parameters AllowedSourceIpAddresses="10.0.0.0/8 192.168.0.1" \
    --parameters GeoLite2LicenseKey=xxxxxxxxxxxxxxxx
```

The deployment takes about 30 minutes. When you're done, go back to README and proceed to “3. Configuring OpenSearch Dashboards.”

## Updating SIEM with the AWS CDK

You can update the SIEM repository with the AWS CDK. Ensure that the cdk.json you used during the initial installation is stored in the CDK directory.

```sh
# cd SIEM repository
git pull --rebase
```

Go back to the [**Deploying with the AWS CDK**] section and rerun [**2. Setting Environment Variables**], [**3. Creating an AWS Lambda Deployment Package**], and [**4. Setting Up the Environment for AWS Cloud Development Kit (AWS CDK)**.]

Note that [5. Setting Installation Options with the AWS CDK] and the subsequent steps **do not need to be followed**. Instead, execute the commands below:

```sh
cd source/cdk/
source .venv/bin/activate
cdk deploy --no-rollback
```

Updated diffs will be displayed. Enter [**y**] to confirm. The update will be complete in a few minutes.

[Back to README](../README.md)
