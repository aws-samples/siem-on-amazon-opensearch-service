# SIEM on Amazon Elasticsearch Service

[日本語](README_ja.md)

SIEM on Amazon Elasticsearch Service (Amazon ES) is a solution that collects multiple types of logs from AWS multiple accounts, correlates and visualizes the logs to investigate security incidents. Deployment is performed with AWS CloudFormation or AWS Cloud Development Kit (AWS CDK). Deployment will finish within about 20 minutes. When AWS services put the log to Simple Storage Service (Amazon S3), AWS Lambda function will load log to Amazon ES. Then you can visualize logs with dashboard and correlate the multiple logs to investigate security incident.

![Sample dashboard](./docs/images/dashboard-sample.jpg)

## Architecture

![Architecture](./docs/images/aes-siem-architecture.png)

## Supported Logs

SIEM on Amazon ES can load and correlate following logs.

|AWS Service|Log|
|-----------|---|
|AWS CloudTrail|CloudTrail Log Event|
|Amazon Virtual Private Cloud (Amazon VPC)|VPC Flow Logs|
|Amazon GuardDuty|GuardDuty findings|
|AWS Security Hub|Security Hub findings<br>GuardDuty findings<br>Amazon Macie findings<br>Amazon Inspector findings<br>AWS IAM Access Analyzer findings|
|AWS WAF|AWS WAF Web ACL traffic information<br>AWS WAF Classic Web ACL traffic information|
|Elastic Load Balancing|Application Load Balancer access logs<br>Network Load Balancer access logs<br>Classic Load Balancer access logs|
|Amazon CloudFront|Standard access log<br>Real-time log|
|Amazon Simple Storage Service (Amazon S3)|access log|
|Amazon Route 53 Resolver|VPC DNS query log|
|Linux OS<br>via CloudWatch Logs|/var/log/messages<br>/var/log/secure|
|Amazon Elastic Container Service (Amazon ECS)<br>via FireLens|Framework only|

Supported logs are normalized according to the [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html). Please refer to [here](docs/suppoted_log_type.md) to see correspondence log table of original and normalized field name.

## Dashboard

See [here](docs/dashboard.md)

## Getting Started

Deploy SIEM on Amazon ES domain for public access using a CloudFormation template. Please refer to [Advanced Deployment](docs/deployment.md) for deploying within the Amazon VPC and customizing.

You can add country information and latitude and longitude location information to the IP address. For location information, SIEM on Amazon ES will download GeoLite2 Free from [MaxMind](https://www.maxmind.com) and will use it. If you would like to give location information, please obtain a free license from MaxMind.

_Note:_ CloudFormation deploys Amazon ES with **t3.small.elasticsearch instance. Please change the instance type when using SIEM in production.** In addition, please use AWS Management Console to add or change instance type, change Amazon ES node configuration. Using CloudFormation template is installed only, it does not manage changes, deletions, etc. of Amazon ES domain.

### 1. Quick Start

You can deploy with following CloudFormation template.

| Region | CloudFormation |
|--------|----------------|
| N. Virginia (us-east-1) |[![Deploy in us-east-1](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new?stackName=aes-siem&templateURL=https://aes-siem-us-east-1.s3.amazonaws.com/siem-on-amazon-elasticsearch.template) |
| Oregon (us-west-2) |[![Deploy in us-west-2](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacks/new?stackName=aes-siem&templateURL=https://aes-siem-us-west-2.s3.amazonaws.com/siem-on-amazon-elasticsearch.template) |
| Tokyo (ap-northeast-1) |[![Deploy in ap-northeast-1](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-northeast-1#/stacks/new?stackName=aes-siem&templateURL=https://aes-siem-ap-northeast-1.s3.amazonaws.com/siem-on-amazon-elasticsearch.template) |
| Frankfurt (eu-central-1) |[![Deploy in eu-central-1](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-central-1#/stacks/new?stackName=aes-siem&templateURL=https://aes-siem-eu-central-1.s3.amazonaws.com/siem-on-amazon-elasticsearch.template) |
| London(eu-west-2) |[![Deploy in eu-west-2](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-west-2#/stacks/new?stackName=aes-siem&templateURL=https://aes-siem-eu-west-2.s3.amazonaws.com/siem-on-amazon-elasticsearch.template) |

If your region doesn't list above, use manually this template.

```text
https://aes-siem-<REGION>.s3.amazonaws.com/siem-on-amazon-elasticsearch.template
```

Or you can create your template with following procedure.

### 2. Deploy siem with own template

You can skip this session if you already deploy with above CloudFormation template.

#### 2-1. Prerequisites

The following procedures assumes that all of the OS-level configuration has been completed. They are:

* Amazon EC2 instance running Amazon Linux 2
  * "Development Tools"
  * Python 3.8
  * Python 3.8 libraries and header files
  * git

```shell
sudo yum groupinstall -y "Development Tools"
sudo yum install -y amazon-linux-extras
sudo amazon-linux-extras enable python3.8
sudo yum install -y python38 python38-devel git jq
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
sudo update-alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip3.8 1
```

#### 2-2. Clone SIEM on Amazon ES

Clone the SIEM on Amazon ES from GitHub repository:

```bash
git clone https://github.com/aws-samples/siem-on-amazon-elasticsearch.git
```

#### 2-3. Declare enviroment variables

```shell
export TEMPLATE_OUTPUT_BUCKET=<YOUR_TEMPLATE_OUTPUT_BUCKET> # Name for the S3 bucket where the template will be located
export AWS_REGION=<AWS_REGION> # region where the distributable is deployed
```

##### _Note:_ You must manually create a bucket in S3 called $TEMPLATE_OUTPUT_BUCKET to copy the distribution. The assets in bucket should be publicly accessible. The build-s3-dist.sh script DOES NOT do this

#### 2-4. Build the AWS Lambda deployment package of SIEM on Amazon Elasticsearch Service

```shell
cd siem-on-amazon-elasticsearch/deployment/cdk-solution-helper/
chmod +x ./step1-build-lambda-pkg.sh && ./step1-build-lambda-pkg.sh && cd ..
chmod +x ./build-s3-dist.sh && ./build-s3-dist.sh $TEMPLATE_OUTPUT_BUCKET
```

#### 2-5. Upload deployment assets to your Amazon S3 buckets

```shell
aws s3 cp ./global-s3-assets s3://$TEMPLATE_OUTPUT_BUCKET/ --recursive --acl bucket-owner-full-control
aws s3 cp ./regional-s3-assets s3://$TEMPLATE_OUTPUT_BUCKET/ --recursive --acl bucket-owner-full-control
```

##### _Note:_ You must use proper acl and profile for the copy operation as applicable

#### 2-6. Deploy the SIEM on Amazon ES

Deploy with `https://s3.amazonaws.com/$TEMPLATE_OUTPUT_BUCKET/siem-on-amazon-elasticsearch.template`

### 3. Configure Kibana

It will probably take about 20 mins to finish deploy Amazon ES. Then you will configure Kibana.

1. To login Amazon ES, move to CloudFormation console, select the stack and "Outputs" in tab menu. Then you can see Kibana's username, password and URL.
1. To import Kibana's configuration such as dashboard, download [saved_objects.zip](https://aes-siem.s3.amazonaws.com/assets/saved_objects.zip). Unzip the file.
1. Go to Kibana console. Click "Management" in left side menu, "Saved Objects", "Import" and "Import". Select unzip file dashboard.ndjson. Then logout once to load the configuration.

### 4. Load logs to Amazon ES

PUT logs to S3 Bucket, **aes-siem-<YOUR_AWS_ACCOUNT>-log**. Then the log will be loaded to Amazon ES. You can see more [details instructions](docs/configure_aws_service.md) for each logs.

## Configuration

### Configuring Amazon ES

Please use AWS Management Console to change the access policy of Amazon ES, storage size, node instance, Availability Zone, UltraWarm, etc.

### Manage index and custom SIEM

Amazon ES indexes each log and rotates it once a month. You can change this term.

You can load non AWS resources to Amazon ES in this framework. See [Configure SIEM](docs/configure_siem.md) fore more details

## Load stored logs

The es-loader, python script, can load stored old logs in S3 Bucket to Amazon ES. Just execute es-loader on Local environment.

## AWS Resources

|AWS Resource|Resource Name|
|------------|----|
|Amazon ES 7.X|aes-siem|
|S3 bucket|aes-siem-[AWS_Account]-log|
|S3 bucket|aes-siem-[AWS_Account]-snapshot|
|S3 bucket|aes-siem-[AWS_Account]-geo|
|Lambda function|aes-siem-es-loader|
|Lambda function|aes-siem-deploy-aes|
|Lambda function|aes-siem-configure-aes|
|Lambda function|aes-siem-geoip-downloader|
|Lambda function|aes-siem-BucketNotificationsHandler|
|AWS Key Management Service<br>(AWS KMS) CMK & Alias|aes-siem-key|
|Amazon SQS Queue|aes-siem-dlq|
|Amazon SQS Queue|aes-siem-sqs-splitted-logs|
|CloudWatch Events|aes-siem-CwlRuleLambdaGeoipDownloader|
|Amazon SNS Topic|aes-siem-alert|
|Amazon SNS Subscription|entered email|

## CleanUp

1. Delete aes-siem stack in CloudFormation
1. Delete following AWS resources manually.
    * aes-siem domain (Amazon ES)
    * aes-siem-123456789012-log (Amazon S3)
    * aes-siem-123456789012-geo (Amazon S3)
    * aes-siem-123456789012-snapshot (Amazon S3)
    * aes-siem-key of CMK alias and key (AWS Key Management Service)
        * **BE CAREFULL**. You will not be able to read the logs, if you encrypt logs with this key.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

This product uses GeoLite2 data created by MaxMind and licensed under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/), available from [https://www.maxmind.com](https://www.maxmind.com).
