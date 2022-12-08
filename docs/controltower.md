# AWS Control Tower Integration

[View this page in Japanese (日本語)](controltower_ja.md) | [Back to README](../README.md)

![Control Tower Architecture](images/controltower-arch-log.svg)

Data from log buckets in the Log Archive account in AWS Control Tower can be loaded into SIEM on OpenSearch as-is. Data in S3 buckets created by default for AWS CloudTrail and AWS Config, and data in independently created S3 buckets can also be loaded if the log format is supported.

## Ingest data

### Deploying SIEM on OpenSearch Service

Deploy SIEM on OpenSearch with reference to [README](../README_en.md)

The account should either create a Security Tooling account in the member account (recommended) or use an Audit account, etc.

The region must be selected for integration with Control Tower, the region where the log buckets for the Log Archive account are located.

Ignore Control Tower related parameters when running CDK / CloudFormation.

After deployment, check the ARN of the IAM Role used in the Lambda function aes-siem-es-loader.

Example, `arn:aws:iam::123456789012:role/aes-siem-LambdaEsLoaderServiceRoleXXXXXXXXXXXX-XXXXXXXXXXXXXX`.

Use this for the CloudFormation parameters in the next step.

### Preparation with your Log Archive account

Create an Amazon SQS and IAM Role in the Log Archive account. Use the CloudFormation Template below to create these resource, which requires the ARN of the above IAM Role in the CDK / CloudFormation parameters. The resources will be newly created and will not modify any existing resources.

[![core resource](./images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home#/stacks/create/template?stackName=siem-integration-with-control-tower&templateURL=https://aes-siem.s3.ap-northeast-1.amazonaws.com/log-exporter/siem-integration-with-control-tower.template) [Direct Link](https://aes-siem.s3.ap-northeast-1.amazonaws.com/log-exporter/siem-integration-with-control-tower.template)

Creaed resources

|resource type|resource ARN|
|------|----------|
|AWS::IAM::Role|arn:aws:iam::999999999999:role/ct-role-for-siem|
|AWS::SQS::Queue|arn:aws:sqs:ap-northeast-1:999999999999:aes-siem-ct|
|AWS::SQS::Queue|arn:aws:sqs:ap-northeast-1:999999999999:aes-siem-ct-dlq|

Next, configure event notifications for the S3 bucket you wish to ingest logs.

* Example of target S3 bucket
  * aws-controltower-logs-999999999999-ap-northeast-1
  * aws-controltower-s3-access-logs-999999999999-ap-northeast-1
* event type: all object creation events ( s3:ObjectCreated:* )
* Destination: aes-siem-ct in SQS

This completes the configuration for the Log Archive account.

Note down the information needed for the next step, which will be used for the SIEM CloudFormation Stack parameters.

Example)

* Name of S3 bucket to ingest logs: `aws-controltower-logs-999999999999-ap-northeast-1, aws-controltower-s3-access-logs-999999999999-ap-northeast-1`.
* SQS ARN: `arn:aws:sqs:ap-northeast-1:999999999999:aes-siem-ct`
* IAM Role: `arn:aws:iam::999999999999:role/ct-assumed-role-for-siem-es-loader`.

### Preparation with admin account (optional)

Manually update the KMS key policy for the admin account if log buckets are encrypted.

The principal to allow will be the **Log Archie account**, not the SIEM account.

Configuration example:

```json
{
    "Effect": "Allow",
    "Principal": {
        "AWS": "arn:aws:iam::999999999999:role/ct-role-for-siem"
    },
    "Action": "kms:Decrypt",
    "Resource": "*"
},
```

Note: [Optionally configure AWS KMS keys](https://docs.aws.amazon.com/controltower/latest/userguide/configure-kms-keys.html#kms-key-policy-update)

### Preparation with SIEM account

Update the CloudFormation aes-siem or siem stack and enter the Control Tower related parameters.

Example: Control Tower Integration Parameter

|Parameter|Value|
|------|----------|
|ControlTowerLogBucketNameList|aws-controltower-logs-282094966508-ap-northeast-1, aws-controltower-s3-access-logs-282094966508-ap-northeast-1|
|ControlTowerSqsForLogBuckets|arn:aws:sqs:ap-northeast-1:999999999999:aes-siem-ct|
|ControlTowerRoleArnForEsLoader|arn:aws:iam::999999999999:role/ct-role-for-siem|

Immediately after configuration, log ingestion may fail, but will succeed once a new instance of the Lambda function (es-loader) is created. Alternatively, manually deploying the es-loader and forcing it to launch a new instance will resolve the error.

This completes the log ingestion configuration for the Log Archive account.
