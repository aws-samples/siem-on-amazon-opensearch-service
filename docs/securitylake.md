# Amazon Security Lake Integration

[View this page in Japanese (日本語)](securitylake_ja.md) | [Back to README](../README.md)

![Security Lake Architecture](images/securitylake-arch.svg)

Data from Amazon Security Lake can be loaded directly into SIEM on OpenSearch.

## Ingest data

### Deploying SIEM on OpenSearch Service

Deploy SIEM on OpenSearch with reference to [README](../README.md)

The account can be the same as or different from the Amazon Security Lake account, but the recommended account is different from the Security Lake account.

The region must be the same as the region where Security Lake is enabled.

Ignore Security Lake related parameters when running CDK / CloudFormation.

### Enabling and Configuring Security Lake

1. Set delegated administrator if using AWS Organizations (optional) [Doc](https://docs.aws.amazon.com/security-lake/latest/userguide/multi-account-management.html)
1. Enable Security Lake [Doc](https://docs.aws.amazon.com/security-lake/latest/userguide/getting-started.html)
1. If you want to monitor multiple regions, configure rollup (Optional) [Doc](https://docs.aws.amazon.com/security-lake/latest/userguide/manage-regions.html)
1. Set up subscribers in the region where you want to deploy SIME on OpenSearch [Doc](https://docs.aws.amazon.com/security-lake/latest/userguide/subscriber-management.html)
    * Data access method: `S3`
    * Subscriber credentials
        * Account Id: `AWS account where SIEM was deployed`
        * External ID: `(any string)`
1. **[Required]** Change the SQS of the created subscriber
    * Target SQS: AmazonSecurityLake-XXXXXXXX-XXXXXX-XXXXXX-XXXXXXXX-Main-Queue
    * Change visibility timeout from 5 minutes to `10 minutes`.

Check the subscriber created.

|resource type|resource ARN|
|------|----------|
|Subscription endpoint|arn:aws:sqs:ap-northeast-1:888888888888:AmazonSecurityLake-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX-Main-Queue|
|AWS role ID|arn:aws:iam::888888888888:role/AmazonSecurityLake-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX|
|External Id|(any string)|

Use this for the CloudFormation parameters in the next step.

### Preparation with SIEM account

Update the CloudFormation aes-siem or siem stack and enter the Control Tower related parameters.

Example: Security Lake Integration Parameter

|Parameter|Value|
|------|----------|
|SecurityLakeSubscriberSqs|arn:aws:sqs:ap-northeast-1:888888888888:AmazonSecurityLake-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX-Main-Queue|
|SecurityLakeRoleArn|arn:aws:iam::888888888888:role/AmazonSecurityLake-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX|
|SecurityLakeExternalId|( string of configured external ID )|

Immediately after configuration, log ingestion may fail, but will succeed once a new instance of the Lambda function (es-loader) is created. Alternatively, manually deploying the es-loader and forcing it to launch a new instance will resolve the error.

This completes the log ingestion configuration for Security Lake
