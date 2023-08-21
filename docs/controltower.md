# AWS Control Tower Integration
<!-- markdownlint-disable-file MD033 -->

[View this page in Japanese (日本語)](controltower_ja.md) | [Back to README](../README.md)

![Control Tower Architecture](images/controltower-arch-log.svg)

Data from log buckets in the Log Archive account in AWS Control Tower can be loaded into SIEM on OpenSearch as-is. Data in S3 buckets created by default for AWS CloudTrail and AWS Config, and data in independently created S3 buckets can also be loaded if the log format is supported.

Next, enable single sign-on to the OpenSearch Service

## Table of Contents

1. [Data ingestion](#data-ingestion)
    * [Deploying SIEM on OpenSearch Service](#deploying-siem-on-opensearch-service)
    * [Preparation with your Log Archive account](#preparation-with-your-log-archive-account)
    * [Preparation with admin account (optional)](#preparation-with-admin-account-optional)
    * [Preparation with SIEM account](#preparation-with-siem-account)
1. [SAML federation](#saml-federation)
    * [Add and configure the application in AWS IAM Identity Center](#add-and-configure-the-application-in-aws-iam-identity-center)
    * [Amazon OpenSearch Service SAML Authentication](#amazon-opensearch-service-saml-authentication)
    * [Amazon OpenSearch Servrless SAML Authentication](#amazon-opensearch-serverless-saml-authentication)
    * [SAML Authentication Configuration in AWS IAM Identity Center](#saml-authentication-configuration-in-aws-iam-identity-center)
    * [Adding general user group to Amazon OpenSearch Service](#adding-general-user-group-to-amazon-opensearch-service)
    * [Adding general user group to Amazon OpenSearch Serverless](#adding-general-user-group-to-amazon-opensearch-serverless)
    * [Adding general user group to IAM Identity Center](#adding-general-user-group-to-iam-identity-center)

## Data ingestion

### Deploying SIEM on OpenSearch Service

Deploy SIEM on OpenSearch with reference to [README](../README.md)

The account should either create a Security Tooling account in the member account (recommended) or use an Audit account, etc.

The region must be selected for integration with Control Tower, the region where the log buckets for the Log Archive account are located.

Ignore Control Tower related parameters when running CDK / CloudFormation.

After deployment, check the ARN of the IAM Role used in the Lambda function aes-siem-es-loader.

e.g. `arn:aws:iam::123456789012:role/aes-siem-LambdaEsLoaderServiceRoleXXXXXXXXXXXX-XXXXXXXXXXXXXX`.

Use this for the CloudFormation parameters in the next step.

### Preparation with your Log Archive account

Create an Amazon SQS and IAM Role in the Log Archive account. Use the CloudFormation Template below to create these resource, which requires the ARN of the above IAM Role in the CDK / CloudFormation parameters. The resources will be newly created and will not modify any existing resources.

[![core resource](./images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home#/stacks/create/template?stackName=siem-integration-with-control-tower&templateURL=https://aes-siem.s3.ap-northeast-1.amazonaws.com/log-exporter/siem-integration-with-control-tower.template) [Direct Link](https://aes-siem.s3.ap-northeast-1.amazonaws.com/log-exporter/siem-integration-with-control-tower.template)

Creaed resources

|resource type|resource ARN|
|------|----------|
|AWS::IAM::Role|arn:aws:iam::999999999999:role/ct-role-for-siem|
|AWS::SQS::Queue|arn:aws:sqs:us-east-1:999999999999:aes-siem-ct|
|AWS::SQS::Queue|arn:aws:sqs:us-east-1:999999999999:aes-siem-ct-dlq|

Next, configure event notifications for the S3 bucket you wish to ingest logs.

* Example of target S3 bucket
  * aws-controltower-logs-999999999999-us-east-1
  * aws-controltower-s3-access-logs-999999999999-us-east-1
* event type: all object creation events ( s3:ObjectCreated:* )
* Destination: aes-siem-ct in SQS

This completes the configuration for the Log Archive account.

Note down the information needed for the next step, which will be used for the SIEM CloudFormation Stack parameters.

e.g.

* Name of S3 bucket to ingest logs: `aws-controltower-logs-999999999999-us-east-1, aws-controltower-s3-access-logs-999999999999-us-east-1`.
* SQS ARN: `arn:aws:sqs:us-east-1:999999999999:aes-siem-ct`
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

Reference: [Optionally configure AWS KMS keys](https://docs.aws.amazon.com/controltower/latest/userguide/configure-kms-keys.html#kms-key-policy-update)

### Preparation with SIEM account

Update the CloudFormation aes-siem or siem stack and enter the Control Tower related parameters.

e.g. Control Tower Integration Parameter

|Parameter|Value|
|------|----------|
|ControlTowerLogBucketNameList|aws-controltower-logs-999999999999-us-east-1, aws-controltower-s3-access-logs-999999999999-us-east-1|
|ControlTowerSqsForLogBuckets|arn:aws:sqs:us-east-1:999999999999:aes-siem-ct|
|ControlTowerRoleArnForEsLoader|arn:aws:iam::999999999999:role/ct-role-for-siem|

Immediately after configuration, log ingestion may fail, but will succeed once a new instance of the Lambda function (es-loader) is created. Alternatively, manually deploying the es-loader and forcing it to launch a new instance will resolve the error.

This completes the log ingestion configuration for the Log Archive account.

## SAML federation

You can use AWS IAM Identity Center in Control Tower to control who has access to OpenSearch with single sign-on. Once users have logged into the portal, they can log into OpenSearch with a single click. This process assumes that your identity source is an Identity Center directory. If you are using other sources, please change accordingly.

Enable single sign-on with OpenSearch Roles for users belonging to his IAM Identity Center group below. Please change the permissions accordingly

**For OpenSearch Service**

|IAM Identity Center Group|OpenSearch Role|Description|
|---|---|----|
|OpenSearchDashboardsSuperUsers|security_manager<br>all_access|all permissions|
|OpenSearchDashboardsAdmins|all_access|all permissions except security|
|OpenSearchDashboardsReadOnlyUsers|opensearch_dashboards_user<br>readall_and_monitor|read only permissions to indices|

**For OpenSearch Serverless**

|IAM Identity Center Group|OpenSearch Serverless Data Access Policy|Description|
|---|---|----|
|OpenSearchDashboardsSuperUsers|Alias and templates permissions<br>aoss:\*<br>Index permissions<br>aoss:\*|all permissions|
|OpenSearchDashboardsAdmins|Index permissions<br>aoss:*|read/write permissions to indices|
|OpenSearchDashboardsReadOnlyUsers|Index permissions<br>aoss:ReadDocument<br>aoss:DescribeIndex|read only permissions to indices|

We recommend that you log in to your two AWS accounts with separate browsers to set up your IAM Identity Center and Amazon OpenSearch Service accounts alternately.

1. Open the [AWS IAM Identity Center console](https://console.aws.amazon.com/singlesignon) for your Control Tower administrator account in the first browser
1. Create a group in the above IAM Identity Center and note the group ID for each

### Add and configure the application in AWS IAM Identity Center

Adding OpenSearch Service or OpenSearch Serverless to your application.

1. Open the [AWS IAM Identity Center console](https://console.aws.amazon.com/singlesignon) for your Control Tower management account in the first browser
1. Select **[Applications]** in the navigation pane on the left side of the screen
1. Select **[Add Application]**
1. On the [Select an application] page, select **[Add custom SAML 2.0 application]**. Then select Next
1. On the [Configure application] page, for [Display Name], enter **[SIEM Dashboards]**. [Description] field is optional
1. Select **[Download]** for [IAM Identity Center SAML metadata file] to download the metadata. An example filename is `Custom SAML 2.0 application_ins-abcdef1234567890.xml`

Stay in this state and set up OpenSearch SAML authentication from the second browser

Reference: [Custom SAML 2.0 applications](https://docs.aws.amazon.com/singlesignon/latest/userguide/samlapps.html)

### Amazon OpenSearch Service SAML Authentication

This configuration is for when using a managed instance of the OpenSearch Service. Skip this section if you are using OpenSearch Serverless.

1. Open [Amazon OpenSearch Service console](https://console.aws.amazon.com/singlesignon) for your SIEM account in the second browser
1. Select **[Domains]**, **[aes-siem]** in the navigation pane on the left side of the screen. If you have changed the domain name, select the domain name you set yourself
1. Select **[Actions]** at the top right of the screen, then **[Edit security configuration]**
1. In the [SAML authentication for OpenSearch Dashboards/Kibana] panel, check **[Enable SAML authentication]**
1. Under [Metadata from IdP], select **[Import from XML file]** to upload the XML file you downloaded from IAM Identity Center. An example filename is `Custom SAML 2.0 application_ins-abcdef1234567890.xml`.
1. Enter **[Group ID of OpenSearchDashboardsSuperUsers]** from IAM Identity Center in [SAML master backend role - optional]. e.g. `abcd1234-5678-9012-3456-111111111111`
1. Select **[Additional settings]** to see advanced options
1. Enter **[ Group ]** in [Roles key - optional]
1. Change [Session time to live] to any time
1. Select **[Save Changes]** to finish configuration in OpenSearch
1. Select **[Actions]**, then **[Edit security configuration]** to view the SAML related parameters for your reference. We will use it in the next section.

Stay in this state and return to the IAM Identity Center

Reference: [SAML authentication for OpenSearch Dashboards](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/saml.html)

### Amazon OpenSearch Serverless SAML Authentication

This configuration is for when using OpenSearch Serverless collections. Skip this section if you have already configured with a managed instance of the OpenSearch Service.

SAML authentication

1. Open [Amazon OpenSearch Service console](https://console.aws.amazon.com/singlesignon) for your SIEM account in the second browser
1. Select Serverless **[SAML Authentication]**, then **[Create SAML Provider]** in the left navigation pane
1. On [Create a SAML provider] screen enter **[ iam-identity-center ]** for Name
1. Under [Step 3: Provide metadata from your IdP], select **[Import from XML file]** and upload the XML file you downloaded from IAM Identity Center. An example filename is `Custom SAML 2.0 application_ins-abcdef1234567890.xml`.
1. For [Group attribute - optional], enter **[ Group ]**
1. Change [OpenSearch Dashboards timeout] to whatever time you want
1. Select **[Create SAML Provider]** to finish SAML authentication configuration

Data access policies

1. In the navigation pane on the left of the screen, select Serverless **[Data access policies]**, then **[Create access policy]**
1. On [Create access policy] screen, enter **[ siem-superusers ]** for the access policy name
1. Select **[Add principals]** for Rule 1 and select **[Select SAML users and groups]**
    1. Select **[ SAML/123456789012/iam-identity-center ]** for [SAML provider name]
    1. For [SAML users or groups], enter **[ group/Group ID of OpenSearchDashboardsSuperUsers ]**. e.g. `group/12345678-1234-5678-abcd-111111111111`
    1. Select **[Save]**
1. Select **[Grant]**
    1. Select **[Select all]** for [Alias and templates permissions]
    1. Enter **[ aes-siem ]** in the text box and enter the return key. Please change the collection name accordingly.
    1. Select **[Select all]** for [Index permissions]
    1. Enter **[ aes-siem ]** in [Select collection] and enter the return key. Please change the collection name accordingly.
    1. Enter the wildcard **[ * ]** in [Specific indexes or index patterns]
    1. Select **[Save]**
1. Select **[Save]** to finish creating the access policy

Reference: [SAML authentication for Amazon OpenSearch Serverless](https://docs.aws.amazon.com/ja_jp/opensearch-service/latest/developerguide/serverless-saml.html)

### SAML Authentication Configuration in AWS IAM Identity Center

Return to the IAM Identity Center in the first browser and configure the rest of your SAML federation.

1. Change [Session duration] to any time
1. Select **[Manually type your metadata values]** in [Application metadata] and enter parameters while referring to OpenSearch SAML authentication parameters.

    **For OpenSearch Service**

    | IAM Identity Center |<<| OpenSearch | example |
    |---------------------|--|------------|--|
    | Application ACS URL |<<| IdP-initiated SSO URL | `https://search-aes-siem-abcd1234567890ulzml47mmaui.us-east-1.es.amazonaws.com/_dashboards/_opendistro/_security/saml/acs/idpinitiated` |
    | Application SAML audience |<<| Service provider entity ID | `https://search-aes-siem-abcd1234567890ulzml47mmaui.us-east-1.es.amazonaws.com` |

    **For OpenSearch Serverless**

    | IAM Identity Center |<<| OpenSearch Serverless|例|
    |---------------------|--|------------|----|
    | Application start URL - (optional) |<<| *not optional*<br>OpenSearch Dashboards URL | `https://abcdef1234567890123456.us-east-1.aoss.amazonaws.com/_dashboards`|
    | Application ACS URL |<<|[SAML authentication]<br>Assertion consumer service (ACS) URL |`https://collection.us-east-1.aoss.amazonaws.com/_saml/acs`|
    | Application SAML audience |<<|aws:opensearch:\<SIEM Account ID\> | `aws:opensearch:123456789012` |

1. Select **[Submit]** to finish SAML authentication configuration

Next, set the attribute mapping.

1. Select **[Actions]** at the top right of the screen, then **[Edit attribute mappings]**
1. Enter the following attributes
    |User attribute in the application|Maps to this string value or user attribute in IAM Identity Center|Format|
    |---------------------------|-------|---------|
    |Subject| **${user:subject}** |unspecified|
    |**Group**| **${user:groups}** |unspecified|
1. Select **[Save Changes]**.

Then specify the groups that are authorized to login

1. Select **[Assign users]**
1. Select the **[Groups]** tab from the tab menu and select **[OpenSearchDashboardsSuperUsers]**
1. Select **[Assign Users]**

Configuration of the management user is complete. Next, configure general user settings

### Adding general user group to Amazon OpenSearch Service

Describes how to add general user group to Fine-grained access control of OpenSearch

1. In the second browser, log in to OpenSearch Dashboards as management user with SAML authentication
1. From the pull-down menu at the top left of the screen, select **[Security]**, then **[Roles]**
1. Select **[all_access]** for Role.
1. Select **[Mapped users]** in the tab menu
1. Select **[Manage mappings]**
1. Select **[Add another backend role]**
1. Enter **[Group ID of OpenSearchDashboardsAdmins]** from IAM Identity Center in [SAML master backend role - optional]. e.g. `abcd1234-5678-9012-3456-222222222222`
1. Finished adding the group OpenSearchDashboardsAdmins
1. To add the group OpenSearchDashboardsReadOnlyUsers, map the IAM Identity Center group ID to the OpenSearch Role below as well
    | OpenSearch Role | Backend roles |
    |-----------------|---------------------------|
    | opensearch_dashboards_user | Group ID for OpenSearchDashboardsReadOnlyUsers |
    | readall_and_monitor | Group ID for OpenSearchDashboardsReadOnlyUsers |

Repeat this configuration if you want to create another user group

### Adding general user group to Amazon OpenSearch Serverless

Describes how to add the OpenSearchDashboardsAdmins group to Amazon OpenSearch Serverless

1. Open your SIEM account's [Amazon OpenSearch Service console](https://console.aws.amazon.com/singlesignon) in the second browser
1. In the navigation pane on the left of the screen, select Serverless **[Data access policies]**, then **[Create access policy]**
1. On [Create access policy] screen, enter **[ siem-admins ]** for the access policy name
1. Select **[Add principals]** for Rule 1 and select **[Select SAML users and groups]**
    1. Select **[ SAML/123456789012/iam-identity-center ]** for [SAML provider name]
    1. For [SAML users or groups], enter **[ group/Group ID of OpenSearchDashboardsAdmins ]**. e.g. `group/12345678-1234-5678-abcd-222222222222`
    1. Select **[Save]**
1. Select **[Grant]**
    1. **Select nothing** for [Alias and templates permissions]
    1. Select **[Select all]** for [Index permissions]
    1. Enter **[ aes-siem ]** in [Select collection] and enter the return key. Please change the collection name accordingly.
    1. Enter the wildcard **[ * ]** in [Specific indexes or index patterns]
    1. Select **[Save]**
1. Select **[Save]** to finish creating the access policy **[ siem-admins ]**

1. Select **Save** to update the access policy **[ siem-admins ]**

Then add the OpenSearchDashboardsReadOnlyUsers group

1. In the navigation pane on the left of the screen, select Serverless **[Data access policies]**, then **[Create access policy]**
1. On [Create access policy] screen, enter **[ siem-readonly-users ]** for the access policy name
1. Select **[Add principals]** for Rule 1 and select **[Select SAML users and groups]**
    1. Select **[ SAML/123456789012/iam-identity-center ]** for [SAML provider name]
    1. For [SAML users or groups], enter **[ group/Group ID of OpenSearchDashboardsReadOnlyUsers ]**. e.g. `group/12345678-1234-5678-abcd-333333333333`
    1. Select **[Save]**
1. Select **[Grant]**
    1. **Select nothing** for [Alias and templates permissions]
    1. Select **[Describe]** and **[Read documents]** for [Index permissions]
    1. Enter **[ aes-siem ]** in [Select collection] and enter the return key. Please change the collection name accordingly.
    1. Enter the wildcard **[ * ]** in [Specific indexes or index patterns]
    1. Select **[Save]**
1. Select **[Save]** to finish creating the access policy **[ siem-readonly-users ]**

Repeat this configuration if you want to create another user group

### Adding general user group to IAM Identity Center

Return to the IAM Identity Center in the first browser and add the general user group

1. Select **[Application]s** in the navigation pane on the left side of the screen
1. Select the application for OpenSearch Service
1. Select **[Assign Users]**
1. Select the **[Groups]** tab from the tab menu and select **[OpenSearchDashboardsAdmins]** and **[OpenSearchDashboardsReadOnlyUsers]**
1. Select **[Assign Users]**

SAML authentication configuration is now complete
