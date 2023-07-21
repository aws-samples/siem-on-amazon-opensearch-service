# Deployment to OpenSearch Serverless (Experimantal)
<!-- markdownlint-disable-file MD033 -->

[View this page in Japanese (日本語)](serverless_ja.md) | [Back to README](../README.md)

This page explains how to deploy SIEM on OpenSearch to Amazon OpenSearch Serverless and notes.

## Introduction

Please note that there are differences from Managed Cluster because the service features and internal versions are different when deploying SIEM on OpenSearch to Amazon OpenSearch Serverless.

|Difference|OpenSearch managed cluster|OpenSearch Serverless|
|----------|--------------------------|---------------------|
| Index and Shard management | Managed by the user | Managed by the service and no user management required. Automatic scaling |
| Maximum number of indices and shards | 1000 shards per instance | [Time series Collection]<br>Up to 120 indices<br>[Search Collection]<br>Up to 20 indices<br>* Please refer to the following quota page |
| [Security Analytics](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/security-analytics.html) | Available since OpenSearch 2.5 | Not implemented |
| Index name and rotation | The index name is given the selected date and automatically rotated | The index name is fixed and manually numbered (e.g. log-aws-xxxx-001) |
| Deduplication | Duplicate logs are excluded and not loaded into OpenSearch | [Time series collection]<br>Not deduplicated. It is deduplicated only when processed by the same es-loader Lambda instance<br> [Search collection]<br>Deduplicated |
| Sorting, aggregations | It can be changed by configuration. The default configuration for SIEM is 200 | [doc_values](https://opensearch.org/docs/latest/field-types/supported-field-types/keyword/#parameters) is up to 100 fields. Please be careful when importing logs with many fields |

Please refer to the official documentation for the differences as a service.

* [Comparing OpenSearch Service and OpenSearch Serverless](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-overview.html#serverless-comparison)
* [Amazon OpenSearch Service quotas](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/limits.html)

## Preparation

### Access from within VPC

If you want to load logs into OpenSearch Serverless from within VPC, create an Amazon OpenSearch Serverless (AOSS) VPC Endpoint in your VPC. If you have public access, skip this step.

1. Create a VPC
1. Create an AOSS Endpoint
1. Create a Security Group that allows inbound tcp/443 and associate it with the AOSS Endpoint.

### OpenSearch Serverless Collection

AWS CDK or AWS CloudFormation templates create a new OpenSearch Serverless collection with the following parameters:

1. Collection name: The name specified in the DomainOrCollectionName parameter
1. Collection type: Time series
1. Network access type: Public
1. Encryption: AWS owned key

If you need a collection with different parameters, please create it yourself in advance.

Please choose one of the following encryption keys:

Only [AWS owned key] is supported for encryption in the SIEM solution.

## Deploying SIEM

1. Run the AWS CDK or CloudFormation template.
1. Parameters
    * Select [opensearch_serverless] for `DeploymentTarget`
    * Enter [any collection name] for `DomainOrCollectionName`. If you want to use an existing collection, enter [existing collection name].
    * If you want to access from within VPC, enter [AOSS Endpoint ID] for `VpcEndpointId`
    * Other parameters are common to Managed Cluster installation.
1. Configure data access policy for OpenSearch Dashboards.

## Configuring data access policy

CDK/CloudFormation only sets the policy required to load logs. Please manually set the policy to login to OpenSearch Dashboards.

Example:

1. Select [Data access policies] from the left menu
1. Select [Create access policy]
    1. Enter [any policy name] in Access policy name. Example: `dashboards-access`
    1. Enter the IAM that allows access in [Add principals]
    1. Select [Grant] in Resources and Permissions
        1. Select [Select all] in "Alias and templates permissions"
        1. Enter the CloudFormation-specified [Collection Name] in Collections field
        1. Select [Select all] in "Index permissions"
        1. Enter the CloudFormation-specified [Collection Name] in Collection field
        1. Enter `*` for Index Name.

## Known Issue

* When logging, internal errors such as "Internal error occurred while processing request" may occur. Automatic retry processing is performed, but if it fails continuously, the log will be moved to DLQ. Please execute Dead-letter queue redrive.
