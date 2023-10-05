# Change Log
<!-- markdownlint-disable-file MD022 MD024 MD032-->

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.10.2] - 2023-10-05
### Added
- Added support for Amazon OpenSearch 2.9 #409
- Added support for NGINX Web Server #408
- Added enrichment feature for source IP address with X-Forwarded-For #407
- Added support for Apache Web Server #405
- Added support for Multi-AZ with Standby #403
- Added logs exporter for EC2 instance Linux log #404
- Added documents about SAML federation of Control Tower for OpenSearch Dashboards #393
- Added Amazon Linux 2023 to CDK deployment platform #387
- Added CDK/CloudFormation parameter to keep or override Log bucket policy #372

### Changed
- Lambda instruction set architectures from x86 to Arm64 in 6 additional regions #400
- Updated AWS SDK for pandas from 3.1.0 to v3.3.0 #399
- Enhanced validation for control tower integration #396

### Deprecated
- Amazon Linux 2 for CDK deployment platform

### Fixed
- Fixed dependency issue with ExecCustomResourceValidator during deployment #406
- es_loader Error: sf_securityhub.py UnboundLocalError instanceid bug #405
- Fixed an issue where VPC Endpoint could not be created in China region.#398

## [2.10.1] - 2023-08-07
### Added
- Added STS VPC Endpoint for Control Tower/Security Lake integration when using VPC #391
- Supports AWS il-central-1/Israel (Tel Aviv) Region #390
- Added tls_connection_creation_time field to NLB #364
- Added SSM VPC Endpoint when using VPC #387

### Fixed
- Fixed s3 and sqs vpce params #389
- Fixed an error with fielddata on @id field in SecurityHub #386
- Fixed issue that caused an error when there were duplicated subnet-id in cdk.json #385
- Fixed log exclusion feature issue #384
- Fixed index_metrics_exporter issue #383

## [2.10.0] - 2023-07-21
### Added
- Supported Amazon OpenSearch 2.7 #381
- Supported general OCSF with JSON file #374
- Supported Amazon Security Lake (GA) #374,#377,#380
- Functionality of log exclusion with AND/OR conditions #376,#378
- A parameter of AWS CDK/AWS CloudFormation to use existing VPC Endpoints (when available) #337
- Supported VPC Endpoint of OpenSearch Serverless or Managed Cluster #358
- An option to add SIEM solution to existing OpenSearch cluster/serverless #333
- Supported Amazon OpenSearch Serverless #333

### Changed
- Enhanced deployment script (auto_setup_on_cloudshell.sh) on CloudShell with CDK #379
- Enhanced own log exclusion such ad es-loader/enrichment database #377
- Updated AWS SDK for pandas from 2.20.0 to v3.1.0 #373

### Fixed
- Fixed parse issue: (CloudTrail) requestParameters.resourceId,requestParameters.items #367,#382

## [2.9.1] - 2023-04-10
### Added
- Enable Amazon OpenSearch Service notifications by SNS mail #363
- Support OpenSearch 2.5 #362
- Support new GeoLite2 license format (40 digits) #360,#361
- Support ap-southeast-4 #352

### Changed
- Update index pattern and script for AWS Security Hub consolidated control #365
- Allow blank email addresses/GeoLite2 license/OTX license #359,#360

### Fixed
- fix NLB regex for new fields #364
- fix the S3 regex pattern to avoid errors when the S3 key of AWS Config History contains guardduty #355
- fix the UTF-8 encoding process for JSON files #353
- fix ZIP file extraction process #340
- fix ETL for large CSV files #338

## [2.9.0] - 2022-12-05
### Added
- Amazon Security Lake integration #334
- Enhance ETL of Windows Event Log #332
- Support eu-central-2, eu-south-2, me-central-1 and ap-south-2 #330
- Support OpenSearch 2.3 #328
- AWS Control Tower Integration #315
- Support TGW (transit gateway) flowlogs #295
### Changed
- Change CPU architecture of Lambda function to Graviton in 12 region #336
- Updated AWS Pandas SDK from 2.16.1 to 2.18.0
- Rewrite S3 Bucket Policy to load log with key prefix #3299
- Reduced privileges of IAM Role of aes-siem-deploy-role-for-lambda #317
- Increase maximum receives of SQS split from 2 to 20 #317
- Enhanced error handling of deployment script #310,#317
- Migration AWS CDK version from v1 to v2 #308
- Performance tuning for IoC enrichment #307
- Delete old v1 index templates #296
### Fixed
- Fixed node version as 16 because node 18 doesn't work on Amazon Linux 2 #322
- Fixed with permission issue with R20220323-P6 software #297,#311
- Fixed parse issue: (CloudTrail) requestParameters.disableApiStop,requestParameters.parameters,requestParameters.resource,requestParameters.target #299,#300,#303,#304,#305,#306
- Fixed typos #320

## [2.8.0] - 2022-08-30
### Added
- Support for OCSF #293
- Support for Parquet file format #275
- Enabled SQS/SNS/EventBridge to invoke es-loader (Lambda function) and load logs from Non-SIEM-managed S3 Bucket into OpenSearch Service #232,#291
- Enhance support for China region and US gov-cloud #281
- Enhance GuardDuty for malware protection #278
- Enrich logs with user-agent #273
- Support CSV delimiter #271
- Support OpenSearch Service v1.3 #270
- Enrich logs with IoC (experimental) #269
### Changed
- Expand log directory to include all logs from AWSLogs/UserLogs #291
- Updated CloudTrail dashboard #289
- Updated CloudWatch Dashboard to show AWS resources metrics $287
- Updated CloudFront dashboard $79
- Updated OpenSearch Indexing Metrics dashboard $272
- Default S3 bucket encryption #287
- Change Lambda platform CPU architecture from x86_64 to arm64 #164
### Fixed
- Fixed unnecessary loop for split logs #285
- Fixed failure to load escaped string in JSON file #284
- Fixed parse issue: (CloudTrail) responseElements.imageId, additionalEventData.requestParameters, tags.AmazonFSx/tags.AmazonFSx.FileSystemId #265,#282,#283
- Fixed parse issue: (AWS Config)
- Fixed failure to deploy in ap-northeast-3 by CDK #280
- Fixed convert_iso8601_to_datetime except logic #268
- Fixed issue with deploying with CDK #267
- Fixed issue with extracting 12 digits distribution_id of CloudFront #61

## [2.7.1] - 2022-06-05
### Added
- Access Point ARN field to s3 access log #260
- CEF File format #28,#259
- Supported and normalized log: AWS Client VPN, AWS CloudHSM #197,#253,#257
- Dashboard: AWS Client VPN, AWS CloudHSM #197,#253,#257
- Support for multiple CIDR blocks in vpc #252
### Changed
- Enhanced error handling of deplyment-aes when opensearch domain exists #262
### Fixed
- Fixed issue with updating cdk.json #261
- UnicodeEncodeError when non utf8 code includs in log #255
- Fixed regex issue: S3 accesslog #254

## [2.7.0] - 2022-04-22
### Added
- Supported OpenSearch Service version: 1.1, 1.2 #210,#237
- Supported and normalized log: AWS Trusted Advisor, Amazon Inspector #8,#207,#236
- Ability to stop log ingestion in an emergency when disk is full #44,#234
- CloudWatch dashboards to monitor SIEM status #233
- Dashboard in OpenSearch to monitor metrics of indices and shards #227
- New parsing logic of timestamp #226
### Changed
- ECS Normalization of Security Hub #239
- ECS Normalization of GuardDuty #238
- Initial version of Amazon OpenSearch Service to v1.2 from v1.0 #237
- Error handling in es-loader. Until v2.6.1, when an error occurred in es-loader, processing was stopped and all error logs were sent to SQS for reprocessing. From this version, parsing errors will not be reprocessed and will not be sent to SQS and DLQ either #231
- Reduce default number of shards: log-aws-inspector, log-aws-securityhub, log-aws-workspaces, log-aws-trustedadvisor, .opendistro-alerting-alerts, .opendistro-alerting-config, .opendistro-ism-config, .opendistro-job-scheduler-lock, #211,#228
- Increase the refresh interval #211
### Removed
- [Legacy index templates](https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates-v1.html) is removed. Please use [new index templates](https://opensearch.org/docs/latest/opensearch/index-templates/) if you configure index settings. See the [doc](docs/configure_siem.md#changing-opensearch-service-configuration-settings-for-advanced-users) #152
- KMS VPC endpoint. If you use client-side encryption, add it manually #235
### Fixed
- Fixed parse issue: (CloudTrail) responseElements.session, responseElements.database, requestParameters.imageId, requestParameters.description, responseElements.data, requestParameters.metrics, requestParameters.CreateLaunchTemplateRequest.LaunchTemplateData.TagSpecification.Tag.Value, requestParameters.parameters, requestParameters.parameters, esponseElements.status,requestParameters.settings, requestParameters.ReplicationConfiguration.Rule.Filter, responseElements.networkInterface.tagSet.items.value, requestParameters.tagSpecificationSet.items.tags.value, responseElements.tableMetadata.parameters.projection.part_date.interval, requestParameters.accountIds #163,#187,#188,#189,#190,#191,#192,#193,#240,#242,#243,#245,#246,#247,#249
- Invalid datetime format of workspaces inventory #229
- Fixed parse error of CloudTrail Insights, 0 bytes ALB access log #219,#241

## [2.6.1] - 2022-02-14
### Added
- Added connection status to Workspaces log #201
- Added 2 dashboards (S3 access log / VPC Flow Logs with v5 custom field) #198,#199
- Readme, docs, deployment script of Chinese Version #186
- CloudFormation template to exporter SecurityHub and Config to S3 bucket #184
- Another logging options for AWS WAF #185
### Changed
- Enhanced parsing logic, updated Dashboard for GuardDuty and Security Hub #179,#182,#183,#203
- Migrated new index template form legacy template of GuardDuty/Security Hub #203
- Enhanced workspace dashboard #202
- Reduced query rate of AWS API for DescribeWorkspaces #200
### Deprecated
- Legacy template is deprecated and will be obsolete in v2.7.0. Please update to index templates and component templates if you use legacy template. If you load only AWS resource log and don't configure OpenSearch settings such as field type, you can ignore. For more details, see [Index templates](https://opensearch.org/docs/latest/opensearch/index-templates/) #152
### Fixed
- Defined Inspector v2 field in Security Hub #203

## [2.6.0] - 2021-11-22
### Added
- Contribution: Okta log support. Thanks to @yopiyama #168
- Supported and normalized log: Config, Config Rules, OpenSearch audit log, ElastiCache Redis SlOWLOG #3,#119,#144
- Enable to index log to a new index when the index is read-only #161
- Enable to rename original log field name before ETL process #172
- Enable to add field prefix to original log #173
- Enable to add list field type to related.* field in aws.ini/user.ini #176
### Changed
- Change client library from Python Elasticsearch Client to OpenSearch-py #171
- Refactored parse logic of CloudWatch Logs/FireLens #171
- Enable to partially load parse error logs when logs are forwarded by FireLens, which container logs have stdout and stderr #171
- Split file format ETL logic to modules #171
- Strictly follow PEP8 and ShellCheck #171
- Updated IAM Policy/Role name and log group name for OpenSearch Service #171
### Deprecated
- Legacy template is deprecated and will be obsolete in v2.7.0. Please update to index templates and component templates if you use legacy template. If you load only AWS resource log and don't configure OpenSearch settings such as field type, you can ignore. For more details, see [Index templates](https://opensearch.org/docs/latest/opensearch/index-templates/) #152
### Fixed
- Fixed issue of parsing nano seconds #160
- Fixed regex pattern of ALB #162
- Fixed parse error of requestParameters.configuration of CloudTrail #166
- Fixed parse issue: requestParameters.command, requestParameters.schedule,requestParameters.scope,responseElements.status #167,#171,#177
- Fixed issue of deploy script and auto_setup_on_cloudshell.sh #177

## [2.5.0] - 2021-09-13
### Added
- Extracted WAF header #128
- Error Log number when es-loader failed to load log into OpenSearch Service #158
- Enhanced related.* and /var/log/secure of Linux log #159
### Changed
- Renamed Solution name from "SIEM on Amazon Elasticsearch Service" to "SIEM on Amazon OpenSearch Service" #157
### Fixed
- Fixed parse issue: responseElements.tableMetadataList.parameters.projection.date.interval, requestParameters.configuration. #153,#156

## [2.4.1] - 2021-08-27
### Added
- Added Amazon WorkSpaces dashboard #150
### Changed
- Updated AWS Security Hub dashboard #2
- Refactored ETL logic of FireLens #149
- partially migrated from legacy index templates to new composable ones. rollover policy, workspaces and windows events index #152
### Fixed
- Fixed logic of truncating field value which is bigger than 32,766 byte #138

## [2.4.0] - 2021-08-09
### Added
- Support Amazon ES 7.10 #103
- Supported and normalized log: Windows on EC2(XML Event Log), Amazon FSx for Windows File Server(Audit log), AWS Directory Service, Amazon WorkSpaces #118,#120,#140,#145
- Support Elastic Common Schema v1.10.0. related.* are useful. #146
- Added CloudTrail Insight to supported service list in document #130
- Auto install script on CloudShell #65
- Automatically parsing micro epoch time #137
### Changed
- Truncated log value more than 32,766 byte #138,
- Enhanced logic of parsing MySQL/MariaDB ,multiple log patterns, using CloudWatch Log's timestamp instead of original log's timestamp, Aurora MySQL v5.6 #134,#143
### Removed
- Unnecessary vpc endpoint for SNS service #132
### Fixed
- Fixed parse issue: responseElements.responseParameters.method.response.header.Access-Control-Allow-Methods, requestParameters.tableInput.parameters.projection.date.interval, requestParameters.FilterValues, requestParameters.CreateVpcEndpointRequest.TagSpecification.Tag.Value #124,#125,#136,#141
- Set default index patterns as log-* #133
- Enhanced for accurate parsing CloudWatch log/EventBridge #127,#129,#142
- Extracting event.outcome for Linux OS #126
### Security
- PR security vulnerability of urllib3 from 1.26.4 to 1.26.5 #121,#122

## [2.3.2] - 2021-05-31
### Changed
- Truncate and load longer field than 32766 byte because of Lucene limitation #102,#117

### Fixed
- Fixed parse issue: additionalEventData.bytesTransferredOut,requestParameters.CreateFleetRequest.TagSpecification.Tag.Value,requestParameters.overrides.containerOverrides.environment.value,requestParameters.CreateLaunchTemplateVersionRequest.LaunchTemplateData.TagSpecification.Tag.Value,responseElements.CreateLaunchTemplateVersionResponse.launchTemplateVersion.launchTemplateData.tagSpecificationSet.item.tagSet.item.value,requestParameters.result,requestParameters.tags,requestParameters.containerOverrides.environment.value,requestParameters.CreateSnapshotsRequest.TagSpecification.Tag.Value,requestParameters.status,requestParameters.searchExpression.subExpressions.subExpressions.filters.value,responseElements.description,responseElements.policy of CloudTrail #95,#98,#99,#100,#101,#106,#108,#109,#110,#111,#112,#113,#114
- Fixed regex pattern of ALB and CLB #115,#116

## [2.3.1] - 2021-05-09
### Added
- FAQ: How to reset password of master user #93
- Chinese README #83
- Automatically importing dashboard and saved objects into Global tenants #82

### Changed
- Change the default instance from t3.small to t3.medium #94

### Fixed
- Fixed parse issue: requestParameters.value, requestParameters.DescribeLaunchTemplateVersionsRequest.LaunchTemplateVersion.content, requestParameters.Tagging.TagSet.Tag.Value, requestParameters.content, requestParameters.groupDescription, requestParameters.logStreamNamePrefix, responseElements.availabilityZones of CloudTrail #84,#87,#88,#89,#90,#91,#92

### Security
- PR security vulnerability of urllib3 from 1.26.3 to 1.26.4 #85,#86

## [2.3.0] - 2021-03-20
### Added
- Supported and normalized log: AWS Network Firewall, Amazon MSK(Blokder log), Amazon RDS(MariaDB/MySQL/PostgreSQL), vpc flow logs v5 format #5,#6,#17,#62,#67,#71
- Added multiline-text log parser #54
- Enabled system log of Amazon ES instance during initial deployment #64
- Enabled parsing china region and Gov Cloud for CloudTrail #72

### Changed
- Refactored deployment script with crhelper #69
- Changed frequency of updating GeoDB from 0:20UTC to every 12 hours #70
- Changed s3_key of s3access log to regex. Users don't need to change anything #74

### Fixed
- Fixed parse issue: responseElements.credentials, requestParameters.CreateSnapshotsRequest.TagSpecification.Tag.Value, requestParameters.source, responseElements.multiAZ, requestParameters.partitionInputList, responseElements.errors.partitionValues of CloudTrail #33,#59,#66,#67,#75,#76
- Fixed issue with importing no data log #53
- Followed ECS rule for dns.question.name of vpc dns query log #60
- Fixed extracting distribution_id of CloudFront #61
- Fixed ambiguous error message like "[[], [], [], [], []]" may appear #68
- fixed ECS violation field, event.severity of Security Hub #77

### Security
- PR security vulnerability of urllib3 from 1.26.2 to 1.26.3 #78,#79

## [2.2.0] - 2021-02-07
### Added
- Added IAM role for EC2 to import ETL existing Logs in S3 #41
- Supported timestamp with nested field #38
- Added custom metrics of es-loader for CloudWatch Metrics #13
- Enabled memory caching of Lambda function, es-loader. When hitting cache, parsing will be 500x faster. Other logics are also tuned up #39,#45

### Changed
- Changing plain logging to structured logging of es-loader #13
- Allowed Amazon Athena to query S3 bucket made by SIEM #35
- Changed S3 file path of CloudFormation template. This affect only when you create own CloudFormation template #51
- Changed default Amazon ES's system index setting such as .opendistro-alerting-alert-history #48
- Limited number of es-loader's concurrency to avoid abnormal situation. Default is 10. You can change it to input CloudFormation parameter #43

### Deprecaed
- Helper functions in siem class such as merge function. Re-wrote and moved to siem.utils.py #39, #45

### Removed
- Removed legacy parsing timestamp code. It used until v1.5.2
- Removed feature of importing logs from Kinesis Data Stream

### Fixed
- Fixed SQS timeout issue in VPC #52
- Fixed parse issue, ELB logs with space(#50, #47), CloudFront Logs with IPv6(#46), non-ascii and JSON logs(#49)
- Fixed NuSuchKey error when S3 key includes meta character #42

## [2.1.1] - 2020-12-28
### Added
- Contribution: Deep Security Support. Thanks to @EijiSugiura #27

### Fixed
- Parse issue of S3 access logs with double quotes on the UA. #34
- Parse issue of ALB and CLB logs when IPv6 address is contained #31
- Issue with key policy created by CDK #32
- VPC config validation raises KeyError when using VPC peering instead IGW #29

## [2.1.0] - 2020-12-14
### Added
- Supported and normalized log: Security Hub(Security Hub, GuardDuty, Macie, IAM Analyzer, Inspector), Linux SSH log via CWL, ECS via FireLens(Framework only) #7
- Dashboard: ELB, Security Hub(GuardDuty) #1,#18
- Split and parse logs in parallel when logs are huge.
- Functionality of filtering unnecessary logs #19
- Supported nano seconds of es-loader(just truncated) #23

### Changed
- Amazon ES's initial version to v7.9.1 from v7.7.0 #24
- Increased es-loader's memory to 2048 MB from 512 MB #21
- Fix version in deployment procedure: Node(Active LTS), Python(3.8) #25,#26
- Dashboard: changed findings count logic of GuardDuty #20
- Enhanced extract logic of AWS account and region

### Fixed
- An error occurred when processing the file of size 0 byte with es-loader #15
- CLB logs parsing fails #16
- Regex error of S3 access log and CloudFront
- Typo of GuardDuty dashboard

## [2.0.0] - 2020-10-23
### Added
- All files, initial version
