# Change Log
<!-- markdownlint-disable-file MD022 MD024 MD032-->

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.5.0] - 2021-09-13
### Added
- Extracetd WAF header #128
- Error Log number when es-loader failed to load log into opensearch service #158
- Enhanced related.* and /var/log/secure of linux log #159
### Changed
- Renamed Solution name from "SIEM on Amazon Elasticsearch Service" to "SIEM on Amazon OpenSearch Service" #157
### Fixed
- Fixed parse issue: responseElements.tableMetadataList.parameters.projection.date.interval, requestParameters.configuration. #153,#156

## [2.4.1] - 2021-08-27
### Added
- Added Amazon WorkSpaces dashboard #150
### Changed
- Updated AWS Security Hub dashboard #2
- Refactored ETL logic of firelens #149
- Partically migrated from legacy index templates to new composable ones. rollover policy, workspaces and windows events index #152
### Fixed
- Fixed logic of truncating field value which is bigger than 32,766 byte #138

## [2.4.0] - 2021-08-09
### Added
- Support Amazon ES 7.10 #103
- Supported and normalized log: Windows on EC2(XML Event Log), Amazon FSx for Windows File Server(Audit log), AWS Directory Service, Amazon WorkSpaces #118,#120,#140,#145
- Support Elastic Common Schema v1.10.0. related.* are usefull. #146
- Added CloudTrail Insight to supported service list in document #130
- Auto install script on CloudShell #65
- Automatically parsing micro epoch time #137
### Changed
- Truncated log value more than 32,766 byte #138,
- Enhanced logic of parsing MySQL/MariaDB ,multiple log patterns, using CloudWatch Log's timestamp insted of original log's timestamp, Aurota mysql v5.6 #134,#143
### Removed
- Unnecessary vpc endpoint for SNS service #132
### Fixed
- Fixed parse issue: responseElements.responseParameters.method.response.header.Access-Control-Allow-Methods, requestParameters.tableInput.parameters.projection.date.interval, requestParameters.FilterValues, requestParameters.CreateVpcEndpointRequest.TagSpecification.Tag.Value #124,#125,#136,#141
- Set default index patterns as log-* #133
- Enhanced for accurate parsing　CloudWatch log/EventBridge #127,#129,#142
- Extracting event.outcome for linux OS #126
### Security
- PR security vulnerability of urllib3 from 1.26.4 to 1.26.5 #121,#122

## [2.3.2] - 2021-05-31
### Changed
- Truncate and load longer field than 32766 byte because of Lucene limitation #102,#117

### Fixed
- Fixed parse issue: additionalEventData.bytesTransferredOut,requestParameters.CreateFleetRequest.TagSpecification.Tag.Value,requestParameters.overrides.containerOverrides.environment.value,requestParameters.CreateLaunchTemplateVersionRequest.LaunchTemplateData.TagSpecification.Tag.Value,responseElements.CreateLaunchTemplateVersionResponse.launchTemplateVersion.launchTemplateData.tagSpecificationSet.item.tagSet.item.value,requestParameters.result,requestParameters.tags,requestParameters.containerOverrides.environment.value,requestParameters.CreateSnapshotsRequest.TagSpecification.Tag.Value,requestParameters.status,requestParameters.searchExpression.subExpressions.subExpressions.filters.value,responseElements.description,responseElements.policy of CloudTrail #95,#98,#99,#100,#101,#106,#108,#109,#110,#111,#112,#113,#114
- Fixed regex pattern of ALB and CLb #115,#116

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
- Deep Security Support #27

### Fixed
- Parse issue of S3 access logs with double quotes on the UA. #34
- Parse issue of  ALB and CLB logs when IPv6 address is contained #31
- Issue with key policy created by CDK #32
- VPC config validation raises KeyError when using VPC peering instead IGW #29

## [2.1.0] - 2020-12-14
### Added
- Supported and normalized log: Security Hub(Security Hub, GuardDuty, Macie, IAM Analyzer, Inspector), Linux SSH log via CWL, ECS via Firelens(Framework only) #7
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
