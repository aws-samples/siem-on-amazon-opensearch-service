# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2021-02-07
### Added
- Added IAM role for EC2 to import ETL existing Logs in S3 #41
- Supported timestamp with nested field #38
- Added custom metrics of es-loader for CloudWatch Metrics #13
- Enabled memory caashing of Lambda function, es-loader. When hitting cache, parsing will be 500x faster. Other logics are also tuned up #39,#45

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
