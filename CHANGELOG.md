# Change Log

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
