# 配置 AWS 服务

[In English](configure_aws_service.md) | [Back to README](../README_zh-cn.md)

在此页面上，我们将引导您了解如何将每个 AWS 服务的日志加载到 Amazon OpenSearch Service 上的 SIEM。 按照以下步骤配置每个 AWS 服务。

## Table of contents

1. [基本配置](#1-Common-Configurations)
1. [安全身份与合规](#2-Security-Identity--Compliance)
    * [Amazon GuardDuty](#Amazon-GuardDuty)
    * [Amazon Inspector](#Amazon-Inspector)
    * [AWS Directory Service](#AWS-Directory-Service)
    * [AWS WAF](#AWS-WAF)
    * [AWS Security Hub](#AWS-Security-Hub) - Still not support in AWS China Region （该功能在China Region不支持）
    * [AWS Network Firewall](#AWS-Network-Firewall) - Still not support in AWS China Region （该功能在China Region不支持）
1. [管理与治理](#3-Management--Governance)
    * [AWS CloudTrail](#AWS-CloudTrail)
    * [AWS Trusted Advisor](#AWS-Trusted-Advisor)
1. [网络及内容交付](#4-Networking--Content-Delivery)
    * [Amazon CloudFront](#Amazon-CloudFront)
    * [Route 53 Resolver VPC DNS 查询日志](#Route-53-Resolver-VPC-DNS-Query-Logging)
    * [Amazon Virtual Private Cloud (Amazon VPC) Flow Logs](#Amazon-VPC-Flow-Logs)
    * [Elastic Load Balancing (ELB)](#Elastic-Load-Balancing-ELB)
1. [存储](#5-Storage)
    * [Amazon FSx for Windows File Server audit log](#Amazon-FSx-for-Windows-File-Server-audit-log)
    * [Amazon Simple Storage Service (Amazon S3) access logs](#Amazon-S3-access-logs)
1. [数据库](#6-Database)
    * [RDS (Aurora MySQL / MySQL / MariaDB)](#RDS-Aurora-MySQL--MySQL--MariaDB-Experimental-Support)
    * [RDS (Aurora PostgreSQL / PostgreSQL)](#RDS-Aurora-PostgreSQL--PostgreSQL-Experimental-Support)
1. [分析](#7-Analytics)
    * [Amazon Managed Streaming for Apache Kafka (Amazon MSK)](#Amazon-MSK)
1. [计算](#8-Compute)
    * [EC2 Instance (Amazon Linux 2)](#EC2-Instance-Amazon-Linux-2)
    * [EC2 Instance (Microsoft Windows Server 2012/2016/2019)](#EC2-Instance-Microsoft-Windows-Server-201220162019)
1. [容器](#9-Containers)
    * [FireLens for Amazon ECS](#FireLens-for-Amazon-ECS)
1. [最终用户计算](#10End-User-Computing)
    * [Amazon WorkSpaces](#Amazon-WorkSpaces)
1. [多区域 / 多账户](#11-Multiple-regions--multiple-accounts)
1. [从现有的S3存储桶加载](#12-Loading-logs-from-an-existing-S3-bucket)

## 1. 基本配置

SIEM on Amazon OpenSearch Service 根据在S3 存储桶上的对象名称和路径名确定相对应的日志类型。
有的AWS服务服务导出日志到S3存储桶的路径，默认的是带输出路径或文件名的。但如果要输出到 S3 的文件路径与默认值不同，请创建 user.ini 并将您自己的文件名或 S3 对象键添加到“s3_key”项中，以进行自定义的映射。
有关如何编辑 user.ini 的信息，请参阅 [Change SIEM on OpenSearch Service Settings] (configure_siem_zh.md)。

当然您也可以自定义设置输出路径到 S3 存储桶，请在输出路径（前缀）中包含您的 AWS 账户 ID 和区域 (Region)。这些信息将被附加到日志中。但是如果该信息已包含在日志中，则将优先考虑日志中的信息。

如果您想使用 AWS Key Management Service (AWS KMS) 加密存储在 S3 存储桶中的文件，请使用 OpenSearch on Amazon Service 部署时自动创建的 AWS KMS 客户管理密钥。默认情况下，KMS Key别名为 aes-siem-key。您还可以使用现有的 AWS KMS 客户管理密钥，在这种情况下，请参考高级部署 (deployment_zh.md)。

此处描述的 AWS 帐户是 **123456789012**。根据需要将其替换为您的 AWS 账户ID。

## 2. 安全身份与合规

### Amazon GuardDuty

![GuardDuty to S3](images/guardduty-to-s3.jpg)

s3_key 初始值: `GuardDuty` (其为缺省输出路径中的一部分)

1. 登录 AWS 管理控制台
1. 导航到 [GuardDuty](https://console.amazonaws.cn/guardduty/home?) 控制台
1. 从左侧导航栏中选择 [**Settings**]
1. 跳到 [Findings export options] 部分
1. Frequency for updated finding :选择[**Update CWE and S3 every 15 minutes**]，然后选择[**Save**]（推荐）
1. S3存储桶选择[**Configure now**]并输入以下参数 :
    * 选择 [**Existing bucket  In your account**]
    * Choose a bucket :选择[**aes-siem-123456789012-log**]
       * 将 123456789012 替换为您的 AWS 账户 ID
    * Log file prefix :保持空白，无需输入任何值
    * KMS encryption :选择 [**Choose key from your account**]
    * Key Alias :选择 [**aes-siem-key**]
    * 点击 [**Save**]

配置现已完成。 选择 [**Generate sample findings**] 以验证是否已成功加载。

### Amazon Inspector

由于 EventBridge在China Region 还未支持Kinesis Firehose集成，所以SIEM on Amazon OpenSearch Service还不能在China Region支持 Inspector服务。

### AWS Directory Service

![Directory Service to S3](images/directoryservice-to-s3.jpg)

 s3_key 初始值 : `/DirectoryService/MicrosoftAD/` (在 Firehose 输出路径中指定)

1. 导航至 [Directory Service Console](https://console.amazonaws.cn/directoryservicev2/home?) 并转发日志到CloudWatch。
1. 使用如下的Cloudformation 文件进行配置。
    * [siem-log-exporter-core-china.template](https://raw.githubusercontent.com/aws-samples/siem-on-amazon-opensearch-service/v2.8.0-beta.2/deployment/log-exporter/siem-log-exporter-core.template)
    * [siem-log-exporter-ad-china.template](https://raw.githubusercontent.com/aws-samples/siem-on-amazon-opensearch-service/v2.8.0-beta.2/deployment/log-exporter/siem-log-exporter-ad-china.template)

### AWS WAF

![aws waf to s3](images/waf-to-s3.jpg)

AWS WAF 有两种类型 :AWS WAF 和 AWS WAF Classic。 这两种服务都可以以相同的方式将两者的日志输出到 S3 存储桶。
s3_key 的初始值 :`aws-waf-logs-`
AWS WAF ACL 流量日志从 Kinesis Data Firehose 导出到 S3 存储桶。 Kinesis Data Firehose 名称必须以 [**aws-waf-logs-**] 开头，并且由于在输出到 S3 存储桶时文件名中包含此前缀，因此我们使用它来确定日志类型。

#### I. AWS WAF 基本配置

首先，部署 Kinesis Data Firehose

1. 导航至 [](https://console.amazonaws.cn/kinesis/home?)Amazon Kinesis 管理界面并选择 **AWS WAF 所部署的 Region**
1. 在左侧的导航栏选择 [**Delivery streams**], 进入页面后点击 [**Create delivery stream**] 按钮。
1. 在 [New delivery stream] 界面, 输入如下参数:
   * Source: 选择 [**Direct PUT or other sources**]
   * Destination: 选择 [**Amazon S3**]
1. 在 [Transform and convert records - optional] 界面, 选择如下参数:
   * Data transformation: [**Disabled**]
   * Record format conversion: [**Disabled**]
   * 选择 [**Next**]
1. 在 [Choose a destination] 界面, 选择或输入如下参数:
   * S3 bucket: [**aes-siem-123456789012-log**]
      * 使用您自己的AWS Account ID 替换 123456789012
   * S3 前缀: 输入 [**AWSLogs/123456789012/WAF/region/**]
   * S3 错误 前缀: Enter [**AWSLogs/123456789012/WAF/region/error/**]
      * 使用您自己的AWS Account ID 替换 123456789012，使用您当前使用的 Region ID 替换, 例如 (cn-northwest-1) .
1. 在 [Buffer hints, compression and encryption] 界面, 输入如下参数:
   * Buffer size: 选择 5 MiB 或者自定义值 [**any number**]
   * Buffer interval: 选择300 seconds或者输入 [**any number**]
   * S3 compression: 选择 [**GZIP**]
   * 其他参数保持默认值
   * 选择 [**Next**]
1. 点击 [**Create delivery stream**]

#### II. 在 AWS WAF 中配置日志信息

1. 导航至 [WAFv2 console](https://console.amazonaws.cn/wafv2/home?)
1. 在左侧的导航菜单中选择 [**Web ACLs**]
1. 从屏幕中央的下拉菜单中，选择您部署 WAF 所在的 [**region**] ，例如 China(BeiJing) 或者 China(Ningxia), => 然后选择 Web ACLS
1. 在 [**Logging and metrics**] 便签页中选择 => [**Enable logging**] => 选择 Kinesis Data Firehose steam
1. 在 [Amazon Kinesis Data Firehose Delivery Stream] 下拉菜单中, 选择 [**你所创建的Kinesis Firehose**]
1. 选择 [**Save**] 完成配置。

### AWS Security Hub

由于 EventBridge在China Region 还未支持Kinesis Firehose集成，所以SIEM on Amazon OpenSearch Service还不能在China Region支持 Security Hub服务。

### AWS Network Firewall

由于 AWS Network Firewall 尚未在China Region发布，所以SIEM on Amazon OpenSearch Service还不能在China Region支持 AWS Network Firewall服务。

## 3. 管理与治理

### AWS CloudTrail

![CloudTrail to S3](images/cloudtrail-to-s3.jpg)

s3_key的初始值 :`CloudTrail/`或`CloudTrail-Insight/`（默认输出路径的一部分）

按照以下步骤将 CloudTrail 日志输出到 S3 存储桶 :

1. 登录 AWS 管理控制台
1. 导航到 [CloudTrail 控制台](https://console.amazonaws.cn/cloudtrail/home?)
1. 从左窗格中选择 [**Trails**] => 选择右上角的 [**Create trail**]。
1. 在[选择路径属性]界面输入以下参数。
   * Trail Name :[**aes-siem-trail**]
   * Enable for all accounts in my organization :任何（如果该字段为灰色且您无法选中该框，请跳过此步骤）
   * Storeage location :勾选[**Use existing S3 bucket**]
   * 选择 [**aes-siem-123456789012-log**]
      * 将 123456789012 替换为您的 AWS 账户 ID
   * Prefix - optional : 留空，不需要输入任何值。
   * Log file SSE-KMS encryption :建议勾选[**Enabled**]
   * AWS KMS customer managed  :选择 [**Existing**]
   * AWS KMS alias :选择 [**aes-siem-key**]
   * Log file validation :建议勾选[**Enable**]
   * SNS notification delivery :不要勾选启用[**Enabled**]
   * CloudWatch Logs :不要勾选启用
   * Tag : 可输入任意值
1. 选择 [**Next**]
1. 在 [Choose log events] 界面, 输入如下参数:
   * Event type
      * Management events: [**checked**]
      * Data events: 可以勾选，也可以不勾选
      * Insights events: 可以勾选，也可以不勾选
   * Management events
      * API activity: 选择 [Read] 和 [Write]
      * Exclude AWS KMS events: 可以勾选，也可以不勾选
1. 选择 [**Next**]
1. 选择 [**Create trail**]

### AWS Trusted Advisor

![Trusted Advisor check result to S3](images/trustedadvisor-check-result-to-s3.svg)

s3_key初始值：`(TrustedAdvisor |trustedadvisor)` 无需设置初始值，Lambda函数将自动输出固定值。

#### 由 CloudFormation配置 (AWS Trusted Advisor)

| No | CloudFormation | 概述 |
|----------|----------------|---------------|
| 1 |[![core resource](./images/cloudformation-launch-stack-button.png)](https://console.amazonaws.cn/cloudformation/home#/stacks/create/template?stackName=log-exporter-core-resource&templateURL=https://aes-siem.s3.ap-northeast-1.amazonaws.com/siem-on-amazon-opensearch-service/v2.8.0-beta.2/log-exporter/siem-log-exporter-core-china.template) [link](https://aes-siem.s3.ap-northeast-1.amazonaws.com/siem-on-amazon-opensearch-service/v2.8.0-beta.2/log-exporter/siem-log-exporter-core-china.template) | CloudFormation的基本设置。 用于获取日志转发目的地的S3存储桶名称并创建IAM role。常用于其他 AWS 服务的基本设置。 |
| 2 |[![trustedadvisor](./images/cloudformation-launch-stack-button.png)](https://console.amazonaws.cn/cloudformation/home#/stacks/new?stackName=log-exporter-trustedadvisor&templateURL=https://aes-siem.s3.ap-northeast-1.amazonaws.com/siem-on-amazon-opensearch-service/v2.8.0-beta.2/log-exporter/siem-log-exporter-trustedadvisor-china.template) [link](https://aes-siem.s3.ap-northeast-1.amazonaws.com/siem-on-amazon-opensearch-service/v2.8.0-beta.2/log-exporter/siem-log-exporter-trustedadvisor-china.template) | 此模板用于创建Lambda函数。设置EventBridge以用于定期执行Lambda函数，并将Trusted Advisor的检查结果写入S3。|

## 4. 网络及内容交付

### Amazon CloudFront

在 AWS Global，CloudFront 有两种日志格式。一种是标准日志（访问日志），另外一种是实时日志。
关于这两种日志的区别，请参考[区别](https://docs.aws.amazon.com/zh_cn/AmazonCloudFront/latest/DeveloperGuide/logging.html)

但是在AWS China Region，只支持 Standard 日志。

#### I. CloudFront 标准日志 (访问日志)

![cloudfront starndard to s3](images/cloudfront-standard-to-s3.jpg)

 s3_key 初始值: `(^|\/)[0-9A-Z]{12,14}\.20\d{2}-\d{2}-\d{2}-\d{2}.[0-9a-z]{8}\.gz$$`

日志类型由使用正则表达式的默认输出文件名来确定。 由于CloudFront标准日志不包含 AWS 账户 ID，因此您应该将它们包含在 S3 前缀中。

1. 登录 AWS 管理控制台
1. 导航至[the Amazon CloudFront console](https://console.amazonaws.cn/cloudfront/home?)
1. 在左侧的导航栏选择 [**Distribution**]
1. 选择 [**Distribution ID**] 后，在[**Setting**]部分中点击[**Edit**]按钮
1. 在[**Standard logging**] 选择
   * 勾选 [**On**]
   * S3 bucket: [**aes-siem-123456789012-log**]
      * 使用您的AWS account ID替换 123456789012
   * Log prefix: [**AWSLogs/123456789012/CloudFront/global/distribution ID/standard/**]
      * 使用您的AWS account ID替换 123456789012, 使用 “ditribution ID” 替换 distribution ID
   * Cookie logging: 勾选[**On**]
   * 点击 [**Save Changes**] 完成配置。

### Route 53 Resolver VPC DNS 查询日志

![Amazon Linux 2 to S3](images/route53resolver-to-s3.jpg)

The initial value of s3_key: `vpcdnsquerylogs` (part of the default output path)

1. 导航至 [Route 53 Resolver console](https://console.amazonaws.cn/route53resolver/home?)
1. 在左侧的导航栏选择 [**Query logging**]
1. 在 [Configure query logging] 部分，输入如下参数：
   * Name: Enter [**any name**]
   * Destination for query logs: 选择 [**S3 bucket**]
   * Amazon S3 bucket: 选择 [**aes-siem-123456789012-log**]
      * 使用您的AWS account ID替换 123456789012。
   * VPCs to log queries for: [**Add any VPC**]
1. 选择 [**Configure query logging**] 完成配置。

### Amazon VPC Flow Logs

![VPC flog logs to S3](images/vpc-to-s3.jpg)

s3_key的初始值：`vpcflowlogs`（默认输出路径的一部分）

按照以下步骤将 VPC 流日志输出到 S3 存储桶：

1. 登录 AWS 管理控制台
1. 导航至 [Amazon VPC console](https://console.amazonaws.cn/vpc/home?)
1. 从左侧的导航栏选择 [**VPC**] 或者 [**Subnet**]  => 选择需要开启VPC Flow Log的对象。
1. 选择屏幕底部的 [**Flow logs**] 选项卡 => 选择 [**Create flow log**]
1. 在创建流日志部分上输入以下参数

   * Name: 可输入任何值
   * Filter: 任意值, 但推荐选择 [**All**]
   * Maximum aggregation interval: 任意值, 但将其设置为 1 分钟会增加日志量。
   * Destination: 选择 [**Send to an S3 bucket**]
   * S3 bucket ARN: [**arn:aws-cn:s3:::aes-siem-123456789012-log**]
      * 使用您的AWS account ID替换 123456789012。
   * Log record format: 勾选 [**Amazon Web Services default format**] 或 勾选 "Custom format" 并选择 "Log format".
   * Tags: 任意值
1. Choose [**Create flow log**]

### Elastic Load Balancing (ELB)

![elb to S3](images/elb-to-s3.jpg)

按照以下步骤将以下三个负载均衡器日志中的每一个输出到 S3 存储桶：

* Application Load Balancer(ALB)
* Network Load Balancer(NLB)
* Classic Load Balancer(CLB)

s3_key 的初始值由使用正则表达式的默认输出路径和文件名决定

* ALB: `elasticloadbalancing_.*T\d{4}Z_\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}_\w*\.log\.gz$$`
* NLB: `elasticloadbalancing_.*T\d{4}Z_[0-9a-z]{8}\.log\.gz$$`
* CLB: `elasticloadbalancing_.*T\d{4}Z_\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}_\w*\.log$$`

1. 登录 AWS 管理控制台
1. 导航至 [Amazon EC2 console](https://console.amazonaws.cn/ec2/home?)
1. 从左侧的导航栏选择 [**Load balancers**] => 选择要从中收集日志的目标负载均衡器的 [**Check the box**]
1. 选择 [Description ] 标签页 => 针对 ALB/NLB/CLB 输入如下参数:
   * 如果是 ALB/NLB 类型: 选择 [**Edit attributes**]
      * Access logs: 选择 [**Enable**]
      * S3 location: 输入 [**aes-siem-123456789012-log**]
         * 使用您的AWS account ID替换 123456789012。
      * Create this location for me: 不勾选
      * 选择 [**Save**]
   * 对于 CLB 类型: 选择 [**Configure Access Logs**]
      * Enable access logs: [**checked**]
      * Interval: 选择 [**5 minutes or 60 minutes**]
      * S3 location: 输入 [**aes-siem-123456789012-log**]
         * 使用您的AWS account ID替换 123456789012。
      * Create this location for me: 不勾选
      * 选择 [**Save**] 完成配置

## 5. 存储

### Amazon FSx for Windows File Server audit log

![FSx to S3](images/fsx-to-s3.jpg)

s3_key 的初始值：`aws-fsx-`

Amazon FSx for Windows File Server 审核日志从 Kinesis Data Firehose 导出到 S3 存储桶。 Kinesis Data Firehose 名称必须以 [**aws-fsx-**] 开头，并且由于该前缀在输出到 S3 存储桶时包含在文件名中，因此我们使用它来确定日志类型。

1. 使用如下的Cloudformation进行配置
    * [siem-log-exporter-core.template](https://raw.githubusercontent.com/aws-samples/siem-on-amazon-opensearch-service/v2.8.0-beta.2/deployment/log-exporter/siem-log-exporter-core-china.template)
    * [siem-log-exporter-fsx.template](https://raw.githubusercontent.com/aws-samples/siem-on-amazon-opensearch-service/v2.8.0-beta.2/deployment/log-exporter/siem-log-exporter-fsx-china.template)
1. 导航至 [FSx Console](https://console.amazonaws.cn/fsx/home?) 把日志转发到 Firehose.

### Amazon S3 access logs

![S3 to S3](images/s3-to-s3.jpg)

按照以下步骤将 S3 访问日志输出到 S3 存储桶。 如果您已经在使用 CloudTrail 数据事件捕获 S3 日志，请单击 [此处](https://docs.aws.amazon.com/zh_cn/AmazonS3/latest/dev/logging-with-S3.html) 以查看与 S3 访问日志记录。

s3_key的初始值：`s3accesslog`（没有标准的保存路径，所以使用前缀指定）

1. 登录 AWS 管理控制台
1. 导航到 [Amazon S3 控制台](https://console.amazonaws.cn/s3/home?)
1. 从存储桶列表中，选择要从中收集日志的 S3 存储桶。

1. 选择 [**Properties**] 标签页 => [**Server access logging**]
   1. Check Enable logging
   1. Choose target bucket: aes-siem-123456789012-log
      * 使用您的AWS account ID替换 123456789012。
   1. Target prefix: [**AWSLogs/AWS account ID/s3accesslog/region/bucket name/** ]
      * 务必确保在 Prefix 中包含 [s3accesslog]
   1. 选择 [**Save**]

## 6. 数据库

### RDS (Aurora MySQL / MySQL / MariaDB) (Experimental Support)

![MySQL to S3](images/mysql-to-s3.jpg)

* Erorr log - 错误日志
* Slow query log - 慢查询日志
* General log - 基本日志
* Audit log - 审计日志

s3_key 的初始值(在Firehose output path 路径中指定)

* Erorr log: `(MySQL|mysql|MariaDB|mariadb).*(error)`
* Slow query log: `(MySQL|mysql|MariaDB|mariadb).*(slowquery)`
* General log: `(MySQL|mysql|MariaDB|mariadb).*(general)`
* Audit log: `(MySQL|mysql|MariaDB|mariadb).*(audit)`

#### 参考链接 (Aurora MySQL / MySQL / MariaDB)

* [Aurora User Guide / MySQL database log files](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_LogAccess.Concepts.MySQL.html)
* [RDS User Guide / MySQL database log files](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.Concepts.MySQL.html)
* [RDS User Guide / MariaDB database log files](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.Concepts.MariaDB.html)
* [Using advanced auditing with an Amazon Aurora MySQL DB cluster](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Auditing.html#AuroraMySQL.Auditing.Logs)
* [How do I publish logs for Amazon RDS or Aurora for MySQL instances to CloudWatch?](https://aws.amazon.com/premiumsupport/knowledge-center/rds-aurora-mysql-logs-cloudwatch/)
* [How can I enable audit logging for an Amazon RDS MySQL or MariaDB instance and publish the logs to CloudWatch?](https://aws.amazon.com/premiumsupport/knowledge-center/advanced-audit-rds-mysql-cloudwatch/)

### RDS (Aurora PostgreSQL / PostgreSQL) (Experimental Support)

![PostgreSQL to S3](images/postgresql-to-s3.jpg)

s3_key 的初始值: `Postgre` or `postgre` (在Firehose output path 路径中指定)

#### Reference (Aurora PostgreSQL / PostgreSQL)

* [Aurora User Guide / PostgreSQL database log files](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_LogAccess.Concepts.PostgreSQL.html)
* [RDS User Guide / PostgreSQL database log files](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.Concepts.PostgreSQL.html)
* [How do I enable query logging using Amazon RDS for PostgreSQL?](https://aws.amazon.com/premiumsupport/knowledge-center/rds-postgresql-query-logging/)
* [Configuring and authoring Kibana dashboards](https://aws.amazon.com/blogs/database/configuring-and-authoring-kibana-dashboards/)
* [How can I track failed attempts to log in to my Amazon RDS DB instance that's running PostgreSQL?](https://aws.amazon.com/premiumsupport/knowledge-center/track-failed-login-rds-postgresql/)

## 7. 分析

### Amazon MSK

![MSK to S3](images/msk-to-s3.jpg)

s3_key 的初始值：`KafkaBrokerLogs`（默认输出路径的一部分）

## 8. 计算

### EC2 Instance (Amazon Linux 2)

![Amazon Linux 2 to S3](images/al2-to-s3.jpg)

操作系统系统日志 -
s3_key的初始值：`/[Ll]inux/`（在Firehose输出路径中指定）

安全日志 -
s3_key的初始值：`[Ll]inux.?[Ss]ecure`（在Firehose输出路径中指定）

日志输出通过 Kinesis Data Firehose 发送，由于没有标准的保存路径，所以需要使用上面的 s3_key 作为 Kinesis Data Firehose 的目标 S3 存储桶的前缀。 由于Region信息不包含在日志中，因此您可以将Region信息其包含在 S3 Key中以捕获它。 加载安全日志有两种方式：将日志加载为操作系统系统日志，然后将其归类为安全日志； 或从一开始就将日志加载为安全日志。 前一种方法是通过进程名来确定安全日志的，所以选择后一种方法可以保证所有的安全日志都满载。 另一方面，后者要求您为每个日志设置Firehose为目的地。

请按照如下步骤配置

1. 在Amazon Linux 2 的 EC2 实例中部署安装 CloudWatch Agent，具体步骤请参考 [快速入门：在运行的 EC2 Linux 实例上安装和配置 CloudWatch Logs 代理](https://docs.aws.amazon.com/zh_cn/AmazonCloudWatch/latest/logs/QuickStartEC2Instance.html)
1. 将日志转发到 CloudWatch Logs
1. 使用 CloudWatch Logs 订阅将日志输出到 Firehose
1. 选择 S3 存储桶作为 Firehose 输出的目的地
1. 目标 S3 存储桶
    * 将日志输出为操作系统日志的前缀：[**AWSLogs/123456789012/EC2/Linux/[region]/**]
    * 将日志输出为安全日志的前缀：[**AWSLogs/123456789012/EC2/Linux/Secure/[区域]/**]
       * 将 123456789012 替换为您的 AWS 账户 ID

### EC2 Instance (Microsoft Windows Server 2012/2016/2019)

![Win Server to S3](images/al2-to-s3.jpg)

s3_key 的初始值：`/[Ww]indows.*[Ee]vent`（在Firehose输出路径中指定）

日志输出将通过 Kinesis Data Firehose 发送，由于没有标准的保存路径，所以使用上面的 s3_key 作为 Kinesis Data Firehose 的目标 S3 存储桶的前缀。 由于Region信息不包含在日志中，因此您需要将Region信息其包含在 S3 Key中以捕获它

以下是步骤的概述：

1. 在部署为 Windows Server 的 EC2 实例中安装 CloudWatch Agent
1. 将日志转发到 CloudWatch Logs
1. 使用 CloudFormation 进行配置
     * [siem-log-exporter-core-china.template](https://raw.githubusercontent.com/aws-samples/siem-on-amazon-opensearch-service/v2.8.0-beta.2/deployment/log-exporter/siem-log-exporter-core-china.template)
     * [siem-log-exporter-cwl-nocompress-china.template](https://raw.githubusercontent.com/aws-samples/siem-on-amazon-opensearch-service/v2.8.0-beta.2/deployment/log-exporter/siem-log-exporter-cwl-nocompress-china.template)
     * 输出日志的前缀：[**AWSLogs/123456789012/EC2/Windows/Event/[region]/**]
         * 将 123456789012 替换为您的 AWS 账户 ID

## 9. 容器

### FireLens for Amazon ECS

![ECS to Firelens to S3](images/ecs-to-firelens-to-s3.jpg)

s3_key 的初始值：N/A。为每个容器应用程序创建和配置 Firehose

* ECS 日志通过 Firelens (Fluent Bit) 发送到 Firehose 并输出到 S3
* 每个容器应用的日志类型由S3文件路径决定。所以你需要为每种日志类型配置 Firehose
* 容器信息是从 ECS 元数据中捕获的。 [Enable it in task definitions](https://docs.aws.amazon.com/ja_jp/AmazonECS/latest/developerguide/using_firelens.html#firelens-taskdef-metadata)
* 默认情况下，不加载 STDERR。如果要加载它，请在 user.ini 中设置 ignore_container_stderr = False。 @timestamp 是收到 SIEM 日志的时间。

配置 Kinesis Data Firehose

1. 按照 Security Hub 中的【Kinesis Data Firehose 设置】中的步骤操作。
1. 在S3的输出路径中包含决定应用的key（例如apache）
1. 因为AWS acount和region是从S3中存储的日志中捕获的，所以在S3输出路径中包含这两个参数是可选的

配置 AWS Firelens

1.Firelens发送日志的任务定义文件和IAM权限设置,请参见[官方文档](https://docs.aws.amazon.com/zh_cn/AmazonECS/latest/userguide/using_firelens.html)和 aws-samples [Send to Kinesis Data Firehose in amazon-ecs-firelens-examples](https://github.com/aws-samples/amazon-ecs-firelens-examples/tree/mainline/examples/fluent-bit/kinesis-firehose)

1. 中文Blog，请参考[使用 AWS FireLens 轻松实现 AWS Fargate 容器日志处理](https://aws.amazon.com/cn/blogs/china/easy-aws-fargate-container-log-processing-with-aws-firelens/)

配置 SIEM

1. 在 user.ini 中为每种日志类型包含以下内容

```ini
# Specifying the logs are via firelens
via_firelens = True
# Specifying whether stderr is loaded or not. Logs will not be loaded if this is True
ignore_container_stderr = True
```

## 10. 最终用户计算

### Amazon WorkSpaces

#### Event

![WorkSpaces event to S3](images/workspaces-event-to-s3.jpg)

s3_key 的初始值：`(WorkSpaces|workspaces).*(Event|event)`（在Firehose输出路径中指定）

#### Inventory

![WorkSpaces inventory to S3](images/workspaces-inventory-to-s3.jpg)

 s3_key 初始值 : `(WorkSpaces|workspaces).*(Inventory|inventory)`

1. 使用Cloudformation进行配置
     * [siem-log-exporter-core-china.template](https://raw.githubusercontent.com/aws-samples/siem-on-amazon-opensearch-service/v2.8.0-beta.2/deployment/log-exporter/siem-log-exporter-core-china.template)
     * [siem-log-exporter-workspaces-china.template](https://raw.githubusercontent.com/aws-samples/siem-on-amazon-opensearch-service/v2.8.0-beta.2/deployment/log-exporter/siem-log-exporter-workspaces-china.template)

## 11. 多 regions / 多账户

通过使用 S3 复制或跨账户输出到存储日志的 S3 存储桶，您可以将来自其他账户或区域的日志加载到 OpenSearch Service 上的 SIEM。输出路径应遵循上面配置的 S3 密钥。

## 12. 从现有的S3存储桶加载

您还可以从现有的 S3 存储桶和/或使用 AWS KMS 客户管理的密钥将日志加载到 OpenSearch Service 上的 SIEM。
要使用现有的 S3 存储桶或 AWS KMS 客户管理的密钥，您必须向 Lambda 函数 es-loader 授予权限。 请参阅 [this](deployment_zh.md) 以使用 AWS CDK 进行部署。

[Back to README](../README_zhcn.md)
