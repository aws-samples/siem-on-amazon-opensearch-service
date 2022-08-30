# SIEM on Amazon OpenSearch Service
<!-- markdownlint-disable-file MD033 -->

[English](README.md) | [Japanese (日本语)](README_ja.md) | [Chinses (繁体中文)](README_zh-tw.md)

SIEM on Amazon OpenSearch Service 是一套免费而完整的安全性事件管理（SIEM）解决方案。让你可从多个AWS账户中收集各种日志类型，并通过日志关联与可视化协助调查安全事件。可以在约30分钟内，透过AWS Cloud开发套件（AWS SDK）或AWS CloudFormation轻松完成SIEM部署。当AWS服务日志存放到指定的Amazon Simple Storage Service (Amazon S3)存储桶后，会自动触发专门的AWS Lambda 函数，并将日志加载至 SIEM on OpenSearch Service 当中。您通过仪表板浏览各项关联记录，以便作出分析及应对。

前往 | [配置AWS服务日志来源](docs/configure_aws_service_zh-cn.md) | [OpenSearch Service上更改SIEM的配置](docs/configure_siem_zh-cn.md) | [高级部署](docs/deployment_zh-cn.md) | [仪表板](docs/dashboard_zh-cn.md) | [支持的日志类型 (英语)](docs/suppoted_log_type.md) | [FAQ](docs/faq_zh-cn.md) | [变更日志 (英语)](CHANGELOG.md) |

![Sample dashboard](./docs/images/dashboard-sample.jpg)

## 基本架构

![基本架构](./docs/images/siem-architecture.svg)

## 支持日志类型

SIEM on OpenSearch Service 能够加载并关联以下日志类型。

|       |Amazon 服务|日志|
|-------|-----------|---|
|Security, Identity, & Compliance|AWS CloudHSM|HSM audit logs|
|Security, Identity, & Compliance|Amazon GuardDuty|GuardDuty 问题清单|
|Security, Identity, & Compliance|Amazon Inspector|Inspector 问题清单|
|Security, Identity, & Compliance|AWS Directory Service|Microsoft AD|
|Security, Identity, & Compliance|AWS WAF|AWS WAF Web ACL 流量信息<br>AWS WAF Classic Web ACL 流量信息|
|Security, Identity, & Compliance|AWS Security Hub|Security Hub 问题清单<br>GuardDuty 问题清单<br>Amazon Macie 问题清单<br>Amazon Inspector 问题清单<br>AWS IAM Access Analyzer 问题清单|
|Security, Identity, & Compliance|AWS Network Firewall|Flow logs<br>Alert logs|
|Management & Governance|AWS CloudTrail|CloudTrail Log Event<br>CloudTrail Insight Event|
|Management & Governance|AWS Trusted Advisor|Trusted Advisor Check Result|
|Networking & Content Delivery|Amazon CloudFront|标准访问日志<br>实时日志|
|Networking & Content Delivery|Amazon Route 53 Resolver|VPC DNS 查询日志|
|Networking & Content Delivery|Amazon Virtual Private Cloud (Amazon VPC)|VPC Flow Logs (Version5)|
|Networking & Content Delivery|Elastic Load Balancing|Application Load Balancer 访问日志<br>Network Load Balancer 访问日志<br>Classic Load Balancer 访问日志|
|Networking & Content Delivery|AWS Client VPN|connection log 连接日志|
|Storage|Amazon FSx for Windows File Server|audit log|
|Storage|Amazon Simple Storage Service (Amazon S3)|访问日志|
|Database|Amazon Relational Database Service (Amazon RDS)<br>(**试验中**)|Amazon Aurora(MySQL)<br>Amazon Aurora(PostgreSQL)<br>Amazon RDS for MariaDB<br>Amazon RDS for MySQL<br>Amazon RDS for PostgreSQL|
|Analytics|Amazon Managed Streaming for Apache Kafka (Amazon MSK)|Broker log|
|Compute|Linux OS<br>通过 CloudWatch Logs|/var/log/messages<br>/var/log/secure|
|Compute|Windows Servver 2012/2016/2019<br>通过 CloudWatch Logs|System event log<br>Security event log|
|Containers|Amazon Elastic Container Service (Amazon ECS)<br>通过 FireLens|仅框架|
|End User Computing|Amazon WorkSpaces|Event log<br>Inventory|

我们以后有机会修改 **Database (试验中)** 日志存放内容来优化功能。

以上日志将根据 [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) 进行标準化。请[浏览此处](docs/suppoted_log_type.md)浏览此处去了解相关字段名称对照表。

## 仪表板

详见 [此处](docs/dashboard.md)

## 入门教程

在本教程中，我们将通过CloudFormation模板在OpenSearch Service上建立可被公开访问的SIEM系统。如果您需要在Amazon VPC内部署SIEM，或者调整其他自定义，请参阅[高级部署说明](docs/deployment.md)。

您可以将国家/地区信息与纬度/经度位置信息添加至各个IP地址。要获取位置信息，SIEM on OpenSearch Service将下载并使用 [MaxMind](https://www.maxmind.com) 提供的GeoLite2 Free。如果您希望添加其他位置信息，请从MaxMind获取免费许可证。

> **_注意：_** CloudFormation模板**将使用（t3.medium.search实例）部署OpenSearch Service。我们建议使用t3以上的高性能类实例来架构你的生產环境SIEM，因为在日志聚合过程中需要较为强大的处理性能。** 您可以使用Amazon管理控制台更改实例类型、扩展存储卷或使用经济实惠的 [UltraWarm](https://docs.amazonaws.cn/opensearch-service/latest/developerguide/ultrawarm.html) 储存节点。请注意，SIEM on OpenSearch Service的CloudFormation模板在设计上仅适用於初始部署目的，无法实现节点更改/删除等管理操作。

### 1. 快速入门

通过以下选项，选择SIEM on OpenSearch Service部署所在的区域： If there is no region below, please check [CloudFormation Template For All Regions](docs/cloudformation_list_zh-cn.md).

| 区域 | CloudFormation | Template URL |
|------|----------------|--------------|
| 中国 (北京) cn-north-1 |[![Deploy in cn-north-1](./docs/images/cloudformation-launch-stack-button.png)](https://console.amazonaws.cn/cloudformation/home?region=cn-north-1#/stacks/new?stackName=siem&templateURL=https://aes-siem-solutions-cn-north-1.s3.cn-north-1.amazonaws.com.cn/siem-on-amazon-opensearch-service-china.template) | `https://aes-siem-solutions-cn-north-1.s3.cn-north-1.amazonaws.com.cn/siem-on-amazon-opensearch-service-china.template` |
| 中国 (宁夏) cn-northwest-1 |[![Deploy in cn-northwest-1](./docs/images/cloudformation-launch-stack-button.png)](https://console.amazonaws.cn/cloudformation/home?region=cn-northwest-1#/stacks/new?stackName=siem&templateURL=https://aes-siem-cn-northwest-1.s3.cn-northwest-1.amazonaws.com.cn/siem-on-amazon-opensearch-service-china.template) | `https://aes-siem-cn-northwest-1.s3.cn-northwest-1.amazonaws.com.cn/siem-on-amazon-opensearch-service-china.template` |
| 美国东部 (弗吉尼亚北部) us-east-1 |[![Deploy in us-east-1](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new?stackName=siem&templateURL=https://aes-siem-us-east-1.s3.amazonaws.com/siem-on-amazon-opensearch-service.template) | `https://aes-siem-us-east-1.s3.amazonaws.com/siem-on-amazon-opensearch-service.template` |
| 亚太地区 (香港) ap-east-1 |[![Deploy in ap-east-1](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-east-1#/stacks/new?stackName=siem&templateURL=https://aes-siem-ap-east-1.s3.amazonaws.com/siem-on-amazon-opensearch-service.template) | `https://aes-siem-ap-east-1.s3.amazonaws.com/siem-on-amazon-opensearch-service.template` |
| 亚太地区 (新加坡) ap-southeast-1 |[![Deploy in ap-southeast-1](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-southeast-1#/stacks/new?stackName=siem&templateURL=https://aes-siem-ap-southeast-1.s3.amazonaws.com/siem-on-amazon-opensearch-service.template) | `https://aes-siem-ap-southeast-1.s3.amazonaws.com/siem-on-amazon-opensearch-service.template` |
| 亚太区域 (东京) ap-northeast-1 |[![Deploy in ap-northeast-1](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-northeast-1#/stacks/new?stackName=siem&templateURL=https://aes-siem-ap-northeast-1.s3.amazonaws.com/siem-on-amazon-opensearch-service.template) | `https://aes-siem-ap-northeast-1.s3.amazonaws.com/siem-on-amazon-opensearch-service.template` |

或者，您可以按照以下步骤创建自己的模板。

### 2. 创建CloudFormation模板

如果您已经在第1步中使用CloudFormation模板部署了SIEM on OpenSearch Service，请直接跳过此步骤。

#### 2-1. 先决条件

我们需要使用以下实例与工具创建CloudFormation模板:

* 运行Amazon Linux 2的Amazon EC2实例
  * "Development Tools"
  * Python 3.8
  * Python 3.8 库与头文件
  * git

如果尚未安装以上工具，请运行下列命令：

```shell
sudo yum groups mark install -y "Development Tools"
sudo yum install -y amazon-linux-extras
sudo amazon-linux-extras enable python3.8
sudo yum install -y python38 python38-devel git jq
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
```

#### 2-2. 复製SIEM on OpenSearch Service

如果尚未安装以上工具，请运行下列命令：

```shell
cd
git clone https://github.com/aws-samples/siem-on-amazon-opensearch-service.git
```

#### 2-3. 设置环境变量

```shell
export TEMPLATE_OUTPUT_BUCKET=<YOUR_TEMPLATE_OUTPUT_BUCKET> # Name of the S3 bucket where the template is loaded
export AWS_REGION=<AWS_REGION> # Region where the distribution is deployed
```

> **_注意：_** $TEMPLATE_OUTPUT_BUCKET是S3存储桶名称，你需要预先建立好这S3存储桶。此存储桶会用来存放部署过程中需要分发的文件，因此需要开放公开访问。这里的build-s3-dist.sh脚本（用於创建模板）不会创建任何S3存储桶

#### 2-4. 打包AWS Lambda函数并建立模板

```shell
cd ~/siem-on-amazon-opensearch-service/deployment/cdk-solution-helper/
chmod +x ./step1-build-lambda-pkg.sh && ./step1-build-lambda-pkg.sh && cd ..
chmod +x ./build-s3-dist.sh && ./build-s3-dist.sh $TEMPLATE_OUTPUT_BUCKET
```

#### 2-5. 将程序上传至您的Amazon S3存储桶

```shell
aws s3 cp ./global-s3-assets s3://$TEMPLATE_OUTPUT_BUCKET/ --recursive --acl bucket-owner-full-control
aws s3 cp ./regional-s3-assets s3://$TEMPLATE_OUTPUT_BUCKET/ --recursive --acl bucket-owner-full-control
```

> **_注意：_** 要运行上述命令，大家需要授予权限以将文件上传至S3存储桶。在文件上传之后，还应确保为文件设置正确的访问策略。

#### 2-6. 部署SIEM on OpenSearch Service

模板将被上传到 示例 `https://customers3bucket.s3.Region.amazonaws.com.cn/$TEMPLATE_OUTPUT_BUCKET/siem-on-amazon-opensearch-service.template` 位置。使用AWS CloudFormation即可部署这套模板。

### 3. 配置OpenSearch Dashboards

SIEM on OpenSearch Service大概需要30分钟来完成部署。随后即可着手配置OpenSearch Dashboards。

注意: OpenSearch Service 的 OpenSearch 控制面板默认安装包括地图服务，但印度和中国区域的域除外。所以在OpenSearch Service 并不能直接提供地图显示功能。如果需要显示地图，需要自行安装WMS地图服务器。

1. 导航至Amazon CloudFormation控制台，选择我们刚刚创建的堆栈，尔后选择右上选项卡清单中的“Outputs”选项。在这里，您将找到用户名、密码与OpenSearch Dashboards的URL。使用相应凭证登录至OpenSearch Dashboards。

1. 要导入仪表板等OpenSearch Dashboards配置文件，请下载 [saved_objects.zip](https://aes-siem.s3.amazonaws.com/assets/saved_objects.zip)，而后执行解压。

1. 导航至OpenSearch Dashboards控制台，点击左侧窗格中的“Management”，而后选择 "Saved Objects" --> "Import" --> "Import"。选择解压后文件夹中的 `dashboard.ndjson` 文件，而后登出并再次登录，确保所导入的配置正确起效。

### 4. 将日志加载至OpenSearch Service

要将日志加载至SIEM on OpenSearch Service，我们只需要将日志PUT进名为 **aes-siem-<YOUR_AWS_ACCOUNT>-log**.的S3存储桶内。在此之后，各日志将自动被加载至SIEM on OpenSearch Service。关於如何将Amazon服务日志输出至S3存储桶的更多操作细节，请参阅[此处](docs/configure_aws_service.md)。

## 更新SIEM

如果您希望将SIEM on OpenSearch Service更新为最新版本，请升级OpenSearch/Elasticsearch域，而后按初始设置方式（使用CloudFormation或AWS CDK）进行更新。您可以在[此处](CHANGELOG.md)查看SIEM变更日志。

### 升级OpenSearch Service域（Domain）

将OpenSearch升级至1.0版本:

1. 导航至 [OpenSearch Service控制台](https://console.amazonaws.cn/esv3/home?)
1. 选定域: [**aes-siem**]
1. 选择 [**Actions**] 图标，而后在下拉清单中选择 [**Upgrade domain**]
1. 在 "Version to upgrade to"部分，选择 [**OpenSearch 1.3**] 后选择[**Submit**]

如果您选择使用CloudFormation进行初始设置，请继续执行下一步。如果您使用AWS CDK进行初设置，请参阅[高级部署](docs/deployment.md)中的 “使用AWS CDK更新SIEM” 部分。

### 更新CloudFormation堆栈（Stack）

您可以按以下方式指定CloudFormation模板，藉此更新CloudFormation堆栈：

```text
https://aes-siem-<REGION>.s3.amazonaws.com/siem-on-amazon-opensearch-service-china.template
```

1. 导航至 [CloudFormation控制台](https://console.aws.amazon.com/cloudformation/home?)
1. 选择堆栈 [**aes-siem**]
1. 在屏幕右上方选择 [**Update**]
1. 在Update stack中，执行以下操作：
    * 准备模板: [**Replace current template**]
    * 模板来源: [**Amazon S3 URL**]
    * Amazon S3 URL:
    * 选择 [**Next**]
1. 其餘设置全部保留为默认形式，而后点击 **Next** 即可完成。

至此，更新过程即完成。

## 变更配置

### 在部署之后，变更OpenSearch Service域资源

如果您希望对OpenSearch Service域做出变更，例如变更OpenSearch Service的访问策略、变更实例类型、变更可用区或添加新可用区，或者变更UltraWarm，请通过 [OpenSearch Service 管理控制台](https://console.aws.amazon.com/es/home?) 执行变更操作。

### 管理SIEM索引与定製化设置

SIEM on OpenSearch Service将日志保存在索引当中，并每月轮换一次。如果要更改这一时间间隔或者从非Amazon服务处加载日志，请参阅[此处](docs/configure_siem.md)。

## 通过批处理方式加载已存储的日志

您可以在本地环境中执行Python脚本es-loader，藉此将存储在S3存储桶内的过往日志加载至SIEM on OpenSearch Service当中。

## 由CloudFormation模板创建的Amazon资源

以下为CloudFormation模板所能创建的Amazon资源列表。您可以从Amazon管理控制台内找到各项Amazon身份与访问管理（IAM）资源。

|AWS 资源|资源名称|用途|
|------------|----|----|
|OpenSearch Service|aes-siem|SIEM 本体|
|S3 存储桶|aes-siem-[AWS_Account]-log|用於收集日志|
|S3 存储桶|aes-siem-[AWS_Account]-snapshot|用於捕捉OpenSearch Service手动快照|
|S3 存储桶|aes-siem-[AWS_Account]-geo|用於存储下载得到的GeoIP|
|Step Functions|aes-siem-ioc-state-machine|For downloading IoC and creating database|
|Lambda 函数|aes-siem-ioc-plan|For creating map to download IoC|
|Lambda 函数|aes-siem-ioc-createdb|For downloading IoC|
|Lambda 函数|aes-siem-ioc-download|For creating IoC Database|
|Lambda 函数|aes-siem-geoip-downloader|用於下载GeoIP|
|Lambda 函数|aes-siem-es-loader|用於标準化日志，并将结果加载至OpenSearch Service|
|Lambda 函数|aes-siem-deploy-aes|用於创建OpenSearch Service域|
|Lambda 函数|aes-siem-configure-aes|用於配置OpenSearch Service|
|Lambda 函数|aes-siem-BucketNotificationsHandler|用於为存储日志的S3存储桶配置发现通知|
|Lambda 函数|aes-siem-add-pandas-layer|For adding aws_sdk_pandas as Lambda layer to es-loader|
|AWS Key Management Service<br>(AWS KMS) CMK 与别名|aes-siem-key|用於加密日志|
|Amazon SQS Queue|aes-siem-sqs-splitted-logs|如果日志中包含多个待处理行，则将各行划分为多个部分；代表用於协调的队列|
|Amazon SQS Queue|aes-siem-dlq|在将日志加载至OpenSearch Service中发生失败时，使用的**死信队列**|
|CloudWatch alarms|aes-siem-TotalFreeStorageSpaceRemainsLowAlarm|Triggered when total free space for the OpenSearch Service cluster remains less than 200MB for 30 minutes|
|CloudWatch dashboards|SIEM|Dashboard of resource information used by SIEM on OpenSearch Service|
|EventBridge events|aes-siem-EventBridgeRuleStepFunctionsIoc|For executing aes-siem-ioc-state-machine regularly|
|EventBridge events|aes-siem-EventBridgeRuleLambdaGeoipDownloader| 用於每天执行aes-siem-geoip-downloader|
|EventBridge events|aes-siem-EventBridgeRuleLambdaMetricsExporter| For executing aes-siem-geoip-downloader every 1 hour|
|EventBridge events|aes-siem-EsLoaderStopperRule|For passing alarm events to es-loader-stopper|
|Amazon SNS Topic|aes-siem-alert|被选定为OpenSearch Service中的警报发送目的地|
|Amazon SNS Subscription|inputd email|作为警报发送目标的电子邮件地址|

## 资源清理

1. 导航至CloudFormation控制台并删除堆栈: aes-siem
2. 手动删除以下Amazon资源：
    * OpenSearch Service域: aes-siem
    * Amazon S3存储桶: aes-siem-[AWS_Account]-log
    * Amazon S3存储桶: aes-siem-[AWS_Account]-snapshot
    * Amazon S3存储桶: aes-siem-[AWS_Account]-geo
    * AWS KMS客户託管密钥: aes-siem-key
        * **请谨慎执行删除操作**。在删除此客户託管密钥之后，您将无法访问使用此密钥进行加密的日志记录。
3. 如果您将SIEM on OpenSearch Service部署至Amazon VPC之内，请同时删除以下Amazon资源：
    * Amazon VPC: aes-siem/VpcAesSiem (如果您创建了新VPC)
    * SecurityGroup: aes-siem-vpc-sg

> **_注意：_** 如果您希望在删除之后立即重新部署SIEM on OpenSearch Service，请使用以下Amazon CLI命令删除密钥别名。否则由於KMS CMK别名仍然存在，重新部署将提示失败

```shell
export AWS_DEFAULT_REGION=<AWS_REGION>
aws kms delete-alias  --alias-name  "alias/aes-siem-key"
```

## 安全性

详见 [贡献](CONTRIBUTING.md#security-issue-notifications) 以获取更多详细信息。

## 许可证

此解决方案遵循 MIT-0 授权许可证。详见 [LICENSE](LICENSE) 文件。

此產品使用MaxMind创建的GeoLite2数据，并遵循 [CC BY-SA 4.0许可证](https://creativecommons.org/licenses/by-sa/4.0/)，详见[https://www.maxmind.com](https://www.maxmind.com)。

This product uses Tor exit list created by The Tor Project, Inc and licensed under [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/), available from [https://www.torproject.org](https://www.torproject.org)

原文连结：
[https://github.com/aws-samples/siem-on-amazon-opensearch-service/blob/main/README.md](https://github.com/aws-samples/siem-on-amazon-opensearch-service/blob/main/README.md)
