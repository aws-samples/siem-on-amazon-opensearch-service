# SIEM on Amazon Elasticsearch Service

[English](README.md) | [Japanese (日本語)](README_ja.md)

SIEM on Amazon Elasticsearch Service (Amazon ES) 是一套免費而完整的安全性資訊事件管理（SIEM）解決方案。讓你可從多個AWS賬戶中收集各種日誌類型，並通過日誌關聯與可視化協助調查安全事件。大家可以在約20分鐘內，透過AWS Cloud開發套件（AWS SDK）或AWS CloudFormation輕鬆完成SIEM部署。當AWS服務日誌存放到指定的Amazon Simple Storage Service (Amazon S3)存儲桶後，會自動觸發專門的AWS Lambda，並將日誌加載至SIEM on Amazon ES當中。您通過儀表板檢視各項關聯記錄，作出分析及應對。

跳往 | [配置AWS服務日誌來源(英語)](docs/configure_aws_service.md) | [Amazon ES上更改SIEM的配置 (英語)](docs/configure_siem.md) | [高級部署 (英語)](docs/deployment.md) | [儀表板 (英語)](docs/dashboard.md) | [支持的日誌類型 (英語)](docs/suppoted_log_type.md) | [FAQ(英語)](docs/faq.md) | [變更日誌 (英語)](CHANGELOG.md) |

![Sample dashboard](./docs/images/dashboard-sample.jpg)

## 基本架構

![基本架構](./docs/images/aes-siem-architecture.png)

## 支援日誌類型

SIEM on Amazon ES能夠加載並關聯以下日誌類型。

|       |Amazon 服務|日誌|
|-------|-----------|---|
|Security, Identity, & Compliance|AWS Security Hub|Security Hub 問題清單<br>GuardDuty 問題清單<br>Amazon Macie 問題清單<br>Amazon Inspector 問題清單<br>AWS IAM Access Analyzer 問題清單|
|Security, Identity, & Compliance|AWS WAF|AWS WAF Web ACL 流量信息<br>AWS WAF Classic Web ACL 流量信息|
|Security, Identity, & Compliance|Amazon GuardDuty|GuardDuty 問題清單|
|Security, Identity, & Compliance|AWS Network Firewall|Flow logs<br>Alert logs|
|Management & Governance|AWS CloudTrail|CloudTrail Log Event|
|Networking & Content Delivery|Amazon CloudFront|標準訪問日誌<br>實時日誌|
|Networking & Content Delivery|Amazon Route 53 Resolver|VPC DNS 查詢日誌|
|Networking & Content Delivery|Amazon Virtual Private Cloud (Amazon VPC)|VPC Flow Logs (Version5)|
|Networking & Content Delivery|Elastic Load Balancing|Application Load Balancer 訪問日誌<br>Network Load Balancer 訪問日誌<br>Classic Load Balancer 訪問日誌|
|Storage|Amazon Simple Storage Service (Amazon S3)|訪問日誌|
|Database|Amazon Relational Database Service (Amazon RDS)<br>(**試驗中**)|Amazon Aurora(MySQL)<br>Amazon Aurora(PostgreSQL)<br>Amazon RDS for MariaDB<br>Amazon RDS for MySQL<br>Amazon RDS for PostgreSQL|
|Analytics|Amazon Managed Streaming for Apache Kafka (Amazon MSK)|Broker log|
|Compute|Linux OS<br>通過 CloudWatch Logs|/var/log/messages<br>/var/log/secure|
|Containers|Amazon Elastic Container Service (Amazon ECS)<br>通過 FireLens|僅框架|

我們日後有機會修改 **Database (試驗中)** 日誌存放內容來優化功能。

以上日誌將根據 [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) 進行標準化。請[瀏覽此處](docs/suppoted_log_type.md)瀏覽此處去了解相關字段名稱對照表。


## 儀表板

詳見 [此處](docs/dashboard.md)

## 入門教學

在本教學中，我們將通過CloudFormation模板在Amazon ES上建立可被公開訪問的SIEM。如果您需要在Amazon VPC內部署SIEM，或者調整其他自定義，請參閱[高級部署說明](docs/deployment.md)。

您可以將國家/地區信息與緯度/經度位置信息添加至各個IP地址。要獲取位置信息，SIEM on Amazon ES將下載並使用 [MaxMind](https://www.maxmind.com) 提供的GeoLite2 Free。如果您希望添加其他位置信息，請從MaxMind獲取免費許可證。

_注意：_ CloudFormation模板**將使用（t3.medium.elasticsearch實例）部署Amazon ES。我們建議使用t2/t3以上的高性能類實例來架構你的生產環境SIEM，因為在日誌聚合過程中需要較為強大的處理性能。** 您可以使用Amazon管理控制臺更改實例類型、擴展存儲卷或使用經濟實惠的 [UltraWarm](https://docs.aws.amazon.com/zh_tw/elasticsearch-service/latest/developerguide/ultrawarm.html) 儲存節點。請注意，SIEM on Amazon ES的CloudFormation模板在設計上僅適用於初始部署目的，無法實現節點更改/刪除等管理操作。


### 1. 快速入門

通過以下選項，選擇SIEM on Amazon ES部署所在的區域： 

| 區域 | CloudFormation |
|--------|----------------|
| 北弗吉尼亞州  (us-east-1) |[![Deploy in us-east-1](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/new?stackName=aes-siem&templateURL=https://aes-siem-us-east-1.s3.amazonaws.com/siem-on-amazon-elasticsearch.template) |
| 俄勒岡州 (us-west-2) |[![Deploy in us-west-2](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacks/new?stackName=aes-siem&templateURL=https://aes-siem-us-west-2.s3.amazonaws.com/siem-on-amazon-elasticsearch.template) |
| 東京 (ap-northeast-1) |[![Deploy in ap-northeast-1](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=ap-northeast-1#/stacks/new?stackName=aes-siem&templateURL=https://aes-siem-ap-northeast-1.s3.amazonaws.com/siem-on-amazon-elasticsearch.template) |
| 法蘭克福  (eu-central-1) |[![Deploy in eu-central-1](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-central-1#/stacks/new?stackName=aes-siem&templateURL=https://aes-siem-eu-central-1.s3.amazonaws.com/siem-on-amazon-elasticsearch.template) |
| 倫敦 (eu-west-2) |[![Deploy in eu-west-2](./docs/images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home?region=eu-west-2#/stacks/new?stackName=aes-siem&templateURL=https://aes-siem-eu-west-2.s3.amazonaws.com/siem-on-amazon-elasticsearch.template) |

如果以上列表未包含您希望使用的區域，請手動選擇以下模板：

```text
https://aes-siem-<REGION>.s3.amazonaws.com/siem-on-amazon-elasticsearch.template
```

或者，您可以按照以下步驟創建自己的模板。 

### 2. 創建CloudFormation模板

如果您已經在第1步中使用CloudFormation模板部署了SIEM on Amazon ES，請直接跳過此步驟。

#### 2-1. 先決條件

我們需要使用以下實例與工具創建CloudFormation模板:

* 運行Amazon Linux 2的Amazon EC2實例
  * "Development Tools"
  * Python 3.8
  * Python 3.8 庫與頭文件
  * git

如果尚未安裝以上工具，請運行下列命令：

```shell
sudo yum groups mark install -y "Development Tools"
sudo yum install -y amazon-linux-extras
sudo amazon-linux-extras enable python3.8
sudo yum install -y python38 python38-devel git jq
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
```

#### 2-2. 複製SIEM on Amazon ES

如果尚未安裝以上工具，請運行下列命令：

```shell
cd
git clone https://github.com/aws-samples/siem-on-amazon-elasticsearch.git
```

#### 2-3. 設置環境變量

```shell
export TEMPLATE_OUTPUT_BUCKET=<YOUR_TEMPLATE_OUTPUT_BUCKET> # Name of the S3 bucket where the template is loaded
export AWS_REGION=<AWS_REGION> # Region where the distribution is deployed
```

##### _注意：_ $TEMPLATE_OUTPUT_BUCKET是S3存儲桶名稱，你需要預先建立好這S3存儲桶。此存儲桶會用來存放部署過程中需要分發的文件，因此需要開放公開訪問。這裏的build-s3-dist.sh腳本（用於創建模板）不會創建任何S3存儲桶

#### 2-4. 打包AWS Lambda函數並建立模板

```shell
cd ~/siem-on-amazon-elasticsearch/deployment/cdk-solution-helper/
chmod +x ./step1-build-lambda-pkg.sh && ./step1-build-lambda-pkg.sh && cd ..
chmod +x ./build-s3-dist.sh && ./build-s3-dist.sh $TEMPLATE_OUTPUT_BUCKET
```

#### 2-5. 將程序上傳至您的Amazon S3存儲桶

```shell
aws s3 cp ./global-s3-assets s3://$TEMPLATE_OUTPUT_BUCKET/ --recursive --acl bucket-owner-full-control
aws s3 cp ./regional-s3-assets s3://$TEMPLATE_OUTPUT_BUCKET/ --recursive --acl bucket-owner-full-control
```

##### _注意：_ 要運行上述命令，大家需要授予權限以將文件上傳至S3存儲桶。在文件上傳之後，還應確保爲文件設置正確的訪問策略。

#### 2-6. 部署SIEM on Amazon ES

模板將被上傳到 `https://s3.amazonaws.com/$TEMPLATE_OUTPUT_BUCKET/siem-on-amazon-elasticsearch.template` 位置。使用AWS CloudFormation即可部署這套模板。

### 3. 配置Kibana

SIEM on Amazon ES大概需要20分鐘來完成部署。隨後即可着手配置Kibana。

1.	導航至Amazon CloudFormation控制臺，選擇我們剛剛創建的堆棧和，爾後選擇右上選項卡清單中的“Outputs”選項。在這裏，您將找到用戶名、密碼與Kibana的URL。使用相應憑證登錄至Kibana。

1.	要導入儀表板等Kibana配置文件，請下載 [saved_objects.zip](https://aes-siem.s3.amazonaws.com/assets/saved_objects.zip)，而後執行解壓。

1.	導航至Kibana控制臺，點擊左側窗格中的“Management”，而後選擇 "Saved Objects" --> "Import" --> "Import"。選擇解壓後文件夾中的 `dashboard.ndjson` 文件，而後登出並再次登錄，確保所導入的配置正確起效。



### 4. 將日誌加載至Amazon ES

要將日誌加載至SIEM on Amazon ES，我們只需要將日誌PUT進名爲 **aes-siem-<YOUR_AWS_ACCOUNT>-log**.的S3存儲桶內。在此之後，各日誌將自動被加載至SIEM on Amazon ES。關於如何將Amazon服務日誌輸出至S3存儲桶的更多操作細節，請參閱[此處](docs/configure_aws_service.md)。


## 更新SIEM

如果您希望將SIEM on Amazon ES更新爲最新版本，請升級Amazon ES域，而後按初始設置方式（使用CloudFormation或AWS CDK）進行更新。您可以在[此處](CHANGELOG.md)查看SIEM變更日誌。

### 升級Amazon ES域（Domain）

將Amazon ES升級至7.9版本:
1.	導航至 [Amazon ES控制臺](https://console.aws.amazon.com/es/home?)
1.	選定域: [**aes-siem**]
1.	選擇 [**Actions**] 圖標，而後在下拉清單中選擇 [**Upgrade domain**] 
1.	在 "Version to upgrade to"部分，選擇 [**7.9**] 後選擇[**Submit**]

如果您選擇使用CloudFormation進行初始設置，請繼續執行下一步。如果您使用AWS CDK進行初設置，請參閱[高級部署](docs/deployment.md)中的 “使用AWS CDK更新SIEM” 部分。


### 更新CloudFormation堆棧（Stack）

您可以按以下方式指定CloudFormation模板，藉此更新CloudFormation堆棧：

```text
https://aes-siem-<REGION>.s3.amazonaws.com/siem-on-amazon-elasticsearch.template
```

1.	導航至 [CloudFormation控制臺](https://console.aws.amazon.com/cloudformation/home?)
1.	選擇堆棧 [**aes-siem**]
1.	在屏幕右上方選擇 [**Update**] 
1.	在Update stack中，執行以下操作：
    * 準備模板: [**Replace current template**]
    * 模板來源: [**Amazon S3 URL**]
    * Amazon S3 URL:
    * 選擇 [**Next**]
1.	其餘設置全部保留爲默認形式，而後點擊 **Next** 即可完成。

至此，更新過程即告完成。


## 變更配置

### 在部署之後，變更Amazon ES域資源

如果您希望對Amazon ES域做出變更，例如變更Amazon ES的訪問策略、變更實例類型、變更可用區或添加新可用區，或者變更UltraWarm，請通過 [Amazon ES 管理控制臺](https://console.aws.amazon.com/es/home?) 執行變更操作。


### 管理SIEM索引與定製化設置

SIEM on Amazon ES將日誌保存在索引當中，並每月輪換一次。如果要更改這一時間間隔或者從非Amazon服務處加載日誌，請參閱[此處](docs/configure_siem.md)。


## 通過批處理方式加載已存儲的日誌

您可以在本地環境中執行Python腳本es-loader，藉此將存儲在S3存儲桶內的過往日誌加載至SIEM on Amazon ES當中。

## 由CloudFormation模板創建的Amazon資源

以下爲CloudFormation模板所能創建的Amazon資源列表。您可以從Amazon管理控制臺內找到各項Amazon身份與訪問管理（IAM）資源。

|AWS 資源|資源名稱|用途|
|------------|----|----|
|Amazon ES 7.X|aes-siem|SIEM 本體|
|S3 存儲桶|aes-siem-[AWS_Account]-log|用於收集日誌|
|S3 存儲桶|aes-siem-[AWS_Account]-snapshot|用於捕捉Amazon ES手動快照|
|S3 存儲桶|aes-siem-[AWS_Account]-geo|用於存儲下載得到的GeoIP|
|Lambda 函數|aes-siem-es-loader|用於標準化日誌，並將結果加載至Amazon ES|
|Lambda 函數|aes-siem-deploy-aes|用於創建Amazon ES域|
|Lambda 函數|aes-siem-configure-aes|用於配置Amazon ES|
|Lambda 函數|aes-siem-geoip-downloader|用於下載GeoIP|
|Lambda 函數|aes-siem-BucketNotificationsHandler|用於爲存儲日誌的S3存儲桶配置發現通知|
|AWS Key Management Service<br>(AWS KMS) CMK 與別名|aes-siem-key|用於加密日誌|
|Amazon SQS Queue|aes-siem-sqs-splitted-logs|如果日誌中包含多個待處理行，則將各行劃分爲多個部分；代表用於協調的隊列|
|Amazon SQS Queue|aes-siem-dlq|在將日誌加載至Amazon ES中發生失敗時，使用的**死信隊列**|
|CloudWatch Events|aes-siem-CwlRuleLambdaGeoipDownloader| 用於每天執行aes-siem-geoip-downloader|
|Amazon SNS Topic|aes-siem-alert|被選定爲Amazon ES中的警報發送目的地|
|Amazon SNS Subscription|inputd email|作爲警報發送目標的電子郵件地址|

## 資源清理

1. 導航至CloudFormation控制臺並刪除堆棧: aes-siem
2.	手動刪除以下Amazon資源：
    * Amazon ES域: aes-siem
    * Amazon S3存儲桶: aes-siem-[AWS_Account]-log
    * Amazon S3存儲桶: aes-siem-[AWS_Account]-snapshot
    * Amazon S3存儲桶: aes-siem-[AWS_Account]-geo
    * AWS KMS客戶託管密鑰: aes-siem-key
        * **請謹慎執行刪除操作**。在刪除此客戶託管密鑰之後，您將無法訪問使用此密鑰進行加密的日誌記錄。
3.	如果您將SIEM on Amazon ES部署至Amazon VPC之內，請同時刪除以下Amazon資源：
    * Amazon VPC: aes-siem/VpcAesSiem (如果您創建了新VPC)
    * SecurityGroup: aes-siem-vpc-sg


### 如果您希望在刪除之後立即重新部署SIEM on Amazon ES，請使用以下Amazon CLI命令刪除密鑰別名。否則由於KMS CMK別名仍然存在，重新部署將提示失敗：

```shell
export AWS_DEFAULT_REGION=<AWS_REGION>
aws kms delete-alias  --alias-name  "alias/aes-siem-key"
```

## 安全性

詳見 [貢獻](CONTRIBUTING.md#security-issue-notifications) 以獲取更多詳細信息。

## 許可證

此解決方案遵循 MIT-0 授權許可證。詳見 [LICENSE](LICENSE) 文件。

此產品使用MaxMind創建的GeoLite2數據，並遵循 [CC BY-SA 4.0許可證](https://creativecommons.org/licenses/by-sa/4.0/)，詳見[https://www.maxmind.com](https://www.maxmind.com)。

原文連結：
https://github.com/aws-samples/siem-on-amazon-elasticsearch/blob/main/README.md
