# 配置 SIEM on Amazon OpenSearch Service

[View this page in Japanese (日本語)](configure_siem_ja.md) | [View this page in Chinse (简体中文)](configure_siem_zh.md) |[Back to README](../README_zhcn.md)

## 目录

* [自定义日志加载方法](#自定义日志加载方法)
* [添加排除日志加载](#添加排除日志加载)
* [更改 OpenSearch 服务配置设置（适用于高级用户）](#更改OpenSearch服务配置设置（适用于高级用户）)
* [加载非AWS相关服务日志](#加载非AWS相关服务日志)
* [加载存储在S3存储桶中的历史数据](##加载存储在S3存储桶中的历史数据)
* [监控](#监控)

## 自定义日志加载方法


您可以使用自定义日志加载方法加载日志到SIEM。当文件被存储在S3 存储桶后，会触发 es-loader lambda函数来进行处理并进行规范化，并加载到 SIEM on  OpenSearch Service 上。部署的 Lambda 函数名为 aes-siem-es-loader。而这个 Lambda 函数（es-loader）是由来自 S3 存储桶的事件通知（所有对象创建事件）触发的。然后根据文件名和 S3 存储桶的文件路径识别日志类型；以预定义的方式为每种日志类型提取字段；将其映射到 [Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html)；最后通过指定索引名称将其加载到 OpenSearch Service 上的 SIEM 中。

此过程依赖于配置文件 (aws.ini) 中定义的初始值。您也可以修改该配置文件以满足如下的定制化需求： 日志文件可以与初始值不同的文件路径导入到 S3 存储桶；重命名OpenSearch中的索引；或更改OpenSearch索引轮换时间间隔，例如您需要修改默认值，您需要按照 aws.ini 结构定义字段和值来创建一个新的 user.ini 文件。注意，在 user.ini 中设置的值优先及高于 aws.ini 中的值，从而实现内部覆盖aws.ini的初始值。

您可以通过将 user.ini 添加到 Lambda 层（推荐）或直接从 AWS 管理控制台编辑来保存 user.ini文件。请注意，每当您更新 SIEM on OpenSearch Service时，Lambda 函数都会替换为新的函数。如果您使用 Lambda 层（因为它独立于 Lambda 函数），虽然 user.ini 保持不变，但如果直接从 AWS 管理控制台编辑该文件，则会删除该文件，因此您需要再次创建它。

注意：配置文件 (aws.ini/user.ini) 是使用标准 Python3 库中的 configparser 加载的。语法和其他规则遵循此库，因此即使您在某些集合值中发现单词之间有空格，也只需按原样描述它们。无需将其括在双引号或单引号中。例如，如果您定义一个值为“This is a sample value”的键，您应该这样写：

（正确配置示例）

```ini
key = This is a sample value
```


（错误的配置示例)

```ini
key = "This is a sample value"
```

参考该链接 [this](https://docs.python.org/ja/3/library/configparser.html#module-configparser) 获得更多得的配置语法信息。

### 在AWS Lambda layer 中添加 user.ini (推荐)

创建与 aws.ini 具有相同结构的 user.ini。
示例）将 AWS CloudTrail 轮换间隔从每月（初始值）更改为每天。
aws.ini 的初始值如下： 

```ini
[cloudtrail]
index_rotation = monthly
```

创建 user.ini 并设置参数如下所示:

```ini
[cloudtrail]
index_rotation = daily
```
使用Zip压缩 user.ini 文件，以便将其添加到 Lambda 层。 请注意，user.ini 不应包含任何目录。 压缩文件可以有任何名称（在本例中我们将其命名为 configure-es-loader.zip）。

```sh
zip -r configure-es-loader.zip user.ini
```


然后按照以下步骤创建一个 Lambda 层：

1. 登录 AWS 管理控制台
1. 导航到 [AWS Lambda console](https://console.amazonaws.cn/lambda/home)
1. 从左窗格中选择 [**Layers**] => 屏幕右上角的 [**Create layer**]
1. 在Layer配置中键入以下内容：将其他字段留空。
    * 名称：aes-siem-configure-es-loader（任意名称）
    * 检查上传 .zip 文件
    * 选择上传，然后选择 configure-es-loader.zip
    * 兼容的运行时：选择 Python 3.8
1. 选择[**Create**]


最后，将刚刚创建的 Lambda 层添加到 Lambda 函数 es-loader：

1. 从 Lambda 控制台的左窗格中选择 [**Functions**] => 选择 [**aes-siem-es-loader**]
1. 在[Configuration]选项卡中，选择[Designer]窗格中央的[**Layers**]。
1.从屏幕底部的[Layers]窗格中，选择[**Add a Layer**]
1.勾选自定义Layer，从自定义图层的下拉菜单中，选择[**aes-siem-configure-es-loader**]（或者使用另外一个不同的名称）和 然后选择[**Add**]

配置现已完成。 您可以在 [Layers] 中确认添加。

### 在 AWS 管理控制台直接修改


或者，您可以直接从 AWS 管理控制台编辑 user.ini 以更改配置。

1. 登录 AWS 管理控制台
1. 导航到 [AWS Lambda console](https://console.aws.amazonaws.cn/lambda/home?)
1. 从左侧导航栏中选择 [**Functions**] => 选择函数 [**aes-siem-es-loader**]
1. 在 [Function code] 窗格中，会显示 Lambda 函数的文件列表。 在根目录下创建 user.ini 并进行添加或编辑该文件进行配置信息
1. 选择[Function code]面板右上角的【**Deploy**】按钮

配置现已完成。 请注意，每当 SIEM on OpenSearch Service 更新时，Lambda 函数 es-loader 将被替换为新函数，并且 user.ini 将被删除。 如果碰到这种情况，请重复上述过程。

## 添加排除日志加载

存储在 S3 存储桶中的日志会自动加载到 OpenSearch 服务中，但您可以通过指定条件排除其中的一些日志。 这将有助于节省 OpenSearch Service 所消耗的资源。

您可以指定两个条件：

1. S3 存储桶存储路径（对象键 object key）
1. 日志字段和值

### 添加基于 S3 存储桶文件路径（对象键）的排除项

每当 CloudTrail 或 VPC 流日志输出到 S3 存储桶时，AWS 账户 ID 和区域信息都会添加到日志中。 您可以使用此信息为日志加载添加排除项。 例如，您可以配置您的 AWS 账户不加载这些信息。

#### 如何添加排除项 :

在 user.ini (aws.ini) 中的 s3_key_ignored 所对应的字符串中指定要排除日志对象。 如果日志**包含**在那里指定的字符串，则该日志不会吧加载。 可以使用正则表达式指定字符串。 请注意，如果字符串太短或通用词，它也可能匹配您不想排除的日志。 此外，一些 AWS 资源的日志默认指定 s3_key_ignored，因此请确保先检查 aws.ini 以避免覆盖配置。

##### 示例 1) 剔除 AWS account 123456789012 from VPC flow logs --> 指定字符串

在S3 bucket中存储: s3://aes-siem-123456789012-log/AWSLogs/**000000000000**/vpcflowlogs/ap-northeast-1/2020/12/25/000000000000_vpcflowlogs_ap-northeast-1_fl-1234xxxxyyyyzzzzz_20201225T0000Z_1dba0383.log.gz

配置文件: user.ini

```ini
[vpcflowlogs]
s3_key_ignored = 000000000000
```

##### 示例 2) 剔除 AWS accounts 111111111111 and 222222222222 from vpcflowlogs --> 您可以使用使用多个字符串进行配置正则表达式，剔除多个日志

```ini
[vpcflowlogs]
s3_key_ignored = (111111111111|222222222222)
```

### 根据日志字段和值排除日志


您可以根据日志字段及其值排除日志。 例如在 VPC 流日志中，您可以排除来自特定源 IP 地址的通信。

如何添加排除项：

将包含排除条件的 CSV 文件上传到存储 GeoIP 的 S3 存储桶（默认为 aes-siem-1234567890-**geo**。）应该上传到没有前缀的根路径。

* CSV 文件名称: [**exclude_log_patterns.csv**]
* CSV 文件保存在: [s3://aes-siem-1234567890-**geo**/exclude_log_patterns.csv]
* CSV 格式: 使用以下格式，包括标题行：

```csv
log_type,field,pattern,pattern_type,comment
```

| Header | Description |
|--------|----|
| log_type | 在 aws.ini 或 user.ini 中指定的日志部分名称。 示例）cloudtrail、vpcflowlogs |
| field | 原始日志的原始字段名称。 它不是规范化的字段。 JSON 等分层字段由点 ( **. ** ) 分隔。 示例）userIdentity.invokedBy |
| pattern | 将字段的值指定为字符串。 被**完全匹配**排除。 可以使用文本格式和正则表达式。 示例）文本格式：192.0.2.10，正则表达式：192\\.0\\.2\\..* |
| pattern_type | [**regex**] 用于正则表达式， [**text**] 用于字符串 |
| comment | 任意字符串. 不会影响表达式 |

#### 配置样例

```csv
log_type,field,pattern,pattern_type,comment
vpcflowlogs,srcaddr,192.0.2.10,text,sample1
vpcflowlogs,dstaddr,192\.0\.2\.10[0-9],regex,sample2
cloudtrail,userIdentity.invokedBy,.*\.amazonaws\.com,regex,sample3
```

##### 示例 1

这不包括源 IP 地址 (srcaddr) 与 VPC 流日志中的 192.0.2.10 匹配的日志。 如果pattern_type 为文本，则文本格式需要精确匹配。 这是为了防止意外排除其他 IP 地址，例如 192.0.2.100。 即使您指定规范化的字段名称（例如 source.ip），也不会匹配或排除字段名称。

##### 示例 2

这不包括目标 IP 地址 (dstaddr) 包含字符串 192.0.2.10 的日志。 因为它与正则表达式匹配，所以192.0.2.100 也被排除在外。 如果 pattern_type 是正则表达式，那么请确保对正则表达式中具有特殊含义的字符（例如点）进行转义。

##### 示例 3

这不包括与 CloudTrail 中的 {'userIdentity': {'invokedBy': '*.amazonaws.com'}} 匹配的日志。 字段名称是嵌套的，并且应该在 CSV 中以点分隔。 在本示例中，不加载 AWS 服务调用的 API 调用日志（例如配置或日志交付）。

## 更改OpenSearch服务配置设置（适用于高级用户）

您可以更改与 SIEM 相关的 OpenSearch Service 的应用程序配置。 可以为每个索引定义以下值。

* 索引的副本数，分片数
* 字段映射，类型
* 使用索引状态管理将索引自动迁移（或删除）到 UltraWarm

虽然您可以任意地配置它们，但有些项目是在 SIEM on OpenSearch Service 中预先配置的。 您可以使用以下命令从开发工具检查预配置的值：

```http
GET target_index_name/_settings
GET target_index_name/_mapping
```


要添加或更改设置，请创建索引模板（index templates）以保存值。 避免使用已经在使用的模板名称。

SIEM on OpenSearch Service 保留关键字：

* log[-aws][-service_name]_aws
* log[-aws][-service_name]_rollover

如果要更改预先配置的值，请将 **order** 设置为 1 或更大的值以覆盖它。

配置示例：

* 使用Dev Tools 将 CloudTrail 索引 (log-aws-cloudtrail-*) 中的分片数量从 3（默认值）减少到 2

```http
POST _template/log-aws-cloudtrai_mine
{
  "index_patterns": ["log-aws-cloudtrail-*"],
  "order": 1,
  "settings": {
    "index": {
      "number_of_shards" : 2
    }
  }
}
```

## 加载非AWS相关服务日志

您可以通过将日志导出到存储日志的 S3 存储桶，将非 AWS 服务日志加载到 SIEM on OpenSearch Service。 当前所支持的文件格式包含文本、JSON 和 CSV 格式。 对于文本格式，只能加载单行日志，不支持多行日志。 您可以使用 Logstash 或 Fluentd 插件将日志导出到 S3。

以下是 Apache HTTP 服务器日志的基本配置流程：

1. 在 user.ini 中定义要加载的日志

   ```ini
   [apache]
   ```

1. 定义用于将Apache HTTP 服务器访问日志导出到S3 存储桶的文件路径、文件名等。 您可以在此处使用正则表达式。 此信息用于确定日志类型。

   ```ini
   s3_key = UserLogs/apache/access.*\.log
   ```

1. 指定文件格式

   ```ini
   file_format = text
   ```

1. 指定索引名称

   ```ini
   index_name = log-web-apache
   ```

1. 定义命名捕获正则表达式以从日志中提取字段

   ```ini
   log_pattern = (?P<remotehost>.*) (?P<rfc931>.*) (?P<authuser>.*) \[(?P<datetime>.*?)\] \"(?P<request_method>.*) (?P<request_path>.*)(?P<request_version> HTTP/.*)\" (?P<status>.*) (?P<bytes>.*)
   ```

1. 指定时间戳以通知 SIEM on  OpenSearch Service 事件发生的时间。 如果 [日期格式](https://docs.python.org/ja/3/library/datetime.html#strftime-and-strptime-format-codes) 不符合 ISO 8601 格式，请按照如下的方式自定义

   ```ini
   timestamp = datetime
   timestamp_format = %d/%b/%Y:%H:%M:%S %z
   ```

1. 指定要映射到 OpenSearch Common Schema 的字段。

   ```ini
   # Syntax
   # ecs = ECS_field_name_1 ECS_field_name_2
   # ECS_field_name_1 = original_feed_name_in_the_log
   # ECS_field_name_2 = original_feed_name_in_the_log
   ecs = source.ip user.name http.request.method url.path http.version http.response.status_code http.response.bytes
   source.ip = remotehost
   user.name = authuser
   http.request.method = request_method
   url.path = request_path
   http.version = request_version
   http.response.status_code = status
   http.response.bytes = bytes
   ```

1. 指定 ECS 字段（将用于使用 GeoIP 获取地理位置信息）。
   ```ini
   # The value is either source or destination
   geoip = source
   ```


有关配置项的更多信息，请参阅 es-loader（Lambda 函数）中的 aws.ini 配置文件。

如果此定义文件不足以处理您的逻辑，您还可以使用 Python 脚本添加自定义逻辑。 例如，您可以添加逻辑以从用户代理中提取操作系统或平台信息。 文件名应该是 sf_logtype.py。 在这个例子中，它被命名为 sf_apache.py。 如果日志类型包含 -（破折号），请将其替换为 _（下划线）。 示例）日志类型：cloudfront-realtime => 文件名：sf_cloudfront_realtime.py

将此文件保存在siem 目录下的 es-loader 文件 或 Lambda 层的 siem 目录中。

Lambda 层的压缩文件内的目录结构应如下所示：

```text
|- user.ini
|- siem
    |- sf_apache.py
    |- sf_logtype1.py
    |- sf_logtype2.py
```

创建一个 zip 文件并将其注册到 Lambda 层就可以了。


## 加载存储在S3存储桶中的历史数据

您可以将存储在 S3 存储桶中的日志批量加载到 OpenSearch 服务中。 通常日志在进入预先配置的 S3 存储桶后会被实时加载处理。 另一方面，也可以稍后加载备份数据以进行可视化或进行事件调查。 同样，您还可以加载实时加载失败并困在 SQS 的死信队列中的数据。


### 设置环境

#### 设置脚本的执行环境（es-loader）

1. 使用 Amazon Linux 2 AMI 在可与 OpenSearch Service 通信的 VPC 中配置 Amazon EC2 实例。
1. 允许HTTP 通信，以便从 Amazon Linux 访问到位于 Internet 上的 GitHub 和 PyPI 网站。 
1. 将 IAM 角色 [**aes-siem-es-loader-for-ec2**] 附加到 EC2 示例。
1. 连接到 Amazon Linux 终端并按照 [README](../README_zhcn.md) --> [2. 创建 CloudFormation 模板] --> [2-1. 先决条件]和[2-2． 克隆 SIEM on OpenSearch Service]
1. 使用以下命令安装 Python 所依赖的模块：

   ```python
   cd siem-on-amazon-opensearch-service/source/lambda/es_loader/
   pip3 install -r requirements.txt -U -t .
   ```

#### 设置环境变量


1. 导航到 AWS 管理控制台中的 Lambda 
1. 导航到 aes-siem-es-loader 函数并记下两个环境变量名称和值：
    * ES_ENDPOINT
    * GEOIP_BUCKET
1. 将环境变量粘贴到 EC2 实例上的 Amazon Linux 终端中。 以适合您的环境来更改值

   ```sh
   export ES_ENDPOINT=search-aes-siem-XXXXXXXXXXXXXXXXXXXXXXXXXX.ap-northeast-1.es.amazonaws.com
   export GEOIP_BUCKET=aes-siem-123456789012-geo
   ```

### 使用对象列表从 S3 存储桶加载日志

1. 进入 es_loader 目录。

   ```sh
   cd
   cd siem-on-amazon-opensearch-service/source/lambda/es_loader/
   ```

1. 从 S3 存储桶创建对象列表 (s3-list.txt)。

   ```sh
   export AWS_ACCOUNT=123456789012   # Replace this with your AWS account
   export LOG_BUCKET=aes-siem-${AWS_ACCOUNT}-log
   aws s3 ls ${LOG_BUCKET} --recursive > s3-list.txt
   ```

1. 如果有需要，你可以限制只处理一部分数据。

   示例) 创建仅包含 2021 年 CloudTrail 日志的文件列表。

   ```sh
   grep CloudTrail s3-list.txt |grep /2021/ > s3-cloudtrail-2021-list.txt
   ```

1. 使用您在 S3 中创建的对象列表将对象加载到 es-loader。

   ```sh
   # Loading all objects in the S3 bucket into es-loader
   ./index.py -b ${LOG_BUCKET} -l s3-list.txt
   # Example of loading extracted objects
   # ./index.py -b ${LOG_BUCKET} -l s3-cloudtrail-2021-list.txt
   ```


1. 加载完成后请查看结果。 如果加载失败，将生成一个包含失败对象列表的日志文件。 如果此文件不存在，则表明所有对象均已成功加载。
    * 成功的对象列表：S3 list filename.finish.log
    * 失败对象列表：S3 list  filename.error.log
    * 失败对象的调试日志：S3 list filename.error_debug.log
1. 您也可以通过重复步骤 4 并在步骤 5 中指定失败的对象列表来仅加载失败的日志文件：

   示例)

   ```sh
   ./index.py -b ${LOG_BUCKET} -l s3-list.error.txt
   ```

1. 加载成功后，请删除您创建的S3对象列表以及生成的日志文件。

### 从 SQS queue 加载

您可以从 SQS 的 SIEM 死信队列 (aes-siem-dlq) 加载消息。 （它们实际上是存储在S3 存储桶中的日志）

1. 指定您当前运行的AWS region，然后运行es-loader

   ```sh
   export AWS_DEFAULT_REGION=ap-northeast-1
   cd
   cd siem-on-amazon-opensearch-service/source/lambda/es_loader/
   ./index.py -q aes-siem-dlq
   ```

1. 加载完成后查看结果。 如果加载失败，将生成一个包含失败对象列表的日志文件。 如果此文件不存在，则表明所有对象均已成功加载。
    * 成功对象列表：aes-siem-dlq-date.finish.log
    * 失败的对象列表：aes-siem-dlq-date.error.log
    * 失败对象的调试日志：aes-siem-dlq-date.error_debug.log

1. 由于failed object list是S3的object list，重新运行上一节中提到的命令时，可以通过指定list来只加载失败的日志
1. 加载成功后删除生成的日志文件

## 监控

### 指标

您可以在 CloudWatch Metrics 中查看 es-loader 的指标，它规范化日志并将数据发送到 OpenSearch 服务。

* 自定义命名空间: SIEM
* 维度: logtype

| Metric | Unit | 描述 |
|------|-------|-----|
| InputLogFileSize | Byte | es-loader 从 S3 存储桶加载的日志文件大小 |
| OutputDataSize | Byte | Size of the data that es-loader sent to OpenSearch Service |
| SuccessLogLoadCount | Count | es-loader 发送到 OpenSearch Service 的数据大小 |
| ErrorLogLoadCount | Count | es-loader 未能向 OpenSearch Service 发送数据的日志数量 |
| TotalDurationTime | Millisecond | es-loader 开始处理和所有处理完成之间的时间量。 与 Lambda 持续时间大致相同 |
| EsResponseTime | Millisecond | es-loader 将数据发送到 OpenSearch Service 并完成处理所花费的时间 |
| TotalLogFileCount | Count | es-loader 处理的日志文件数 |
| TotalLogCount | Count | 从日志文件中包含的日志中作为处理目标的日志数量。 这包括由于过滤而未实际加载的日志 |

### 日志

您可以在 CloudWatch Logs 中查看用于 SIEM 的 Lambda 函数的日志。
es-loader 日志以 JSON 格式输出，因此您可以在 CloudWatch Logs Insights 中对其进行过滤和搜索。

| Field | 描述 |
|-----|------|
| level | 日志的严重性。 默认情况下，只记录“info”或更高级别的消息。 如果出现故障，您可以通过将 LOG_LEVEL（aes-siem-es-loader 环境变量）更改为“调试”来临时记录“调试”级别的消息。 由于记录调试消息会生成大量日志文件，我们建议您在调查后将 LOG_LEVEL 恢复为“info” |
| s3_key | 存储在 S3 存储桶中的日志文件的对象键。 处理完目标日志文件后，可以使用s3_key作为搜索关键字，提取处理日志和上述metrics的原始数据进行确认 |
| message | 日志中的消息。 在某些情况下，它是 JSON 格式 |



AWS Lambda Powertools Python 可用于其他字段。 有关更多信息，请参阅 [AWS Lambda Powertools Python](https://awslabs.github.io/aws-lambda-powertools-python/core/metrics/) 文档。

[Back to README](../README_zhcn.md)
