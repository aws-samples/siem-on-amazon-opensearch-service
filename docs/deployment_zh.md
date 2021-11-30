# Advanced Deployment

[View this page in Japanese (日本語)](deployment_ja.md) | [View this page in Chinese (简体中文)](deployment_zh.md) |[Back to README](../README_zhcn.md)

## 目录

* [高级部署所需要的条件](#Conditions-that-require-advanced-deployment)
* [从现有的S3存储桶加载数据](#Loading-an-existing-S3-bucket)
* [使用 AWS CDK 进行部署](#Deploying-with-the-AWS-CDK)
* [使用 AWS CDK 更新 SIEM](#Updating-SIEM-with-the-AWS-CDK)

## 高级部署所需要的条件

如果您的环境满足以下任一条件，则建议运行 AWS Cloud Development (AWS CDK)，而不使用 AWS CloudFormation 部署 SIEM onAmazon OpenSearch Service：

* 我想将 Amazon OpenSearch Service 部署到 Amazon VPC **私有子网**
  * 不支持部署到 Amazon VPC 公有子网
* 我想在多账户环境下聚合和分析日志
* 我想将现有的 Amazon Simple Storage Service (Amazon S3) 存储桶导入 CloudFormation 堆栈，以使用 AWS CDK 自动配置 **S3 存储桶策略** 以接收多账户日志。 （现有的 S3 存储桶策略将被覆盖）
* 我想将现有 S3 存储桶中的日志加载到 OpenSearch 服务上的 SIEM。 **我自己管理 S3 存储桶策略**
* 我想使用现有的 AWS Key Management Service (AWS KMS) 客户管理的密钥解密以加密方式存储在 S3 存储桶中的日志。 **我自己管理 AWS KMS 的密钥策略**
* 我想在部署时更改默认 S3 存储桶名称或 OpenSearch 服务域名上的 SIEM
  * SIEM on OpenSearch Service 域名：aes-siem
  * 日志的 S3 存储桶名称：aes-siem-*[AWS 账户 ID]*-log
  * 快照的 S3 存储桶名称：aes-siem-*[AWS 账户 ID]*-snapshot
  * GeoIP 下载的 S3 存储桶名称：aes-siem-*[AWS 账户 ID]*-geo

## 从现有的S3存储桶加载数据


您可以将现有的 S3 存储桶加载到 OpenSearch Service 上的 SIEM 的 CloudFormation 堆栈中，并使用 AWS CDK 对其进行管理。 为此，您需要添加或修改 S3 存储桶策略。 请注意，按照以下步骤操作，**S3 存储桶策略和其他存储桶配置** 将被覆盖。 此外，您只能在 OpenSearch Service 上初始安装 SIEM 期间执行以下步骤。如果您想将日志从现有 S3 存储桶发送到 OpenSearch Service 上的 SIEM，但仍想自己管理 S3 存储桶策略等，请跳过这些步骤。

### 步骤


1. 检查要加载到 CloudFormation 堆栈中的 S3 存储桶的名称
1. 您可以使用 git clone [Github](https://github.com/aws-samples/siem-on-amazon-opensearch-service) 复制代码，或下载从[这里](https://aes-siem.s3.amazonaws.com/siem-on-amazon-opensearch-service-import-exist-s3bucket.template)
1. 在从 GitHub 克隆或下载的 CloudFormation 模板中编辑 `deployment/siem-on-amazon-opensearch-service-import-exist-s3bucket.template`。将 BucketName 中的 [change-me-to-your-bucket] 更改为要加载到堆栈中的 S3 存储桶的名称
1. 在 AWS 管理控制台中导航到 CloudFormation
1. 在[Stacks]菜单中，从右上角的下拉菜单中选择[**Create stack**] --> [**With existing resources (import resources)**]。
1. 选择[**Next**]，在[Specify template]界面上传编辑好的模板`siem-on-amazon-opensearch-service-import-exist-s3bucket.template`，选择[**Next] **]
1. 在[Identify resources] 界面，导航到 [Identifier value]，在栈中输入【**the name of the S3 bucket you want to import**】，选择【**Next**】
1. 在[Specify stack details]屏幕上，输入堆栈名称[**aes-siem**]，然后选择[**Next**]
1. 在[Import overview] 界面，选择【**Import resources**】完成
1. 在下一节中编辑 cdk.json：[使用 AWS CDK 部署] --> [5-3. 其他常用配置] 将要导入堆栈的S3存储桶的名称设置为 **s3_bucket_name.log**。 

## 使用 AWS CDK 进行部署

### 注意

* 您部署的子网是私有子网
* 为子网选择三个不同的可用区。 （每个AZ只部署一个实例）
* 在 Amazon VPC 中，同时启用 [**DNS hostnames**] 和 [**DNS resolution**]
* `cdk.json` 和 `cdk.context.json` 是在部署过程中创建的，并确保保存此文件。 需要重新运行用于在 SIEM on OpenSearch Service 的CDK文件。

### 1. 设置 AWS CDK 运行环境



1. 部署一个运行 Amazon Linux 2 (x86) 的 Amazon Elastic Compute Cloud (Amazon EC2) 实例
1. 在 AWS Identity and Access Management (IAM) 中创建一个具有管理员权限的角色并将其附加到 Amazon EC2 实例
1. 登录shell； 安装开发工具、Python 3.8 和开发相关文件、git 和 jq； 并从 GitHub 获取源代码。

   ```shell
   sudo yum groups mark install -y "Development Tools"
   sudo yum install -y amazon-linux-extras
   sudo amazon-linux-extras enable python3.8
   sudo yum install -y python38 python38-devel git jq
   sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
   git clone https://github.com/aws-samples/siem-on-amazon-opensearch-service.git
   ```

### 2. 设置环境变量

```shell
export CDK_DEFAULT_ACCOUNT=<AWS_ACCOUNT> # your AWS account
export AWS_DEFAULT_REGION=<AWS_REGION> # region where the distributable is deployed
```

### 3. 创建 AWS Lambda 部署包

您在 OpenSearch Service 上的 SIEM 中使用的 AWS Lambda 函数使用第三方库。 下面的脚本将下载这些库并在本地创建部署包。 确保您已安装 Python 3。

```shell
cd siem-on-amazon-opensearch-service/deployment/cdk-solution-helper/
chmod +x ./step1-build-lambda-pkg.sh && ./step1-build-lambda-pkg.sh
```

### 4. 为 for AWS Cloud Development Kit (AWS CDK) 设置环境

下面的脚本将在用户模式下安装运行 AWS CDK 所需的各种软件。

```bash
chmod +x ./step2-setup-cdk-env.sh && ./step2-setup-cdk-env.sh
source ~/.bash_profile
```

如下软件将被安装:

* Node Version Manager (nvm)
* Node.js
* AWS SDK for Python (Boto3)
* AWS Cloud Development Kit (AWS CDK)

### 5. 设置 AWS CDK 安装选项

从当前存储库的根目录，进入到包含 AWS CDK 代码的目录。运行虚拟环境配置选项后，进行CDK以进行安装部署。

```bash
cd ../../source/cdk/
source .env/bin/activate
cdk bootstrap
```

如果执行失败并出现错误，请验证您的 Amazon EC2 实例是否已分配适当的权限角色。

#### 5-1. 在 VPC 中部署 SIEM on OpenSearch Service in an Amazon VPC

如果你想在VPC中部署 SIEM on OpenSearch Service，你可以编辑 AWS CDK Sample 文件

```bash
cp cdk.json.vpc.sample cdk.json
```

编辑 cdk.json 文件。

Amazon VPC 参数及描述:

| Parameter | Description |
|----------|----|
| vpc_typ | 如果您创建新的 Amazon VPC，请输入 [**new**]，如果您使用现有的 Amazon VPC，请输入 [**import**]。 要编辑的参数是新 VPC 的 new_vpc_xxxx 和现有 VPC 的imported_vpc_xxxx |
| imported_vpc_id | 输入要在 OpenSearch Service 上部署 SIEM 的 Amazon VPC 的 ID |
| imported_vpc_subnets | 从下来列表中选择三个或更多“VPC 子网 ID” |
| imported_vpc_subnetX | (废弃) 输入三个参数，分别是【VPC子网ID】、【可用区】、【路由表ID】 |
| new_vpc_nw_cidr_block | 为您创建的新 Amazon VPC 输入 IP 和 CIDR 块。 格式为IP地址/子网掩码数。 示例）192.0.2.0/24 |
| new_vpc_subnet_cidr_mask | 子网 CIDR 块。 为了可扩展性，我们推荐使用 /27 或更大范围的CIDR。 |

#### 5-2. Deploying OpenSearch Service for public access (outside of Amazon VPC)

如果要在公共子网中配置 SIEM on  OpenSearch Service：

```bash
cp cdk.json.public.sample cdk.json
```

没有特定于公共访问的配置.

#### 5-3. Other common configurations

您可以将以下参数更改为常用配置。 如果没有变化，则不需要修改。

| 参数 | 初始值 | 描述 |
|------------|-------|-----|
| aes_domain_name | aes-siem | 更改 SIEM on OpenSearch Service 在 OpenSearch中的domain名称 |
| s3_bucket_name | 从更改 S3 存储桶初始值名称|
| log | aes-siem-*[AWS Account ID]*-log | S3 存储桶名称 for logs |
| snapshot | aes-siem-*[AWS Account ID]*-snapshot | 用于快照的S3 存储桶名称 |
| geo | aes-siem-*[AWS Account ID]*-geo | 用于存储GeoIP库的 S3 存储桶名称 |
| kms_cmk_alias | aes-siem-key | 更改 AWS KMS 客户管理密钥的别名 |
| organizations | 使用此处输入的 AWS Organizations 信息自动生成 S3 存储桶策略。 如果您自己管理另一个 S3 存储桶，则不需要输入 |
| .org_id | Organizations ID. 示例) o-12345678 |
| .management_id | 作为组织中的管理员账户的 AWS 账户 ID |
| .member_ids | 作为组织中成员账户的 AWS 账户 ID，以逗号分隔 |
| no_organizations | 使用此处输入的账户信息，为不受组织管理的账户自动生成存储桶策略。 如果您自己管理另一个 S3 存储桶，则不需要输入 |
| .aws_accounts | 输入不由 Oarganizations 管理的以逗号分隔的 AWS 账户 ID |
| additional_s3_buckets | 以逗号分隔的 S3 存储桶名称 |
| additional_kms_cmks | 枚举 AWS KMS 客户管理的密钥的 ARN，以逗号分隔 |

最后，验证 JSON 文件。 如果执行后显示 JSON 并且没有错误，则 JSON 文件的语法没有问题。 

```shell
cdk context  --j
```

### 6. 运行AWS CDK

部署 AWS CDK:

```bash
cdk deploy
```


你可以指定同 CloudFormation 模板一样的参数。

| 参数 | 描述 |
|------------|----|
| AllowedSourceIpAddresses |允许从外部IP地址访问部署在Amazon VPC 之内的 SIEM on OpenSearch Service，如果有多个地址可以使用空格分隔  |
| GeoLite2LicenseKey | Maxmind license key. 该库用于基于IP 地址查询所在的国家信息  |
| ReservedConcurrency | es-loader 的最大并发执行次数。 默认值为 10。如果您看到加载日志出现延迟，或者看到即使没有错误也可能发生持续节流，请考虑增加此值  |
| SnsEmail | Email 地址. SIEM on OpenSearch Service 将错误信息发送到该邮件地址 |

语法) --parameters Option1=Parameter1 --parameters Option2=Parameter2
如果你有其他的一些参数，请重复使用 --parameters

部署参数示例)

```bash
cdk deploy \
    --parameters AllowedSourceIpAddresses="10.0.0.0/8 192.168.0.1" \
    --parameters GeoLite2LicenseKey=xxxxxxxxxxxxxxxx
```


该部署大概需要30分钟的时间。当完成后，请参考 README文件 并执行 “3. Configuring OpenSearch Dashboards.” 部分。

## 使用 AWS CDK 更新 SIEM


您可以使用 AWS CDK 更新 SIEM 存储库。 请确保您在初始安装时使用的 cdk.json 已经被存储在 CDK 目录中。 

```sh
# cd SIEM repository
git pull --rebase
```

返回 [**Deploying with the AWS CDK**] 部分并重新运行 [**2. 设置环境变量**], [**3. 创建 AWS Lambda 部署包**] 和 [**4. 为 AWS Cloud Development Kit (AWS CDK)** 设置环境。]

请注意 [5. 使用 AWS CDK 设置安装选项] 和后续步骤**不需要遵循**。 相反，请执行以下命令： 

```sh
cd source/cdk/
source .env/bin/activate
cdk deploy
```

将显示更新的差异。 输入 [**y**] 进行确认。 更新将在几分钟内完成。

[Back to README](../README_zhcn.md)
