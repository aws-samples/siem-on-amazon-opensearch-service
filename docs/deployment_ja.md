# 高度なデプロイ

[In English](deployment.md) | [READMEに戻る](../README_ja.md)

## 目次

* [高度なデプロイが必要なケース](#高度なデプロイが必要なケース)
* [既存の S3 バケットの取り込み](#既存の-s3-バケットの取り込み)
* [AWS CDK によるデプロイ](#aws-cdk-によるデプロイ)
* [AWS CDK によるアップデート](#aws-cdk-によるアップデート)

## 高度なデプロイが必要なケース

次のいずれかに該当する場合は AWS CloudFormation を使わずに AWS Cloud Development Kit (AWS CDK) を実行してデプロイしてください。

* Amazon OpenSearch Service を Amazon VPC の **Private Subnet** にデプロイする
  * Amazon VPC の Public Subnet へのデプロイは未対応
* マルチアカウント環境下でログを集約して分析する
* 既存の Amazon Simple Storage Service (Amazon S3) の バケットを CloudFormation のスタックにインポートし、マルチアカウントのログ受信用に、**S3 バケットポリシーを AWS CDK で自動設定**をする。既存の S3 バケットポリシーは上書きされます
* 既存の S3 バケットからログを SIEM on OpenSearch Service にロードする。**S3 バケットポリシーはご自身で管理する**
* 既存の AWS Key Management Service (AWS KMS) カスタマーマネジメントキー で S3 バケットに暗号化して保存したログを復号する。**AWS KMS のキーポリシーはご自身で管理する**
* S3 バケット名または SIEM on OpenSearch Service のドメイン名を初期値から変更してデプロイする
  * SIEM on OpenSearch Serviceのドメイン名: aes-siem
  * ログ用 S3 バケット名: aes-siem-*[AWS アカウント ID]*-log
  * スナップショット用 S3 バケット名: aes-siem-*[AWS アカウント ID]*-snapshot
  * GeoIPダウンロード用 S3 バケット名: aes-siem-*[AWS アカウント ID]*-geo

## 既存の S3 バケットの取り込み

すでにお持ちの S3 バケットを SIEM on OpenSearch Service の CloudFormation スタックに取り込み、AWS CDK で管理します。ログ取り込み用にS3 バケットポリシーを追加・修正します。**S3 のバケットポリシーやその他のバケット設定は上書きされる**のでご注意ください。SIEM on OpenSearch Service の初期インストール時にのみ設定可能です。
既存の S3 バケットから SIEM on OpenSearch Service にログを送信しつつ、S3 バケットポリシー等はご自身で引き続き管理する場合は、この手順はスキップしてください。

### 手順

1. CloudFormation スタックに取り込みたい S3 バケットの名前を確認してください
1. [Github](https://github.com/aws-samples/siem-on-amazon-opensearch-service) からソースコード一式を git clone するか、[ここ](https://aes-siem.s3.amazonaws.com/siem-on-amazon-opensearch-service-import-exist-s3bucket.template) からインポート用CloudFormationテンプレートをダウンロード
1. GitHub から clone またはダウンロードした CloudFormationテンプレートの `deployment/siem-on-amazon-opensearch-service-import-exist-s3bucket.template` を編集する。BucketName の [change-me-to-your-bucket] をスタックに取り込みたい S3 バケット名に変更
1. AWS マネジメントコンソールで CloudFormation に移動
1. [スタック] のメニューから、右上のプルダウンメニューの [**スタックの作成**] から [**既存のリソースを使用(リソースをインポート)**] を選択
1. [**次へ**]を選択して、[テンプレートの指定] 画面にて、編集したテンプレートの `siem-on-amazon-opensearch-service-import-exist-s3bucket.template` をアップロードし、[**次へ**] を選択
1. [リソースを識別] 画面にて、[識別子の値] にスタックへ [**インポートしたい S3 バケット名**] を入力して、[**次へ**] を選択
1. [スタックの詳細を指定] 画面にて、スタック名に [**aes-siem**] と入力して [**次へ**] を選択
1. [概要をインポート] 画面にて、[**リソースのインポート**] を選択して完了
1. 次のセクションの [AWS CDK によるデプロイ] の [5-3. その他の共通設定] で cdk.json を編集してください。スタックにインポートする S3 バケット名を **s3_bucket_name.log** に指定をしてください。

## AWS CDK によるデプロイ

### 注意事項

* デプロイするサブネットは Private Subnet です
* サブネットは 3つの異なる Availability Zone を選択してください。(実際にデプロイするのは 1 つの AZ へ 1 インスタンスのみです)
* Amazon VPC の [**DNS ホスト名**] と [**DNS ホスト解決**] の 2 つとも有効にしてください
* デプロイ時に `cdk.json` の作成をしますが、このファイルと自動生成される `cdk.context.json` を AWS Systems Manager パラメーターストア等に保存をしてください。SIEM on OpenSearch Service のデプロイで使用する CDK の再実行に必要です

### 1. AWS CDK 実行環境の準備

1. Amazon Linux 2023 または Amazon Linux 2 を実行させた Amazon Elastic Compute Cloud (Amazon EC2) インスタンスをデプロイしてください。インスタンスは 2 GB 以上のメモリが必要です
1. AWS Identity and Access Management (IAM) で Admin 権限を持つロールを作成して、インスタンスにアタッチします
1. シェルにログインして、開発ツール、Python 3.11 と開発ファイル、git、jq、tar をインストールし、ソースコードを GitHub から取得します

    Amazon Linux 2023 の場合

    ```shell
    export GIT_ROOT=$HOME
    cd ${GIT_ROOT}
    sudo dnf install -y python3.11 python3.11-devel python3.11-pip git jq tar
    git clone https://github.com/aws-samples/siem-on-amazon-opensearch-service.git
    ```

    Amazon Linux 2 の場合

    > **_Note:_** このソリューションでは、Amazon Linux 2 での CDK によるデプロイは deprecated です。Amazon Linux 2023 をお使いください。

    ```shell
    export GIT_ROOT=$HOME
    cd ${GIT_ROOT}
    sudo yum install -y amazon-linux-extras
    sudo amazon-linux-extras enable python3.8
    sudo yum install -y python38 python38-devel git jq tar
    sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
    git clone https://github.com/aws-samples/siem-on-amazon-opensearch-service.git
    ```

### 2. 環境変数の設定

```shell
export CDK_DEFAULT_ACCOUNT=<AWS_ACCOUNT> # your AWS account
export AWS_DEFAULT_REGION=<AWS_REGION> # region where the distributable is deployed
```

### 3. AWS Lambda デプロイパッケージの作成

SIEM on OpenSearch Service で使用する AWS Lambda 関数は 3rd Party のライブラリを利用します。ローカルにこれらのライブラリをダウンロードしてデプロイパッケージを作成します。Python 3 がインストールされていることを確認してください。

```shell
cd ${GIT_ROOT}/siem-on-amazon-opensearch-service/deployment/cdk-solution-helper/
deactive 2>/dev/null
chmod +x ./step1-build-lambda-pkg.sh && ./step1-build-lambda-pkg.sh
```

### 4. AWS Cloud Development Kit (AWS CDK) の環境セットアップ

AWS CDK を実行できるように各種のソフトウェアをユーザーモードでインストールします。

```bash
chmod +x ./step2-setup-cdk-env.sh && ./step2-setup-cdk-env.sh
source ~/.bashrc
```

インストールされるソフトウェア

* Node Version Manager (nvm)
* Node.js
* AWS SDK for Python (Boto3)
* AWS Cloud Development Kit (AWS CDK)

### 5. AWS CDK によるインストールのオプション設定

レポジトリのルートディレクトリから、AWS CDK のコードのあるディレクトリに移動して、オプション設定とインストールの準備をします

```bash
cd ${GIT_ROOT}/siem-on-amazon-opensearch-service/ && source .venv/bin/activate
cd source/cdk && cdk bootstrap $CDK_DEFAULT_ACCOUNT/$AWS_DEFAULT_REGION
```

エラーで実行が失敗した場合、Amazon EC2 インスタンスに Admin 権限のロールが割り当てられているかを確認してください。

#### 5-1. SIEM on OpenSearch Service を Amazon VPC 内にデプロイ

SIEM on OpenSearch Service を Amazon VPC 内にデプロイする場合は、Amazon VPC 用の AWS CDK のサンプルファイルをコピーして編集してください。

```bash
cp cdk.json.vpc.sample cdk.json
```

cdk.json を編集してください。

Amazon VPC に関するパラメーターと説明です。

|パラメータ|説明|
|----------|----|
|vpc_typ|新しい Amazon VPC を作成する場合は [**new**] を、既存の Amazon VPC を利用する場合は [**import**] を入力。編集するパラメーターとして、新規の場合は new_vpc_XXXX、既存の利用は imported_vpc_XXXX を修正する|
|imported_vpc_id|SIEM on OpenSearch Service をデプロイする Amazon VPC の ID を入力|
|imported_vpc_subnets|3つ以上の"VPC サブネット ID" をリスト形式で入力|
|imported_vpc_subnetX|(deprecated) 3つの、[VPC サブネット ID]、[アベイラビリティーゾーン]、[ルートテーブル ID] を入力|
|new_vpc_nw_cidr_block|新規に作成する Amazon VPC の IP と CIDR ブロックを入力。形式は、IP アドレス/サブネットマスク数。例) 192.0.2.0/24|
|new_vpc_subnet_cidr_mask|サブネット CIDR ブロック。拡張性を考慮して 27 以上を推奨|

#### 5-2. OpenSearch Service を パブリックアクセス (Amazon VPC 外)にデプロイ

SIEM on OpenSearch Service をパブリックアクセス環境にデプロイする場合

```bash
cp cdk.json.public.sample cdk.json
```

パブリックアクセス特有の設定はなし

#### 5-3. その他の共通設定

共通の設定として以下のパラメーターを変更できます。変更がなければ修正は不要です。

|パラメーター|初期値|説明|
|------------|-------|-----|
|aes_domain_name|aes-siem|SIEM on OpenSearch Service ドメインを変更する|
|s3_bucket_name||S3 バケット名を初期値から変更する|
|log|aes-siem-*[AWS アカウント ID]*-log|ログ用 S3 バケット名|
|snapshot|aes-siem-*[AWS アカウント ID]*-snapshot|スナップショット用 S3 バケット名|
|geo|aes-siem-*[AWS アカウント ID]*-geo|GeoIPダウンロード用 S3 バケット名|
|kms_cmk_alias|aes-siem-key|AWS KMS カスタマーマネジメントキーのエイリアス名を変更する|
|organizations||AWS Organizations の情報を入力して、S3 バケットのバケットポリシーを自動生成。他の S3 バケットをご自身で管理する場合は入力不要|
|.org_id||Organizations ID。例)o-12345678|
|.management_id||Organizations で管理者アカウントとなっている AWS アカウント ID|
|.member_ids||Organizations でメンバーアカウントとなっている AWS アカウント ID をカンマ区切りでを入力|
|no_organizations||Oarganizations で管理していないアカウント情報を入力して、バケットポリシーを自動生成。他の S3 バケットをご自身で管理する場合は入力不要|
|.aws_accounts||Oarganizations で管理していない AWS アカウント ID をカンマ区切りで入力|
|additional_s3_buckets||カンマ区切りで S3 バケット名を列挙|
|additional_kms_cmks||カンマ区切りで AWS KMS カスタマーマネジメントキー の ARN を列挙|

最後に JSON ファイルのバリデーションをしてください。実行結果として、JSON が表示され、エラーが出なければ JSON ファイルの文法に問題はありません。

```shell
cdk context  --j
```

### 6. AWS CDK の実行

CloudFormation テンプレートと同じパラーメーターを指定して CDK コマンドを実行します。パラメーターは、CDK コマンドでデプロイ後に、CloudFormation のコンソールから変更することもできます。初期インストール時には、パラメータなしでもデプロイできます。

|パラメーター|説明|
|------------|----|
| **Initial Deployment Parameters** ||
| AllowedSourceIpAddresses |Amazon VPC 外に SIEM on OpenSearch Service をデプロイした時に、アクセスを許可するIPアドレス。複数アドレスはスペース区切り|
| **Basic Configuration** ||
| DeploymentTarget | SIEM ソリューションをどこにインストールしますか？ 値は、`opensearch_managed_cluster` (初期値) か `opensearch_serverless` です。**Serverless は実験的オプションです**|
| DomainOrCollectionName | Amazon OpenSearch Service のドメイン名、または OpenSearch Serverless のコレクション名|
| SnsEmail |メールアドレス。SIEM on OpenSearch Service で検知したアラートを SNS 経由で送信する|
| ReservedConcurrency |es-loaderの同時実行数の上限値。デフォルトは `10`。エラーがないにもかかわらずログ取り込み遅延やThrottleが常時発生する場合はこの値を増やしてください|
| **Log Enrichment - optional** ||
| GeoLite2LicenseKey | Maxmindのライセンスキー。IP アドレスに国情報を付与|
| OtxApiKey | AlienVault OTX の API キー。入力すると AlienVault から IoC をダウンロードする|
| EnableTor | Tor Project から IoC をダウンロードするかどうか。値は `true` か `false`(初期値)|
| EnableAbuseCh | Abuse.ch から IoC をダウンロードするかどうか。値は `true` か `false`(初期値)||
| IocDownloadInterval | IoC をダウンロードする間隔を分で指定。初期値は720分|
| **Advanced Configuration - optional** ||
| LogBucketPolicyUpdate | Log バケットのポリシーについて、`update_and_override`(初期値) または `keep` を選択してください。最初のデプロイ時には `update_and_override` を選んでください。更新時に `update_and_override` を選んだ場合は、ログを取り込むためのバケットポリシーはご自身で作成・管理をしてください |
| VpcEndpointId | OpenSearch managed cluster または OpenSearch Serverless の VPC Endpoint ID を指定してください。VPC Endpoint はデプロイ前に指定してください。もし指定した場合は、いくつかの Lambda 関数とリソースは VPC 内にデプロイされます|
| CreateS3VpcEndpoint | 新しく S3 の VPC Endpoint を作成しますか？値は `true`(初期値) か `false`です。もし、すでに VPC があり、S3 の VPC Endpoint がある場合は、`false` を指定してください |
| CreateSqsVpcEndpoint | 新しく SQS の VPC Endpoint を作成しますか？値は `true`(初期値) か `false`です。もし、すでに VPC があり、SQS の VPC Endpoint がある場合は、`false` を指定してください |
| CreateSsmVpcEndpoint | 新しく Systems Manager の VPC Endpoint を作成しますか？値は `true`(初期値) か `false`です。もし、すでに VPC があり、Systems Manager の VPC Endpoint がある場合は、`false` を指定してください |
| CreateStsVpcEndpoint | 新しく STS の VPC Endpoint を作成しますか？Control Tower または Security Lake との統合を選択した場合のみ STS VPC Endpoint は作成されます。値は `true`(初期値) か `false`です。もし、すでに VPC があり、STS の VPC Endpoint がある場合は、`false` を指定してください。 |
| **Control Tower Integration - optional** | [Amazon Security Lake との統合](securitylake_ja.md) |
| ControlTowerLogBucketNameList | Log Archive アカウントにある S3 バケット名を指定してください。複数ある場合は、カンマ区切り入力してください. (例: `aws-controltower-logs-123456789012-ap-northeast-1, aws-controltower-s3-access-logs-123456789012-ap-northeast-1` )|
| ControlTowerSqsForLogBuckets | Log Archive アカウントで作成した SQS の ARN を指定してください。(例:  `arn:aws:sqs:ap-northeast-1:12345678902:aes-siem-ct` )|
| ControlTowerRoleArnForEsLoader | aes-siem-es-loader が引き受けるために作成した IAM Role の ARN を指定してください。(例:  `arn:aws:iam::123456789012:role/ct-role-for-siem` )|
| **Security Lake Integration - optional** | [AWS Control Tower との統合](controltower_ja.md) |
| SecurityLakeSubscriberSqs | Security Lake が作成するサブスクライバーの SQS の ARN を指定してください。(例:  `arn:aws:sqs:us-east-1:12345678902:AmazonSecurityLake-00001111-2222-3333-5555-666677778888-Main-Queue` ` ) |
| SecurityLakeRoleArn | Security Lake が作成するサブスクライバーの IAM Role の ARN を指定してください。(例:  `arn:aws:iam::123456789012:role/AmazonSecurityLake-00001111-2222-3333-5555-666677778888` ) |
| SecurityLakeExternalId | Security Lake でサブスクライバー作成時に指定した external ID を指定してください。(例:  `externalid123` ) |

文法) `--parameters オプション1=パラメータ1 --parameters オプション2=パラメータ2`
複数のパラメーターがある場合は、--parametersを繰り返す

パラメーター付きでの実行例)

```bash
cdk deploy \
    --parameters AllowedSourceIpAddresses="10.0.0.0/8 192.168.0.1" \
    --parameters GeoLite2LicenseKey=xxxxxxxxxxxxxxxx
```

約30分でデプロイが終わります。完了したら、[READMEに戻って](../README_ja.md)、「2. OpenSearch Dashboards の設定」にお進みください。

### 7. cdk.json と cdk.context.json のバックアップ

cdk.json と cdk.context.json のバックアップ をしてください。

AWS Systems Manager パラメーターストアへバックアップする例

```sh
aws ssm put-parameter \
  --overwrite \
  --type String \
  --name /siem/cdk/cdk.json \
  --value file://cdk.json

if [ -f cdk.context.json ]; then
  aws ssm put-parameter \
    --overwrite \
    --type String \
    --name /siem/cdk/cdk.context.json \
    --value file://cdk.context.json
fi
```

## AWS CDK によるアップデート

SIEM のレポジトリを更新して、AWS CDK でアップデートします。初期インストール時に使用した cdk.json が CDK のディレクトリにあることを確認してください。

> **注) Global tenant の 設定やダッシュボード等は自動で上書きされるのでご注意ください。アップデート前に使用していた設定ファイルやダッシュボード等は S3 バケットの aes-siem-[AWS_Account]-snapshot/saved_objects/ にバックアップされるので、元の設定にする場合は手動でリストアしてください。**

> **注) S3 バケットポリシー、KMS の キーポリシーは、IAM ポリシー等は、CDK/CloudFormation で自動生成されています。手動で変更は非推奨ですが、変更している場合は上書きされるので、それぞれをバックアップをしてからアップデート後に差分を更新して下さい。**

> SIEM on Amazon ES からお使いの方は、ディレクトリを変更して下さい。
> cd && mv siem-on-amazon-elasitcsearch siem-on-amazon-opensearch-service

```sh
export GIT_ROOT=$HOME
cd ${GIT_ROOT}/siem-on-amazon-opensearch-service/ && git stash && git checkout main
git pull --rebase
```

[**AWS CDK によるデプロイ**] の [**2. 環境変数の設定**]、[**3. AWS Lambda デプロイパッケージの作成**]、「**4. AWS Cloud Development Kit (AWS CDK) の環境セットアップ**] を再実行してください。

[5. AWS CDK によるインストールのオプション設定] 以降は **実行せず**、下記を実行

インストール時に保存した `cdk.json` と `cdk.context.json` を `${GIT_ROOT}/siem-on-amazon-opensearch-service/source/cdk/` にリストア。`cdk.context.json` はない場合があります。

AWS Systems Manager パラメーターストアからリストアする例

```sh
cd ${GIT_ROOT}/siem-on-amazon-opensearch-service/source/cdk/
if [ -s cdk.json ]; then
  cp cdk.json cdk.json.`date "+%Y%m%d%H%M%S"`
fi
aws ssm get-parameter \
  --name /siem/cdk/cdk.json \
  --query "Parameter.Value" \
  --output text > cdk.json

if [ -s cdk.context.json ]; then
  cp cdk.context.json cdk.context.json.`date "+%Y%m%d%H%M%S"`
fi
aws ssm get-parameter \
  --name /siem/cdk/cdk.context.json \
  --query "Parameter.Value" \
  --output text > cdk.context.json.new 2> /dev/null
if [ -s cdk.context.json.new ]; then
  mv cdk.context.json.new cdk.context.json
else
  rm cdk.context.json.new
fi
```

> **注) v2.8.0d 以下からアップデートする場合、CDK v1 から CDK v2 へ移行する必要があります。再度、cdk bootstrap を実行します**

```sh
cd ${GIT_ROOT}/siem-on-amazon-opensearch-service/ && source .venv/bin/activate
cd source/cdk
# v2.8.0d 以下からアップデートする場合、cdk bootstrap も実行
# cdk bootstrap
cdk deploy
```

更新される差分が表示されるので確認して、[**y**] を入力。数分でアップデートは完了します。

`cdk.json` と `cdk.context.json` を保存して終了です。

[READMEに戻る](../README_ja.md)
