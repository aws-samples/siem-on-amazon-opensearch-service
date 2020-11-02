# AWS サービスの設定方法

[In English](configure_aws_service.md) | [READMEに戻る](../README_ja.md)

SIEM on Amazon ES に AWS の各サービスのログを取り込みます。下記を参考にしてログを取り込む AWS サービスを設定してください。

## 1. 共通

SIEM on Amazon ES は Amazon Simple Storage Service (Amazon S3) の S3 バケットに出力されたファイル名とパス名からログ種別を判定しています。初期値は、各サービスのデフォルト設定による出力パスまたはファイル名です。デフォルト設定で判定できない場合は、判別可能な情報を付与した設定にしています。初期値とは異なるファイルパスで S3 に出力する場合は、user.ini を作成して "s3_key" の項目に独自のファイル名や S3 オブジェクトキーを追加してください。user.ini の編集方法は [SIEM on Amazon ES の設定変更](configure_siem_ja.md)を参照してください。

S3 バケットへの出力パスを自由に設定できる場合は、出力パス(プレフィックス)に AWS アカウント ID とリージョンを含めてください。取り込んだログにこの情報を付与します。ログにこの情報が含まれている場合には、ログに含まれている情報を優先します。

AWS Key Management Service (AWS KMS) による暗号化をして、S3 バケットにファイルを保存する場合は、SIEM on Amazon ESのデプロイ時に自動作成された AWS KMS カスタマーマネジメントキーをご利用ください。デフォルトではエイリアス名は aes-siem-key です。すでにある AWS KMS カスタマーマネジメントキーを利用することも可能で、その場合には [こちら](deployment_ja.md) をご確認ください。

ここでの説明の AWS アカウントは **123456789012** としています。適宜、ご自身の AWS アカウントに置き換えてください。

## 2. AWS CloudTrail

CloudTrail のログを下記の方法で S3 バケットに出力してください。

s3_key の初期値: `CloudTrail` (デフォルト設定の出力パスの一部)

1. AWS マネジメントコンソールにログイン
1. [CloudTrail コンソール](https://console.aws.amazon.com/cloudtrail/home?) に移動
1. 画面左メニューの [**証跡**] => 画面右上の [**証跡の作成**] を選択
1. [証跡属性の選択] 画面で次のパラメータを入力
    * 証跡名: [**aes-siem-trail**]
    * 組織内の全てのアカウントについて有効化: 任意。グレーアウトしてチェックできない場合はスキップ
    * ストレージの場所: [**既存の S3 バケットを使用する**] にチェック
    * [**aes-siem-123456789012-log**] を選択
        * 123456789012 はご利用の AWS アカウント ID に置換してください
    * ログファイルの SSE-KMS 暗号化: [**有効**] にチェックを推奨
    * AWS KMS カスタマー管理の CMK: [**既存**] にチェック入れる
    * AWS KMS エイリアス： [**aes-siem-key**] を選択
    * ログファイルの検証: [**有効**] にチェックを推奨
    * SNS 通知の配信: 有効にチェックせず
    * CloudWatch Logs: 有効にチェックせず
    * タグオプション: 任意
1. [**次へ**] を選択
1. [ログイベントの選択] 画面でで次のパラメーターを入力
    * イベントタイプ
        * 管理イベント: [**チェックする**]
        * データイベント: 任意
        * Insights イベント: 任意
    * 管理イベント
        * APIアクティビティ: [読み取り]と[書き込み] の両方にチェック
        * AWS KMS イベントの除外: 任意
1. [**次へ**] を選択
1. [**証跡の作成**] を選択

## 3. Amazon Virtual Private Cloud (Amazon VPC) Flow Logs

VPC Flow Logs を下記の方法で S3 バケットに出力してください。

s3_key の初期値: `vpcflowlogs` (デフォルト設定の出力パスの一部)

1. AWS マネジメントコンソールにログイン
1. [VPC コンソール](https://console.aws.amazon.com/vpc/home?) に移動
1. 画面左メニューの [**VPC**] または [**サブネット**] を選択 => ログ取得対象リソースのチェックボックスを選択する
1. 画面下部の詳細情報の、[**フローログ**] タブを選択 => [**フローログの作成**] を選択する
1. [フローログを作成]画面にて下記のパラメーターを入力する
    * 名前: 任意
    * フィルタ: 任意、[**すべて**] を推奨
    * 最大集約間隔: 任意、1分間にするとログ量が増えます
    * 送信先: [**S3 バケットへの送信**] にチェックを入れる
    * S3 バケット ARN: [**arn:aws:s3:::aes-siem-123456789012-log**]
        * 123456789012 は ご利用の AWS アカウント ID に置換してください
    * ログレコード形式: [**AWS のデフォルトの形式**] にチェックを入れる
        * カスタム形式を利用される場合は user.ini にログの正規表現を定義してください
    * タグ: 任意
1. [**フローログを作成**] を選択

## 4. Amazon GuardDuty

GuardDuty のログを下記の方法で S3 バケットに出力してください。

s3_key の初期値: `GuardDuty` (デフォルト設定の出力パスの一部)

1. AWS マネジメントコンソールにログイン
1. [GuardDuty コンソール](https://console.aws.amazon.com/guardduty/home?) に移動
1. 画面左メニューの [**設定**] を選択
1. [結果のエクスポートオプション] パネルへスクロールをして移動
1. 更新された結果の頻度: [**15分ごとに CWE と S3 を更新する**] を選択して [**保存**] を選択 (推奨)
1. S3 バケットの [**今すぐ設定**] を選択して下記のパラメーターを入力する
    * [**既存のバケット お使いのアカウント内**] にチェックを入れる
    * バケットの選択: [**aes-siem-123456789012-log**] を選択
        * 123456789012 は ご利用の AWS アカウント ID に置換してください
    * ログファイルのプレフィックス: 空欄のまま
    * KMS 暗号化: [**アカウントからキーを選択する**] にチェックを入れる
    * キーエイリアス: [**aes-siem-key**] を選択
    * [**保存**] を選択

設定は完了です。同じ設定画面内の [**結果サンプルの生成**] を選択すると SIEM on Amazon ES への取り込み設定の成否を確認できます。

## 5. Amazon Simple Storage Service (Amazon S3) access log

S3 access log を下記の方法で S3 バケットに出力してください。すでに CloudTrail の データイベントで S3 を取得してる場合、S3 access log との違いは [こちら](https://docs.aws.amazon.com/ja_jp/AmazonS3/latest/dev/logging-with-S3.html) をご確認ください

s3_key の初期値: `s3accesslog` (標準の保存パスがないのでプレフィックスで指定してください)

1. AWS マネジメントコンソールにログイン
1. [S3 コンソール](https://console.aws.amazon.com/s3/home?) に移動
1. バケットの一覧からログを取得したい S3 バケットを選択。
1. [**プロパティ**]タブを選択 => [**サーバーアクセスのログ記録**]を選択
    1. [**ログの有効化**]にチェックを入れる
    1. ターゲットバケット: [**aes-siem-123456789012-log**] を選択
        * 123456789012 は ご利用の AWS アカウント ID に置換してください
    1. ターゲットプレフィックス: [**AWSLogs/AWSアカウントID/s3accesslog/リージョン/バケット名/**]
        * [s3accesslog] を含むことが重要
    1. [**保存**] を選択

## 6. Elastic Load Balancing (ELB)

次の3つのロードバランサーのログについて、それぞれを S3 バケットに出力します。

* Application Load Balancer(ALB)
* Network Load Balancer(NLB)
* Classic Load Balancer(CLB)

s3_key の初期値はデフォルトの出力パスとファイル名を正規表現で判別します

* ALB: `elasticloadbalancing_.*T\d{4}Z_\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}_\w*\.log\.gz$$`
* NLB: `elasticloadbalancing_.*T\d{4}Z_[0-9a-z]{8}\.log\.gz$$`
* CLB: `elasticloadbalancing_.*T\d{4}Z_\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}_\w*\.log$$`

1. AWS マネジメントコンソールにログイン
1. [EC2 コンソール](https://console.aws.amazon.com/ec2/home?) に移動
1. 画面左メニューの [**ロードバランサー**] を選択 => ログ取得の対象ロードバランサーの [**チェックボックスを選択**]
1. [説明] タブを選択 => ALB/NLB/CLBでそれぞれの方法を次のパラメータを入力
    * ALB/NLBの場合: [**属性の編集**] を選択
        * アクセスログ: [**有効化**] にチェックを入れる
        * S3 の場所: [**aes-siem-123456789012-log**] を入力
            * 123456789012 は ご利用の AWS アカウント ID に置換してください
        * この場所の作成: チェックをせず
        * [**保存**] を選択
    * CLBの場合: [**アクセスログの設定**]を選択
        * アクセスログの有効化: [**チェックを入れる**]
        * 間隔: [**5分 or 60分**] のどちらかを選択
        * S3 の場所: [**aes-siem-123456789012-log**] を入力
            * 123456789012 は ご利用の AWS アカウント ID に置換してください
        * この場所の作成: チェックをせず
        * [**保存**] を選択して設定完了

## 7. Amazon CloudFront

CloudFront には、ディストリビューションに送信されるリクエストを2つの方法で記録できます。標準ログ (アクセスログ)とリアルタイムログです。2つの違いは、[こちら](https://docs.aws.amazon.com/ja_jp/AmazonCloudFront/latest/DeveloperGuide/logging.html)をご確認ください。

### 7-1. CloudFront 標準ログ (アクセスログ)

CloudFront 標準ログは、選択した Amazon S3 バケットに配信されます。

s3_key の初期値: `(^|\/)[0-9A-Z]{14}\.20\d{2}-\d{2}-\d{2}-\d{2}.[0-9a-z]{8}\.gz$$`

ログ種別はデフォルト設定の出力ファイル名を正規表現で判別。ログには AWS アカウント ID が含まれていないので S3 のプレフィックスに含めてください。

1. AWS マネジメントコンソールにログイン
1. [CloudFront コンソール](https://console.aws.amazon.com/cloudfront/home?) に移動
1. 画面左メニューの [**Logs**] を選択 => [**Distribution logs**] タブを選択
1. ログを取り込みたい [**Distribution ID**] を選択
1. [Standard logs] タイトルの右にある [**Edit**] を選択
1. ポップアップした [Edit standard logs] 画面に次のパラメーターを入力する
    * Standard logs を [**Enabled**] にする
    * S3 bucket: [**aes-siem-123456789012-log**] を入力
        * 123456789012 は ご利用の AWS アカウント ID に置換してください
    * S3 bucket prefix: [**AWSLogs/123456789012/CloudFront/global/ディストリビューションID/standard/**] を入力
        * ご利用の AWS アカウント ID と CloudFront のディストリビューション ID に置換してください
    * Cookie logging: [**Yes**] にする
    * [**Update**] を選択して設定完了

### 7-2. CloudFront リアルタイムログ

CloudFront リアルタイムログは、Amazon Kinesis Data Streams で選択したデータストリームに配信されます。その後、Amazon Kinesis Data Firehose を使用して、ログデータを Amazon S3 に送信します。

s3_key の初期値: `CloudFront/.*/realtime/`

リアルタイムログには、標準の保存パスがないので上記の S3 パスをプレフィックスで指定してください。 .* (ピリオドとアスタリスク) は自由な文字を入れられますのでリージョン等を含めてください。CloudFront のログには AWS アカウント ID と ディストリビューションID が含まれていないので S3 のプレフィックスに、この2つを含めるようにしてください。

次の順番で設定します。

1. Kinesis Data Stream
1. Kinesis Data Firehose
1. CloudFront

Kinesis Data Stream と Kinesis Data Firehose の設定

1. AWS マネジメントコンソールにログイン
1. **バージニア北部リージョン**の [Kinesis コンソール](https://console.aws.amazon.com/kinesis/home?region=us-east-1) に移動
1. 画面左メニューの [**データストリーム**] を選択 => [**データストリームの作成**] を選択
1. [データストリームの作成] 画面にて次のパラメーターを入力
    * データストリーム名: [**任意の名前**] を入力
    * 開いているシャードの数: [**任意のシャード数**] を入力
    * [**データストリームの作成**] を選択
1. 続けて Kinesis Data Firehose の設定します。作成したデーターストリームのステータスが [アクティブ] になるまで待ってから、画面下の [コンシューマー] パネルの [**配信ストリームを使用した処理**] を選択。
1. [New delivery stream] 画面にて次のパラメーターを入力
    * Delivery stream name: [**任意の名前**] を入力
    * Source: [**Kinesis Data Stream**] にチェックを入れる
    * Kinesis data stream: [**1つ前で作成した Kinesis Data Stream**] を選択する
    * [**Next**] を選択
1. [Process records] 画面にて次のパラメーターを入力
    * Data transformation: [**Disabled**] を選択
    * Record format conversion: [**Disabled**] を選択
    * [**Next**] を選択
1. [Choose a destination] 画面にて次のパラメーターを入力
    * Destination: [**Amazon S3**] を選択
    * S3 bucket: [**aes-siem-123456789012-log**] を入力
        * 123456789012 は ご利用の AWS アカウント ID に置換してください
    * S3 prefix: [**AWSLogs/123456789012/CloudFront/global/ディストリビューションID/realtime/**] を入力
        * 123456789012 は ご利用の AWS アカウント ID に置換してください
    * S3 error prefix: [**AWSLogs/123456789012/CloudFront/global/ディストリビューションID/realtime/error/**] を入力
1. [Configure settings] 画面にて次のパラメーターを入力
    * Buffer size: [**任意の数字**]を 入力
    * Buffer interval: [**任意の数字**]を 入力
    * S3 compression: [**GZIP**] を選択
    * 次以降はデフォルトのまま
    * [**Next**] を選択
1. [**Create delivery stream**] を選択

CloudFront の設定

1. [CloudFront コンソール](https://console.aws.amazon.com/cloudfront/home?) に移動
1. 画面左メニューの [**Logs**] を選択 => [**Real-time log configurations**]タブを選択
1. 画面右の[**Create configuration**] を選択
1. [Create real-time log configuration] 画面に次のパラメーターを入力する
    * Name: [**任意の名前**] を入力
    * Sampling rate: [**100**]
        * 全てのログを SIEM on Amazon ES に取り込みます
    * Fields: [**全てのフィールドにチェックを入れてください**]
        * デフォルトで全てがチェックされています
    * Endpoint:  [**2つ前で作成した Kinesis Data Stream**] を選択する
    * IAM role: [**Create new service role CloudFrontRealtimeLogConfiguRole-XXXXXXXXXXXX**] を選択
    * Distribution: [**対象のDistribution**] を選択
    * Cache behavior(s): [**Default(*)**] を選択
1. [**Create configuration**] を選択して設定完了

## 8. AWS WAF

AWS WAF には AWS WAF と AWS WAF Classic の2つがありますが、両方とも同じ方法で S3 バケットに出力してください。

s3_key の初期値: `aws-waf-logs-`

AWS WAF の ACL トラフィックログは Kinesis Data Firehose から S3 バケットにエクスポートします。Kinesis Data Firehose の名前は [**aws-waf-logs-**] から始まることが条件となっており、この名前が S3 バケット出力時のファイル名に含まれているため、これをログ種類の判別に使用しています。

### 8-1. AWS WAF 共通設定

最初に Kinesis Data Firehose をデプロイします

1. AWS マネジメントコンソールにログイン
1. [Kinesis コンソール](https://console.aws.amazon.com/kinesis/home?) に移動して、**AWS WAF がデプロイされたリージョン** を選択
1. 画面左メニューの [**配信ストリーム**] を選択 => [**Create delivery stream**] を選択
1. [New delivery stream] 画面にて次のパラメーターを入力
    * Delivery stream name: [**aws-waf-logs-任意の名前**] を入力
    * Source: [**Direct PUT or other sources**] にチェックを入れる
    * [**Next**] を選択
1. [Process records] 画面にて次のパラメーターを入力
    * Data transformation: [**Disabled**] を選択
    * Record format conversion: [**Disabled**] を選択
    * [**Next**] を選択
1. [Choose a destination] 画面にて次のパラメーターを入力
    * Destination: [**Amazon S3**] を選択
    * S3 bucket: [**aes-siem-123456789012-log**] を入力
        * 123456789012 は ご利用の AWS アカウント ID に置換してください
    * S3 prefix: [**AWSLogs/123456789012/WAF/リージョン/**] を入力
    * S3 error prefix: [**AWSLogs/123456789012/WAF/リージョン/error/**] を入力
        * 123456789012 は ご利用の AWS アカウントに、ap-northeast-1 はリージョンに置換してください。WAF をアタッチするリソースが CloudFront の時はリージョンを **global** としてください
1. [Configure settings] 画面にて次のパラメーターを入力
    * Buffer size: [**任意の数字**] を入力
    * Buffer interval: [**任意の数字**] を入力
    * S3 compression: [**GZIP**] を選択
    * 次以降はデフォルトのまま
    * [**Next**] を選択
1. [**Create delivery stream**] を選択

### 8-2. AWS WAF の Logging 設定

1. [WAFv2 コンソール](https://console.aws.amazon.com/wafv2/home?) に移動
1. 画面左メニューの [**Web ACLs**] を選択
1. 画面中央のプルダウンから、WAF をデプロイした [**リージョン**] を選択 => ログ取得の対象 WAF の Name を選択する
1. [**Logging and metrics**] タブを選択 => [**Enable logging**] を選択
1. [Amazon Kinesis Data Firehose Delivery Stream] のプルダウンから [**作成した Kinesis Firehose**] を選択
1. [**Enable logging**] を選択して設定完了

### 8-3. WAF Classic の Logging 設定

1. [WAF Classic コンソール](https://console.aws.amazon.com/waf/home?) に移動
1. 画面左メニューの [**Web ACLs**] を選択
1. 画面中央のプルダウンから、WAF をデプロイした [**リージョン**] を選択 => ログ取得の対象 WAF の Name を選択する
1. 画面右上の [**Logging**] タブを選択 => [**Enable logging**] を選択
1. [Amazon Kinesis Data Firehose] のプルダウンから [**作成した Kinesis Firehose**] を選択
1. [**Create**] を選択して設定完了

## 9. Route 53 Resolver VPC DNS Query Log

s3_key の初期値: `vpcdnsquerylogs` (デフォルト設定の出力パスの一部)

1. [Route 53 Resolver コンソール](https://console.aws.amazon.com/route53resolver/home?) に移動
1. 画面左メニューの [**クエリのログ記録**] を選択
1. [クエリログ記録の設定] 画面で次のパラメータを入力
    * 名前: [**任意の名前**] を入力
    * クエリログの送信先: [**S3 バケット**] を選択
    * Amazon S3 バケット: [**aes-siem-123456789012-log**] を選択
        * 123456789012 は ご利用の AWS アカウント ID に置換してください
    * クエリをログ記録するVPC: [**任意のVPCを追加**]
1. [**クエリログの設定**] を選択して設定完了

## 10. EC2 インスタンス (Amazon Linux 2)

Amazon Linux 2 を実行している EC2 インスタンス の Secure ログを CloudWatch Agent から CloudWatch Logs に送信し、サブスクリプションフィルタで Kinesis Data Firehose に配信し、S3 バケットへ出力してください。

OS のシステムログ
s3_key の初期値: `/[Ll]inux/` (Firehose の出力パスに指定)

Secure ログ
s3_key の初期値: `[Ll]inux.?[Ss]ecure` (Firehose の出力パスに指定)

ログ出力は Kinesis Data Firehose 経由となり、標準の保存パスがないので上記の s3_key を Kinesis Data Firehose の出力先の S3 バケットのプレフィックスに指定してください。リージョン情報はログに含まれていないので、S3 キーに含めることで取得することができます。OS のシステムログとして取り込んだ後にSecure ログとして分類する方法と、最初から Secure ログとして取り込む方法の2種類があります。前者はプロセス名から判断するので、確実に Secure ログを Secure ログとして取り込むためには後者を選択してしてください。一方で後者はログの出力先毎に Firehose をデプロイする必要があります。

手順は概要のみです。

1. Amazon Linux 2 でデプロイした EC2 インスタンスに CloudWatch Agent をインストール
1. CloudWatch Logs にログを転送
1. CloudWatch Logs のサブスクリプションで Firehose に出力
1. Firehose の出力先に S3 バケットを選択
1. S3 バケットの出力先
    * OS ログとして出力するプレフィックス: [**AWSLogs/123456789012/EC2/Linux/[region]/**]
    * Secure ログとして出力するプレフィックス: [**AWSLogs/123456789012/EC2/Linux/Secure/[region]/**]
        * 123456789012 は ご利用の AWS アカウント ID に置換してください

## 11. AWS Security Hub (under development)

Security Hub の 検出結果を S3 への出力するために、検出結果イベントを Amazon EventBridge で検出させ、Kinesis Data Firehose に配信して、S3 バケットへ出力してください。

s3_key の初期値: `SecurityHub` (Firehose の出力パスに指定)

ログ出力は Kinesis Data Firehose 経由となり、標準の保存パスがないので上記の s3_key をKinesis Data Firehose の出力先 S3 バケットのプレフィックスに指定してください。

Kinesis Data Firehose の設定

1. AWS マネジメントコンソールにログイン
1. [Kinesis コンソール](https://console.aws.amazon.com/kinesis/home?) に移動
1. 画面左メニューの [**配信ストリーム**] を選択
1. 画面右上の [**Create delivery stream**] を選択
1. [New delivery stream] 画面にて次のパラメーターを入力
    * Delivery stream name: [**aes-siem-firehose-securityhub**] を入力
    * Source: [**Direct PUT or other sources**] にチェックを入れる
    * [Enable server-side encryption for source records in delivery stream] は任意
    * [**Next**] を選択
1. [Process records] 画面にて次のパラメーターを入力
    * Data transformation: [**Disabled**] を選択
    * Record format conversion: [**Disabled**] を選択
    * [**Next**] を選択
1. [Choose a destination] 画面にて次のパラメーターを入力
    * Destination: [**Amazon S3**] を選択
    * S3 bucket: [**aes-siem-123456789012-log**] を入力
        * 123456789012 は ご利用の AWS アカウント ID に置換してください
    * S3 prefix: [**AWSLogs/123456789012/SecurityHub/[region]/**] を入力
        * 123456789012 は ご利用の AWS アカウント ID に置換してください
    * S3 error prefix: [**AWSLogs/123456789012/SecurityHub/[region]/error/**] を入力
1. [Configure settings] 画面にて次のパラメーターを入力
    * Buffer size: [**任意の数字**]を 入力
    * Buffer interval: [**任意の数字**]を 入力
    * S3 compression: [**GZIP**] を選択
    * 次以降はデフォルトのまま
    * [**Next**] を選択
1. [**Create delivery stream**] を選択して Kinesis Data Firehose のデプロイ完了

EventBridge の設定

1. [EventBridge コンソール](https://console.aws.amazon.com/events/home?) に移動
1. 画面左メニューの [**ルール**] を選択 => [**ルールの作成**] を選択
1. [ルールを作成] 画面にて次のパラメーターを入力
    * 名前: aes-siem-securityhub-to-firehose
    * イベントパターンを選択
    * サービスごとの事前定義パターン
    * サービスプロバイダー: AWS
    * サービス名: Security Hub
    * イベントタイプ: Security Hub Findings - Imported
    * [イベントバス]は変更なし
    * ターゲット: Firehose 配信ストリーム
    * ストリーム: aes-siem-firehose-securityhub
    * 他は任意の値を選択して
    * [**作成**] を選択を選択して完了

## マルチリージョン・マルチアカウント

他のアカウントや他リージョンのログを、S3 レプリケーションか、クロスアカウントで ログ用 S3 バケットに出力することで SIEM on Amazon ES にログを取り込むことができます。
出力先のパスは上記で設定した S3 Key に基づいてください。

## 既存の S3 バケットからログからの取り込み

すでに作成済みの S3 バケット に保存されログ、または AWS KMS カスタマーマネジメントキー を使って、SIEM on Amazon ES にログを取り込むこともできます。
既存の S3 または AWS KMS を使うためには、Lambda 関数 es-loader に権限を付与する必要があります。[ここを](deployment_ja.md) を参照して、AWS CDK を使ってデプロイしてください。

[READMEに戻る](../README_ja.md)
