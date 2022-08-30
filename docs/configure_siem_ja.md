# SIEM on Amazon OpenSearch Service の設定変更

[In English](configure_siem.md) | [READMEに戻る](../README_ja.md)

## 目次

* [ログ取り込み方法のカスタマイズ](#ログ取り込み方法のカスタマイズ)
* [IoC による脅威情報の付与](#ioc-による脅威情報の付与)
* [ログ取り込みの除外設定](#ログ取り込みの除外設定)
* [OpenSearch Service の設定変更](#opensearch-service-の設定変更)
* [AWS サービス以外のログの取り込み](#aws-サービス以外のログの取り込み)
* [他の S3 バケットからニアリアルタイムの取り込み](#他の-s3-バケットからニアリアルタイムの取り込み)
* [S3 バケットに保存された過去データの取り込み](#s3-バケットに保存された過去データの取り込み)
* [SQS の Dead Letter Queue からの取り込み](#sqs-の-dead-letter-queue-からの取り込み)
* [モニタリング](#モニタリング)
* [CloudFormation テンプレートの作成](#cloudformation-テンプレートの作成)

## ログ取り込み方法のカスタマイズ

SIEM on OpenSearch Service へのログの取り込みをカスタマイズできます。S3 バケットにエクスポートされたログを、Lambda 関数の es-loader が正規化して SIEM on OpenSearch Service にロードしています。デプロイされた Lambda 関数名は aes-siem-es-loader となります。この Lambda 関数 es-loader は、S3 バケットから「すべてのオブジェクト作成イベント」のイベント通知を受け取って、起動します。S3 バケットに保存されたファイル名やファイルパスから、ログの種類を特定して、ログ種類毎に定義された方法でフィールドを抽出し、[Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) へマッピングをして、最後に SIEM on OpenSearch Service へインデックス名を指定してロードします。

このプロセスは設定ファイル (aws.ini) に定義された初期値に基づいています。任意の値に変えることもできます。例えば、あるログの S3 バケットへのエクスポートは初期値とは違うファイルパスにしたり、インデックス名の変更をしたり、インデックスのローテーション間隔を変更する場合等です。変更は、aws.ini を参考に user.ini を作成して項目と値を定義します。user.ini に設定した値は aws.ini よりも優先度が高く設定されており、初期値の値を内部で上書きします。

user.ini の保存は、Lambda レイヤーによる追加(推奨)か、AWS マネジメントコンソールから直接編集をしてください。SIEM on OpenSearch Service をアップデートすると、Lambda 関数が新しい関数に入れ替わります。Lambda レイヤーであれば独立しているので user.ini は維持されますが、AWS マネジメントコンソールから直接編集した user.ini は削除されるので、再度 user.ini を作成する必要があります。

注) 設定ファイル( aws.ini/user.ini )の読み込みは Python3 の標準ライブラリ configparser を使用しています。文法等はこのライブラリに従います。空白等を含んだ設定値であってもそのまま記載してください。ダブルクオーテーションやシングルクオーテーションで囲う必要はありませんのでご注意ください。例えば、設定項目に key、設定値として "This is a sample value" を定義する場合、下記のようになります。

正しい設定例)

```ini
key = This is a sample value
```

誤った設定例)

```ini
key = "This is a sample value"
```

configparser の文法の詳細は、[こちら](https://docs.python.org/ja/3/library/configparser.html#module-configparser) をご参照ください。

### AWS Lambda レイヤーによる追加方法(推奨)

aws.ini を参考にして user.ini を作成してください。

例) AWS CloudTrail の ローテーション間隔を初期値の毎月から毎日に変更する。

aws.ini の初期値は以下となっています

```ini
[cloudtrail]
index_rotation = monthly
```

user.ini を作成してパラメーターを下記の通りとします

```ini
[cloudtrail]
index_rotation = daily
```

この user.ini ファイルを Lambda レイヤー用に zip で圧縮します。user.ini はディレクトリを含まないようにしてください。圧縮ファイル名は任意の名前が可能です(ここでは configure-es-loader.zip としています)。

```sh
zip -r configure-es-loader.zip user.ini
```

次に、Lambda レイヤーを作成します。

1. AWS マネジメントコンソールにログイン
1. [Lambda コンソール](https://console.aws.amazon.com/lambda/home?) に移動
1. 左メニューの [**レイヤー**] => 画面右上の [**レイヤーの作成**] を選択
1. レイヤーの設定に以下を入力。他は空欄のまま。
    * 名前: aes-siem-configure-es-loader (任意の名前)
    * zipファイルのアップロードにチェック
    * アップロードを選択して、configure-es-loader.zip を選択
    * 互換性のあるランタイム: Python 3.8 を選択
1. [**作成**] を選択

最後に、Lambda 関数 es-loader に、作成した Lambada レイヤーを設定します

1. Lambda コンソールの左メニューの [**関数**] => 関数名の [**aes-siem-es-loader**] を選択
1. [設定] タブ、[デザイナー] パネルの画面中央にある [**Layers**] を選択
1. 画面下の [レイヤー] パネルの、[**レイヤーの追加**] を選択
1. カスタムレイヤーにチェックを入れて、カスタムレイヤーのプルダウンメニューから、[**aes-siem-configure-es-loader**] または任意で設定した名前を選択し、[**追加**] を選択

設定完了です。[レイヤー] パネルから設定済みであることを確認できます。

### AWSマネジメントコンソールから直接編集

AWSマネジメントコンソールから user.ini を直接編集して設定変更をします。

1. AWS マネジメントコンソールにログイン
1. [Lambda コンソール](https://console.aws.amazon.com/lambda/home?) に移動
1. 左メニューの [**関数**] => 関数名の [**aes-siem-es-loader**] を選択
1. [関数コード] パネルに Lambda 関数のファイル一覧が表示されます。ルートディレクトリに user.ini を作成して、設定情報を追加・編集
1. [関数コード] パネルの右上にある [**Deploy**] ボタンを選択

設定完了です。SIEM on OpenSearch Service をアップデートすると Lambda 関数 の es-loader が入れ替わり user.ini は削除されるので、再度同じことをしてください。

## IoC による脅威情報の付与

IP アドレス、ドメイン名を元に脅威情報を付与することができます。IoC (Indicators of compromise) の脅威情報ソースとして、以下の Provider を CloudFormation または CDK でのデプロイ時に選択することができます。

* [Tor Project](https://www.torproject.org)
* [Abuse.ch Feodo Tracker](https://feodotracker.abuse.ch)
* [AlienVault OTX](https://otx.alienvault.com/)

IoC 数が多いとは Lambda の処理時間が増えるので、IoC は厳選して下さい。AlienVault OTX の IoC を利用される方は、[AlienVault OTX](https://otx.alienvault.com/#signup) で API キーを取得して下さい。

独自の IoC も使用することができます。サポートしている IoC のフォーマットは TXT 形式と SITX 2.x 形式です。TXT 形式は、IP アドレスおよび CIDR 範囲を 1 行に 1 つずつ表示する必要があります。

独自の IoC ファイルは以下の場所にアップロードして下さい。**_"your provider name"_** は任意の名前に変えて下さい。"your provider name" フォルダを作成しな場合は、Provider の名前は "custom" になります。

TXT形式

* s3://aes-siem-**_123456789012_**-geo/IOC/TXT/**_your provider name_**/

STIX 2.x 形式

* s3://aes-siem-**_123456789012_**-geo/IOC/STIX2/**_your provider name_**/

Provider 毎に IoC は重複の排除をしているのでファイルに含まれる indicator 数と、実際にデータベースに保存される indicator 数は一致しません。ダウンロードできるファイルは 5,000 個まで、作成される IoC データベースは 128 MB までの制限があります。

作成された IoC データベースの情報は下記を参照して下さい。

1. [Step Functions コンソール](https://console.aws.amazon.com/states/home?) に移動
1. ステートマシーンの **[aes-siem-ioc-state-machine]** を選択
1. 成功している最新の実行を選択
1. タブメニューの [**実行出力**] を選択
1. Provider 毎の IoC 数、タイプ毎の IoC 数、データベースのサイズを確認できます

IoC のダウンロード及びデータベースの作成は、デプロイ後に最初に実行されるまで最大で24時間かかります。サイズが大きくて、データベースの作成に失敗している場合は、IoC を厳選後に、キャッシュファイルの `s3://aes-siem-123456789012-geo/IOC/tmp` を削除して、Step Functions の [**aes-siem-ioc-state-machine**] を手動で実行して下さい。

エンリッチするフィールドは user.ini で指定して下さい。

例) hoge ログの source.ip と destination.ip を元にエンリッチする場合

```conf
[hoge]
ioc_ip = source.ip destination.ip
```

例) fuga ログの DNS のクエリーである ECS フィールドの dns.question.name を元にエンリッチする場合

```conf
[fuga]
ioc_domain = dns.question.name
```

エンリッチされた情報は以下のフィールで確認することができます。

* threat.matched.providers: マッチした IoC を提供した Provider。複数マッチした場合はリスト形式
* threat.matched.indicators: IoC とマッチした値。複数マッチした場合はリスト形式
* threat.enrichments: エンリッチされた詳細。nested 形式

## ログ取り込みの除外設定

S3 バケットに保存されたログは自動的に OpenSearch Service に取り込まれますが、条件を指定することで取り込みの除外をすることができます。これによって OpenSearch Service のリソースを節約できます。

設定できる条件は以下の2つです

1. S3 バケットの保存パス(オブジェクトキー)
1. ログのフィールドと値

### S3 バケットのファイルパス(オブジェクトキー) による除外

CloudTrail や VPC Flow Logs を S3 バケットに出力すると、AWS アカウント ID やリージョン情報が付与されます。これらの情報を元にログの取り込みを除外します。例えば検証環境の AWS アカウントのログを取り込まない等の設定をすることができます。

#### 設定方法

user.ini (aws.ini) の s3_key_ignored に除外したいログの文字列を指定。この文字列が**含まれている**とログは取り込まれません。文字列には正規表現が指定できます。文字列が短すぎたり一般的な文字だと、除外したくないログにもマッチしてしまう可能性があるのでご注意ください。否定の正規表現により取り込むログだけを設定することも可能です。

##### 例1) VPC Flow Logs で AWS アカウント 000000000000 を除外する。単純な条件なので文字列を指定する

S3 バケットに保存されたログ: s3://aes-siem-123456789012-log/AWSLogs/**000000000000**/vpcflowlogs/ap-northeast-1/2020/12/25/000000000000_vpcflowlogs_ap-northeast-1_fl-1234xxxxyyyyzzzzz_20201225T0000Z_1dba0383.log.gz

設定ファイル user.ini

```ini
[vpcflowlogs]
s3_key_ignored = 000000000000
```

##### 例2) vpcflowlogs で 2 つの AWS アカウント 111111111111 と 222222222222 を除外する。文字列が複数あるので正規表現で指定

```ini
[vpcflowlogs]
s3_key_ignored = (111111111111|222222222222)
```

##### 例3) VPCFlowlogs で AWS アカウント 111111111111 と 222222222222 のみを取り込む

否定の正規表現により取り込むログだけを設定

```ini
[vpcflowlogs]
s3_key_ignored = ^(?!.*(111111111111|222222222222)).*
```

### ログのフィールドと値による除外

個々のログのフィールドとその値を条件にして除外できます。例えば、VPC Flow Logs で特定の送信元 IP アドレスからの通信を除外する等です。

設定方法)

CSV ファイルを作成して、除外したいログのログタイプ、フィールド、除外条件を設定してください。1つのフィールドに対して複数の条件を設定する時は正規表現で指定してください。GeoIP を保存している S3 バケット(デフォルトではaes-siem-1234567890-**geo**)に、除外条件を指定した CSV ファイルをアップロード。アップロード先はプレフィックスなしのルートパス。

* CSV ファイル名: [**exclude_log_patterns.csv**]
* CSV ファイルの保存先: [s3://aes-siem-1234567890-**geo**/exclude_log_patterns.csv]
* CSV フォーマット: ヘッダーを含んだ以下のフォーマット

```csv
log_type,field,pattern,pattern_type,comment
```

|ヘッダー|説明|
|--------|----|
|log_type|aws.ini または user.ini で指定したログのセクション名。例) cloudtrail, vpcflowlogs|
|field|生ログのオリジナルのフィールド名。正規化後のフィールドではありません。JSON等の階層になっているフィールドはドット区切り( **.** )で指定。例) userIdentity.invokedBy|
|pattern|フィールドの値を文字列で指定。**完全一致**により除外される。テキスト形式と正規表現が可能。例) テキスト形式: 192.0.2.10、正規表現: 192\\.0\\.2\\..*|
|pattern_type|正規表現の場合は [**regex**]、文字列の場合は [**text**]|
|comment|任意の文字列。除外条件には影響しない|

#### 設定例

```csv
log_type,field,pattern,pattern_type,comment
vpcflowlogs,srcaddr,192.0.2.10,text,sample1
vpcflowlogs,dstaddr,192\.0\.2\.10[0-9],regex,sample2
vpcflowlogs,dstport,80|443,regex,sample3
cloudtrail,userIdentity.invokedBy,.*\.amazonaws\.com,regex,sample4
```

##### sample1

VPC Flow Logs で、送信元 IP アドレス(srcaddr) が 192.0.2.10 と一致する時は除外。pattern_type を text とした場合の条件はテキスト形式で完全一致。192.0.2.100 などが誤って除外されることを防ぐためです。フィールド名は、source.ip等の正規化後のフィールド名を指定してもマッチせず除外されません。

##### sample2

VPC Flow Logs で、送信先 IP アドレス(dstaddr) が 192.0.2.10 の文字列を含んだ IP アドレスを除外。正規表現で指定したことにより、192.0.2.100 も除外される。pattern_type を regex とした場合は、正規表現として意味のある文字列(ドット等)はエスケープしてください。

##### sample3

VPC Flow Logs で、送信先 IP ポート(dstport) が 80 または 443 の 2 つを含んだログを除外。1つのフィールドに複数条件を指定するために正規表現で設定。同じフィールドに対して、条件毎に複数行に指定することはできません。

##### sample4

CloudTrail で、{'userIdentity': {'invokedBy': '*.amazonaws.com'}} と一致した場合に除外する。フィールド名が入れ子になっているので、CSVではドット区切りで指定。この例は、Config や ログ配信などのAWS のサービスがリクエストしたAPI Callのログを取り込まない。

## OpenSearch Service の設定変更

SIEM に関する OpenSearch Service のアプリケーションの設定を変更できます。設定は以下のような項目がありインデックス毎に定義できます。

* インデックスのレプリカ数、シャード数
* フィールドのマッピング、タイプ指定
* Index State Management による UltraWarm へのインデックスの自動移行や削除

設定は自由にできます。設定方法は 2 種類あり、SIEM on OpenSearch Service のバージョンによって違いますのでご注意ください。

* [Index templates](https://opensearch.org/docs/latest/opensearch/index-templates/) (SIEM on OpenSearch Service v2.4.1 以降)
* [legacy index templates](https://www.elastic.co/guide/en/elasticsearch/reference/current/indices-templates-v1.html) (SIEM on OpenSearch Service v2.4.0 まで)

SIEM on OpenSearch Service にて初期設定している項目があります。設定値は [こちらの設定ファイル](../source/lambda/deploy_es/data.ini) の [component-templates] と [index-templates] を確認するか、OpenSearch Dashboards の Dev Tools から以下のコマンドで確認可能です。

```http
GET 対象のindex名/_settings
GET 対象のindex名/_mapping
```

設定を追加・変更する場合にはインデックステンプレートを作成して値を保存します。テンプレート名はすでに使われているテンプレートは避けてください。

SIEM on OpenSearch Service のテンプレートの予約名

* log\[-aws][-サービス名]_aws
* log\[-aws][-サービス名]_rollover
* component_template_log\[-aws][-サービス名] (SIEM on OpenSearch Service v2.4.1 以降のみ)

SIEM on OpenSearch Service の初期値を上書きするには Index templates の priority を 10 以上、または legacy index templates の order を 1 以上にしてください。

設定例

* Dev Tools から CloudTrail のインデックス (log-aws-cloudtrail-*) のシャード数をデフォルトの 3 から 2 に減らす

Index templates (SIEM on OpenSearch Service v2.4.1 以降) の場合

```http
POST _index_template/log-aws-cloudtrail_mine
{
  "index_patterns": ["log-aws-cloudtrail-*"],
  "priority": 10,
  "composed_of": [
    "component_template_log",
    "component_template_log-aws",
    "component_template_log-aws-cloudtrail"
  ],
  "template": {
    "settings": {
      "number_of_shards": 2
    }
  }
}
```

Legacy index templates (SIEM on OpenSearch Service v2.4.0 以前) の場合

```http
POST _template/log-aws-cloudtrail_mine
{
  "index_patterns": ["log-aws-cloudtrail-*"],
  "order": 1,
  "settings": {
    "index": {
      "number_of_shards": 2
    }
  }
}
```

## AWS サービス以外のログの取り込み

AWS 以外のログをログ用 S3 バケットにエクスポートすることで SIEM on OpenSearch Service に取り込むことができます。ファイルフォーマットはテキスト形式、JSON 形式、CSV 形式に対応しています。テキスト形式は1行ログを取り込むことができますが、複数行ログには対応していません。S3 へのエクスポートは Logstash や Fluentd のプラグインを使う方法があります。

設定の基本的な流れを、Apache HTTP Server のログを例にして説明します

1. user.ini に取り込みたいログを定義する

    ```ini
    [apache]
    ```

1. Apache HTTP Server の access ログを s3 バケットにエクスポートする時のファイルパス、ファイル名等を定義する。正規表現が使えます。この情報からログの種類を特定します

    ```ini
    s3_key = UserLogs/apache/access.*\.log
    ```

1. ファイルフォーマットを指定する

    ```ini
    file_format = text
    ```

1. インデックス名を指定する

    ```ini
    index_name = log-web-apache
    ```

1. ログからフィールドを抽出するために、名前付き正規表現を定義する

    ```ini
    log_pattern = (?P<remotehost>.*) (?P<rfc931>.*) (?P<authuser>.*) \[(?P<datetime>.*?)\] \"(?P<request_method>.*) (?P<request_path>.*)(?P<request_version> HTTP/.*)\" (?P<status>.*) (?P<bytes>.*)
    ```

1. イベントの発生日時を SIEM on OpenSearch Service に伝えるためにtimestamp を指定する。フォーマットが iso8601 以外なら [Dateフォーマット](https://docs.python.org/ja/3/library/datetime.html#strftime-and-strptime-format-codes) も定義

    ```ini
    timestamp = datetime
    timestamp_format = %d/%b/%Y:%H:%M:%S %z
    ```

1. Elastic Common Schema にマッピングしたいフィールドを指定する

    ```ini
    # 書式
    # ecs = ECSのフィールド名1 ECSのフィールド名2
    # ECSのフィールド名1 = ログのオリジナルフィールド名
    # ECSのフィールド名2 = ログのオリジナルフィールド名
    ecs = source.ip user.name http.request.method url.path http.version http.response.status_code http.response.bytes
    source.ip = remotehost
    user.name = authuser
    http.request.method = request_method
    url.path = request_path
    http.version = request_version
    http.response.status_code = status
    http.response.bytes = bytes
    ```

1. GeoIPで国情報を取得するECSフィールドを指定する

    ```ini
    # 値は source または destination
    geoip = source
    ```

設定項目の詳細については Lambda 関数の es-loader の aws.ini をご参照ください。

この定義ファイルだけでは処理できない場合、Python スクリプトでカスタムロジックを入れることも可能です。例えば user-agent から OS や プラットフォームを抽出するロジックを入れるなどです。ファイル名は sf_ログの種類.py としてください。この例では、sf_apache.py となります。「ログの種類」に - (ダッシュ)が含まれている場合には、\_ (アンダーバー)に置換してください。例) ログの種類: cloudfront-realtime => ファイル名: sf_cloudfront_realtime.py

このファイルを es-loader の siem ディレクトリに保存するか、Lambda レイヤーの siem ディレクトリに保存してください。

Lambda レイヤーの zip 圧縮ファイルの内部は以下のディレクトリ構成にしてください

```text
|- user.ini
|- siem
    |- sf_apache.py
    |- sf_ログ種類1.py
    |- sf_ログ種類2.py
```

zip を作成し Lambda レイヤーに登録すれば設定完了です

## 他の S3 バケットからニアリアルタイムの取り込み

![Custom S3](images/custom-s3.svg)

S3バケット、通知手段のリソースポリシーを変更することで、同一アカウント、同一リージョンのバケットのログをOpenSearch Service に取り込むことができます。

※ CDK / CloudFormation で作成された AWS リソースのポリシーの変更はしないでください。SIEM のアップデート時にデフォルトのポリシーで上書きされます。

### 共通設定

es-loader が S3 バケットのログを取得できるように、ログが保存されている S3 バケットのバケットポリシーを編集します。

1. es-loader の IAM ロール名を取得する。IAM Role で、[**siem-LambdaEsLoaderServiceRole**] で検索して表示される IAM ロールの ARN をコピーして下さい。
2. 以下のポリシー例を参考にバケットポリシーを修正

```json
{
    "Version": "2012-10-17",
    "Id": "Policy1234567890",
    "Statement": [
        {
            "Sid": "es-loader-to-s3-bucket",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::123456789012:role/aes-siem-LambdaEsLoaderServiceRoleXXXXXXXX-XXXXXXXXXXXXX"
            },
            "Action": "s3:GetObject",
            "Resource": [
                "arn:aws:s3:::your-bucket-name/*"
            ]
        }
    ]
}
```

### Amazon S3 Event Notifications

![Custom S3 Notification](images/custom-s3-eventnotification.svg)

1. S3 バケットでイベント通知を作成
    * 以下は必須項目です。他の値は環境に合わせて入力して下さい。
    * イベントタイプは[**すべてのオブジェクト作成イベント**] にチェック
    * 送信先: Lambda 関数 を選択
    * Lambda 関数: aes-siem-es-loader を選択
1. [**変更の保存**]

### Amazon SQS

![Custom S3 SQS](images/custom-s3-sqs.svg)

1. SQS キューの作成
    * 以下は必須項目です。他の値は環境に合わせて入力して下さい。
    * 標準タイプ
    * 可視性タイムアウト: 600秒
1. 以下のポリシー例を参考にSQSのアクセスポリシーを修正

    ```json
    {
        "Version": "2008-10-17",
        "Id": "sqs_access_policy",
        "Statement": [
            {
                "Sid": "__owner_statement",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789012:root"
                },
                "Action": "SQS:*",
                "Resource": "arn:aws:sqs:ap-northeast-1:123456789012:your-sqs-name"
            },
            {
                "Sid": "allow-s3bucket-to-send-message",
                "Effect": "Allow",
                "Principal": {
                    "Service": "s3.amazonaws.com"
                },
                "Action": "SQS:SendMessage",
                "Resource": "arn:aws:sqs:ap-northeast-1:123456789012:your-sqs-name",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": "123456789012"
                    }
                }
            },
            {
                "Sid": "allow-es-loader-to-recieve-message",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::123456789012:role/aes-siem-LambdaEsLoaderServiceRoleXXXXXXXX-XXXXXXXXXXXXX"
                },
                "Action": [
                    "SQS:GetQueueAttributes",
                    "SQS:ChangeMessageVisibility",
                    "SQS:DeleteMessage",
                    "SQS:ReceiveMessage"
                ],
                "Resource": "arn:aws:sqs:ap-northeast-1:123456789012:your-sqs-name"
            }
        ]
    }
    ```

1. SQS コンソールから、[**Lambda トリガー**] を設定する
    * [**aes-siem-es-loader**] を選択
1. S3 バケットでイベント通知を作成
    * 以下は必須項目です。他の値は環境に合わせて入力して下さい。
    * イベントタイプは[**すべてのオブジェクト作成イベント**] にチェック
    * 送信先: SQS を選択
    * SQS: 作成した SQS を選択

### Amazon SNS

![Custom S3 SNS](images/custom-s3-sns.svg)

1. SNS トピックを作成
    * スタンダードタイプ
1. 以下のポリシー例を参考に SNS のアクセスポリシーを修正

    ```json
    {
        "Version": "2008-10-17",
        "Id": "sns_access_policy",
        "Statement": [
            {
                "Sid": "__default_statement_ID",
                "Effect": "Allow",
                "Principal": {
                    "AWS": "*"
                },
                "Action": [
                    "SNS:GetTopicAttributes",
                    "SNS:SetTopicAttributes",
                    "SNS:AddPermission",
                    "SNS:RemovePermission",
                    "SNS:DeleteTopic",
                    "SNS:Subscribe",
                    "SNS:ListSubscriptionsByTopic",
                    "SNS:Publish"
                ],
                "Resource": "arn:aws:sns:ap-northeast-1:123456789012:your-sns-topic",
                "Condition": {
                    "StringEquals": {
                        "AWS:SourceOwner": "123456789012"
                    }
                }
            },
            {
                "Sid": "Example SNS topic policy",
                "Effect": "Allow",
                "Principal": {
                    "Service": "s3.amazonaws.com"
                },
                "Action": "SNS:Publish",
                "Resource": "arn:aws:sns:ap-northeast-1:123456789012:your-sns-topic",
                "Condition": {
                    "StringEquals": {
                        "aws:SourceAccount": "123456789012"
                    }
                }
            }
        ]
    }
    ```

1. SNS のコンソール画面から、サブスクリプションを作成
    * プロトコル: AWS Lambda
    * エンドポイント: es-loader の ARN
1. S3 バケットでイベント通知を作成
    * 以下は必須項目です。他の値は環境に合わせて入力して下さい。
    * イベントタイプは[**すべてのオブジェクト作成イベント**] にチェック
    * 送信先: SNS を選択
    * SNS: 作成した SNS を選択

### Amazon EventBridge

![Custom S3 EventBridge](images/custom-s3-eventbridge.svg)

1. S3 コンソールから、イベント通知の Amazon EventBridge をオンにする
1. EventBridge コンソールでルールを作成
    * ルールの詳細: デフォルトで次へ
    * イベントパターンを構築:
        * イベントソース: AWS のサービス
        * AWS のサービス: Simple Storage Service (S3)
        * イベントタイプ: Amazon S3 イベント通知
    * ターゲットを選択:
        * ターゲットタイプ: AWS のサービス
        * ターゲットを選択: Lambda 関数
        * 関数: aes-siem-es-loader
    * [**ルールの作成**] を選択して完了

## S3 バケットに保存された過去データの取り込み

S3 バケットに保存されているログをバッチで OpenSearch Service に取り込みます。通常は S3 バケットに保存された時にリアルタイムで取り込みます。一方で、バックアップをしていたデータを可視化やインシデント調査のために後から取り込むこともできます。同様の方法で、リアルタイムの取り込みに失敗して SQS のデッドレターキューに待避されたデータも取り込めます。

### 環境準備

#### スクリプト(es-loader)実行環境の準備

1. OpenSearch Service へ通信ができる VPC 内に Amazon Linux 2 で EC2 インスタンスをプロビジョニング
1. Amazon Linux からインターネット上の GitHub と PyPI サイト へ HTTP 通信を許可
1. EC2 に IAM ロールの [**aes-siem-es-loader-for-ec2**] をアタッチ
1. Amazon Linux のターミナルに接続して、[README](../README_ja.md) の説明にある [2. CloudFormation テンプレートの作成] の [2-1. 準備] と [2-2. SIEM on OpenSearch Service の clone] の手順を実施
1. 下記のコマンドで Python のモジュールをインストールします

    ```python
    cd siem-on-amazon-opensearch-service/source/lambda/es_loader/
    pip3 install -r requirements.txt -U -t .
    pip3 install pandas -U
    ```

#### 環境変数の設定

1. AWS マネジメントコンソールの Lambda コンソールに移動
1. aes-siem-es-loader 関数に移動して以下の 2 つの環境変数名と値をメモします
    * ES_ENDPOINT
    * GEOIP_BUCKET
1. 環境変数を EC2 インスタンスの Amazon Linux のターミナルに貼り付けます。値は環境に合わせて変更してください

    ```sh
    export ES_ENDPOINT=search-aes-siem-XXXXXXXXXXXXXXXXXXXXXXXXXX.ap-northeast-1.es.amazonaws.com
    export GEOIP_BUCKET=aes-siem-123456789012-geo
    ```

### S3 バケットのオブジェクトリストからの取り込み

1. es-loaderのディレクトリに移動します

    ```sh
    cd
    cd siem-on-amazon-opensearch-service/source/lambda/es_loader/
    ```

1. S3 バケットからオブジェクトリスト (s3-list.txt) を作成します。

    ```sh
    export AWS_ACCOUNT=123456789012   # お使いのAWSアカウントに置換してください
    export LOG_BUCKET=aes-siem-${AWS_ACCOUNT}-log
    aws s3 ls ${LOG_BUCKET} --recursive > s3-list.txt
    ```

1. 必要に応じて、取り込む対象を限定したリストを作成します

    例) 2021 年の CloudTrail のログだけのリストを作成

    ```sh
    grep CloudTrail s3-list.txt |grep /2021/ > s3-cloudtrail-2021-list.txt
    ```

1. 作成した S3 リストのオブジェクトを es-loader にログを流し込みます

    ```sh
    # 対象の S3 バケットにある全てのオブジェクトを流し込む
    ./index.py -b ${LOG_BUCKET} -l s3-list.txt
    # 抽出したオブジェクトを流し込む例
    # ./index.py -b ${LOG_BUCKET} -l s3-cloudtrail-2021-list.txt
    ```

1. 完了したら結果を確認します。取り込みに失敗すると失敗したオブジェクトリストのログファイルが生成されます。このファイルが存在しなければ全ての取り込みが成功してます
    * 成功したオブジェクトリスト: S3 のリストファイル名.finish.log
    * 失敗したオブジェクトリスト: S3 のリストファイル名.error.log
    * 失敗したオブジェクトのデバッグログ: S3 のリストファイル名.error_debug.log
1. 失敗したオブジェクトリストを、上記コマンドにリストとして再指定することで失敗したログファイルだけの取り込みができます。

    例)

    ```sh
    ./index.py -b ${LOG_BUCKET} -l s3-list.error.txt
    ```

1. 全ての取り込みが成功したら、読み込み用に作成した S3 オブジェクトリストと、生成されたログファイルを削除してください

## SQS の Dead Letter Queue からの取り込み

SQS の SIEM 用のデッドレターキュー (aes-siem-dlq) からメッセージを取り込みます。(実体は S3 バケット上のログ)。DQLの再処理による方法と、EC2 インスタンスで処理する方法の 2 つの方法があります。

### DLQ再処理による取り込み

1. SQS のコンソールに移動します
1. [**aes-siem-dlq**] を選択します
1. 画面右上の、[**DLQ 再処理の開始**] を選択
1. デッドレターキューの再処理の画面に遷移しました
    * [**再処理のためにカスタム送信先に移動**]にチェックボックスを入れます
    *「既存のキューを選択」で [**aes-siem-sqs-split-logs**] を選択
    * 画面右下の [**DQLの再処理**] を選択

以上で、再取り込みが始まります。

### EC インスタンスによる取り込み

[S3 バケットに保存された過去データの取り込み](#s3-バケットに保存された過去データの取り込み) で作成した EC2 インスタンスを使います。

1. リージョンを指定してから es-loader を実行します

    ```sh
    export AWS_DEFAULT_REGION=ap-northeast-1
    cd
    cd siem-on-amazon-opensearch-service/source/lambda/es_loader/
    ./index.py -q aes-siem-dlq
    ```

1. 完了したら結果を確認します。取り込みに失敗すると失敗したオブジェクトリストのログファイルが生成されます。このファイルが存在しなければ全ての取り込みが成功してます
    * 成功したオブジェクトリスト: aes-siem-dlq-日時.finish.log
    * 失敗したオブジェクトリスト: aes-siem-dlq-日時.error.log
    * 失敗したオブジェクトのデバッグログ: aes-siem-dlq-日時.error_debug.log

1. 失敗したオブジェクトリストは、S3 のオブジェクトリストとなっているため、前章のコマンドにリストとして指定することで失敗したログだけの取り込みができます
1. 全ての取り込みが成功したら生成されたログファイルを削除してください

## モニタリング

### OpenSearch Index Metrics

OpenSearch のパフォーマンスを最適にするためには、Index のローテーション間隔とシャード数を調整して、シャード数、シャードサイズを適切にする必要があります。現在、シャード数がどれくらいあるか、大きすぎるシャードはあるかなどを OpenSearch Service のダッシュボードから確認できます。

OpenSearch Dashboards のダッシュボード名: OpenSearch Metrics [サンプル](./dashboard_ja.md#Amazon-OpenSearch-Service-Metrics)

基となるデータは、1 時間 に 1 回、Lambda Function の aes-siem-index-metrics-exporter を実行して、ログ用 S3 バケットの `/AWSLogs/123456789012/OpenSearch/metrics/` に保存されます。

参考: [Amazon OpenSearch Service の運用上のベストプラクティス](https://docs.aws.amazon.com/ja_jp/opensearch-service/latest/developerguide/bp.html)

### CloudWatch Dashboard

SIEM を構成する主要な AWS リソースのメトリックスやエラーログを確認できます。OpenSearch Service での Indexing や Search のパフォーマンスチューニング、不具合時などのトラブルシュートに活用できます。

CloudWatch Dashboard のカスタムダッシュボード名: [SIEM](https://console.aws.amazon.com/cloudwatch/home?#dashboards:name=SIEM)

### CloudWatch Metrics

ログを正規化して OpenSearch Service にデータを送信する es-loader のメトリクスを、CloudWatch Metrics で確認できます。

* カスタム名前空間: SIEM
* ディメンション: logtype

|メトリクス|単位|説明|
|------|-------|-----|
|InputLogFileSize|Bytes|es-loader が S3 バケットから取り込んだファイルサイズ|
|OutputDataSize|Bytes|es-loader が OpenSearch Service に送信したデータサイズ|
|SuccessLogLoadCount|Count|es-loader が OpenSearch Service へのデータ送信が成功したログ数|
|ErrorLogLoadCount|Count|es-loader が OpenSearch Service へのデータ送信が失敗したログ数|
|TotalDurationTime|Milliseconds|es-loader が処理を始めてから全ての処理が完了するまでの時間。Lambda Durationとほぼ同じ|
|EsResponseTime|Milliseconds|es-loader が OpenSearch Service にデータを送信して処理が完了するまでの時間|
|TotalLogFileCount|Count|es-loader が 処理をしたログファイルの数|
|TotalLogCount|Count|ログファイルに含まれるログから処理対象となったログの数。フィルターをして取り込まれなかったログも含む|

### CloudWatch Logs

SIEM で利用している Lambda 関数のログを CloudWatch Logs で確認できます。
es-loader のログは JSON 形式で出力しているため、CloudWatch Logs Insights でフィルターをして検索できます。

|フィールド|説明|
|-----|------|
|level|ログの重要度。デフォルトでは info 以上を記録しています。トラブル時に aes-siem-es-loader の環境変数 の LOG_LEVEL を debug に変更に変更することで、debug のログを一時的に記録することができます。大量にログが出るので確認が終わったら info に戻すことをおすすめします|
|s3_key|S3 バケットに保存されているログファイルの オブジェクトキー です。対象ログファイルを処理した場合には s3_key を検索キーにして、処理一連のログと上記のメトリクスの生データを抽出して確認できます|
|message|ログのメッセージ。場合によっては JSON 形式|

その他のフィールドは、AWS Lambda Powertools Python を使用しています。詳細は、[AWS Lambda Powertools Python のドキュメント](https://awslabs.github.io/aws-lambda-powertools-python/core/metrics/)を参照してください。

## CloudFormation テンプレートの作成

クイックスタートでデプロイされた方は CloudFormation テンプレートの作成はスキップしてください。

### 1. 準備

AWS CloudShell または Amazon Linux 2 を実行している Amazon Elastic Compute Cloud (Amazon EC2) インスタンスを使って CloudFormation テンプレートを作成します

前提の環境)

* AWS CloudShell または Amazon Linux 2 on Amazon EC2
  * "Development Tools"
  * Python 3.8
  * Python 3.8 libraries and header files
  * Git

上記がインストールされてない場合は以下を実行

```shell
sudo yum groups mark install -y "Development Tools"
sudo yum install -y amazon-linux-extras
sudo amazon-linux-extras enable python3.8
sudo yum install -y python38 python38-devel git jq
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
```

### 2. SIEM on OpenSearch Service の clone

GitHub レポジトリからコードを clone します

```shell
cd
git clone https://github.com/aws-samples/siem-on-amazon-opensearch-service.git
```

### 3. 環境変数の設定

```shell
export TEMPLATE_OUTPUT_BUCKET=<YOUR_TEMPLATE_OUTPUT_BUCKET> # Name for the S3 bucket where the template will be located
export AWS_REGION=<AWS_REGION> # region where the distributable is deployed
```

> **_注)_** $TEMPLATE_OUTPUT_BUCKET は S3 バケット名です。事前に作成してください。デプロイ用のファイルの配布に使用します。ファイルはパブリックからアクセスできる必要があります。テンプレート作成時に使用する build-s3-dist.sh は S3 バケットの作成をしません。

### 4. AWS Lambda 関数のパッケージングとテンプレートの作成

```shell
cd ~/siem-on-amazon-opensearch-service/deployment/cdk-solution-helper/
chmod +x ./step1-build-lambda-pkg.sh && ./step1-build-lambda-pkg.sh && cd ..
chmod +x ./build-s3-dist.sh && ./build-s3-dist.sh $TEMPLATE_OUTPUT_BUCKET
```

### 5. Amazon S3 バケットへのアップロード

```shell
aws s3 cp ./global-s3-assets s3://$TEMPLATE_OUTPUT_BUCKET/ --recursive --acl bucket-owner-full-control
aws s3 cp ./regional-s3-assets s3://$TEMPLATE_OUTPUT_BUCKET/ --recursive --acl bucket-owner-full-control
```

> **注)** コマンドを実行するために S3 バケットへファイルをアップロードする権限を付与し、アップロードしたファイルに適切なアクセスポリシーを設定してください。

### 6. SIEM on OpenSearch Service のデプロイ

コピーしたテンプレートは、`https://s3.amazonaws.com/$TEMPLATE_OUTPUT_BUCKET/siem-on-amazon-opensearch-service.template` にあります。このテンプレートを AWS CloudFormation に指定してデプロイしてください。

[READMEに戻る](../README_ja.md)
