# SIEM on Amazon ES の設定変更

[In English](configure_siem.md) | [READMEに戻る](../README_ja.md)

## 目次

* [ログ取り込み方法のカスタマイズ](#ログ取り込み方法のカスタマイズ)
* [ログ取り込みの除外設定](#ログ取り込みの除外設定)
* [Amazon ES の設定変更](#Amazon-ES-の設定変更-上級者向け)
* [AWS サービス以外のログの取り込み](#AWS-サービス以外のログの取り込み)
* [S3 バケットに保存された過去データの取り込み](#S3-バケットに保存された過去データの取り込み)
* [モニタリング](#モニタリング)

## ログ取り込み方法のカスタマイズ

SIEM on Amazon ES へのログの取り込みをカスタマイズできます。S3 バケットにエクスポートされたログを、Lambda 関数の es-loader が正規化して SIEM on Amazon ES にロードしています。デプロイされた Lambda 関数名は aes-siem-es-loader となります。この Lambda 関数 es-loader は、S3 バケットから「すべてのオブジェクト作成イベント」のイベント通知を受け取って、起動します。S3 バケットに保存されたファイル名やファイルパスから、ログの種類を特定して、ログ種類毎に定義された方法でフィールドを抽出し、[Elastic Common Schema](https://www.elastic.co/guide/en/ecs/current/index.html) へマッピングをして、最後に SIEM on Amazon ES へインデックス名を指定してロードします。

このプロセスは設定ファイル (aws.ini) に定義された初期値に基づいています。任意の値に変えることもできます。例えば、あるログの S3 バケットへのエクスポートは初期値とは違うファイルパスにしたり、インデックス名の変更をしたり、インデックスのローテーション間隔を変更する場合等です。変更は、aws.ini を参考に user.ini を作成して項目と値を定義します。user.ini に設定した値は aws.ini よりも優先度が高く設定されており、初期値の値を内部で上書きします。

user.ini の保存は、Lambda レイヤーによる追加(推奨)か、AWS マネジメントコンソールから直接編集をしてください。SIEM on Amazon ES をアップデートすると、Lambda 関数が新しい関数に入れ替わります。Lambda レイヤーであれば独立しているので user.ini は維持されますが、AWS マネジメントコンソールから直接編集した user.ini は削除されるので、再度 user.ini を作成する必要があります。

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

設定完了です。SIEM on Amazon ES をアップデートすると Lambda 関数 の es-loader が入れ替わり user.ini は削除されるので、再度同じことをしてください。

## ログ取り込みの除外設定

S3 バケットに保存されたログは自動的に Amazon ES に取り込まれますが、条件を指定することで取り込みの除外をすることができます。これによって Amazon ES のリソースを節約できます。

設定できる条件は以下の2つです

1. S3 バケットの保存パス(オブジェクトキー)
1. ログのフィールドと値

### S3 バケットのファイルパス(オブジェクトキー) による除外

CloudTrail や VPC Flow Logs を S3 バケットに出力すると、AWS アカウント ID やリージョン情報が付与されます。これらの情報を元にログの取り込みを除外します。例えば検証環境の AWS アカウントのログを取り込まない等の設定をすることができます。

#### 設定方法

user.ini (aws.ini) の s3_key_ignored に除外したいログの文字列を指定。この文字列が**含まれている**とログは取り込まれません。文字列には正規表現が指定できます。文字列が短すぎたり一般的な文字だと、除外したくないログにもマッチしてしまう可能性があるのでご注意ください。また、AWS リソースのログにはデフォルトで s3_key_ignored が指定されているログがあるので、aws.ini を確認して上書き設定で消さないようにしてください。

##### 例1) VPC Flow Logs で AWS アカウント 123456789012 を除外する。単純な条件なので文字列を指定する

S3 バケットに保存されたログ: s3://aes-siem-123456789012-log/AWSLogs/**000000000000**/vpcflowlogs/ap-northeast-1/2020/12/25/000000000000_vpcflowlogs_ap-northeast-1_fl-1234xxxxyyyyzzzzz_20201225T0000Z_1dba0383.log.gz

設定ファイル user.ini

```ini
[vpcflowlogs]
s3_key_ignored = 000000000000
```

##### 例2) vpcflowlogs の AWS アカウント 111111111111 と 222222222222 を除外する。文字列が複数あるので正規表現で指定

```ini
[vpcflowlogs]
s3_key_ignored = (111111111111|222222222222)
```

### ログのフィールドと値による除外

個々のログのフィールドとその値を条件にして除外できます。例えば、VPC Flow Logs で特定の送信元 IP アドレスからの通信を除外する等です。

設定方法)

GeoIP を保存している S3 バケット(デフォルトではaes-siem-1234567890-**geo**)に、除外条件を指定した CSV ファイルをアップロード。アップロード先はプレフィックスなしのルートパス。

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
vpcflowlogs,srcaddr,192\.0\.2\.10[0-9],regex,sample2
cloudtrail,userIdentity.invokedBy,.*\.amazonaws\.com,regex,sample3
```

##### sample1

VPC Flow Logs で、送信元 IP アドレス(srcaddr) が 192.0.2.10 と一致する時は除外。pattern_type を text とした場合の条件はテキスト形式で完全一致。192.0.2.100 などが誤って除外されることを防ぐためです。フィールド名は、source.ip等の正規化後のフィールド名を指定してもマッチせず除外されません。

##### sample2

VPC Flow Logs で、送信元 IP アドレス(srcaddr) が 192.0.2.10 の文字列を含んだ IP アドレスを除外。正規表現で指定したことにより、192.0.2.100 も除外される。pattern_type を regex とした場合は、正規表現として意味のある文字列(ドット等)はエスケープしてください。

##### sample3

CloudTrail で、{'userIdentity': {'invokedBy': '*.amazonaws.com'}} と一致した場合に除外する。フィールド名が入れ子になっているので、CSVではドット区切りで指定。この例は、Config や ログ配信などのAWS のサービスがリクエストしたAPI Callのログを取り込まない。

## Amazon ES の設定変更 (上級者向け)

SIEM に関する Amazon ES のアプリケーションの設定を変更できます。設定は以下のような項目がありインデックス毎に定義できます。

* インデックスのレプリカ数、シャード数
* フィールドのマッピング、タイプ指定
* Index State Management による UltraWarm へのインデックスの自動移行や削除

設定は自由にできますが、SIEM on Amazon ES としてすでに設定している項目があります。設定値は Dev Tools から以下のコマンドで確認可能です。

```http
GET 対象のindex名/_settings
GET 対象のindex名/_mapping
```

設定を追加・変更する場合にはインデックステンプレートを作成して値を保存します。テンプレート名はすでに使われているテンプレートは避けてください。

SIEM on Amazon ES のテンプレートの予約名

* log[-aws][-サービス名]_aws
* log[-aws][-サービス名]_rollover

すでに設定された値を変更する時は、上書きするために order を 1 以上にしてください。

設定例

* Dev Tools から CloudTrail のインデックス (log-aws-cloudtrail-*) のシャード数をデフォルトの 3 から 2 に減らす

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

## AWS サービス以外のログの取り込み

AWS 以外のログをログ用 S3 バケットにエクスポートすることで SIEM on Amazon ES に取り込むことができます。ファイルフォーマットはテキスト形式、JSON 形式、CSV 形式に対応しています。テキスト形式は1行ログを取り込むことができますが、複数行ログには対応していません。S3 へのエクスポートは Logstash や Fluentd のプラグインを使う方法があります。

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

1. イベントの発生日時を SIEM on Amazon ES に伝えるためにtimestamp を指定する。フォーマットが iso8601 以外なら [Dateフォーマット](https://docs.python.org/ja/3/library/datetime.html#strftime-and-strptime-format-codes) も定義

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

## S3 バケットに保存された過去データの取り込み

S3 バケットに保存されているログをバッチで Amazon ES に取り込みます。通常は S3 バケットに保存された時にリアルタイムで取り込みます。しかし、バックアップをしていたデータを可視化やインシデント調査のために後から取り込む、または、リアルタイムで取り込みを失敗したデータが、保存されている SQS のデッドレターキューから取り込みをリトライする時に利用できます。

### 環境準備

#### スクリプト(es-loader)実行環境の準備

1. Amazon ES へ通信ができる VPC 内に Amazon Linux 2 で EC2 インスタンスをプロビジョニング
1. Amazon Linux からインターネット上の GitHub と PyPI サイト へ HTTP 通信を許可
1. EC2 に IAM ロールの [**aes-siem-es-loader-for-ec2**] をアタッチ
1. Amazon Linux のターミナルに接続して、[README](../README_ja.md) の説明にある [2. CloudFormation テンプレートの作成] の [2-1. 準備] と [2-2. SIEM on Amazon ES の clone] の手順を実施
1. 下記のコマンドで Python のモジュールをインストールする

    ```python
    cd siem-on-amazon-elasticsearch/source/lambda/es_loader/
    pip3 install -r requirements.txt -U -t .
    ```

#### 環境変数の設定

1. AWS マネジメントコンソールの Lambda コンソールに移動
1. aes-siem-es-loader 関数に移動して以下の 2 つの環境変数名と値をメモをする
    * ES_ENDPOINT
    * GEOIP_BUCKET
1. EC2 インスタンスの Amazon Linux のターミナルに貼り付ける

    環境変数の設定コマンド例。値は環境に合わせて変更してください

    ```sh
    export ES_ENDPOINT=search-aes-siem-XXXXXXXXXXXXXXXXXXXXXXXXXX.ap-northeast-1.es.amazonaws.com
    export GEOIP_BUCKET=aes-siem-123456789012-geo
    ```

### S3 バケットのオブジェクトリストからの取り込み

es-loader

```sh
cd
cd siem-on-amazon-elasticsearch/source/lambda/es_loader/
```

S3 バケットからオブジェクトリスト(s3-list.txt)を作成する

```sh
export AWS_ACCOUNT=123456789012   # お使いのAWSアカウントに置換してください
export LOG_BUCKET=aes-siem-${AWS_ACCOUNT}-log
aws s3 ls ${LOG_BUCKET} --recursive > s3-list.txt
```

必要に応じて、取り込む対象を限定したリストを作成する

例) 2021 年の CloudTrail のログだけのリストを作成する

```bash
grep CloudTrail s3-list.txt |grep /2021/ > s3-cloudtrail-2021-list.txt
```

作成した S3 リストのオブジェクトを es-loader にログを流し込む

```sh
# 対象の S3 バケットにある全てのオブジェクトを流し込む
./index.py -b ${LOG_BUCKET} -l s3-list.txt
# 抽出したオブジェクトを流し込む例
# ./index.py -b ${LOG_BUCKET} -l s3-cloudtrail-2021-list.txt
```

成功したオブジェクトリスト: s3のリストファイル名.finish.log
失敗したオブジェクトリスト: s3のリストファイル名.error.log
失敗したオブジェクトのデバッグログ: s3のリストファイル名.error_debug.log

失敗したオブジェクトリストは、上記コマンドにリストとして再指定することで失敗したログだけの取り込みができます。

例)

```sh
./index.py -b ${LOG_BUCKET} -l s3-list.error.txt
```

### SQS のキューからの取り込み

SQS の SIEM 用のデッドレターキュー (aes-siem-dlq) からログを取り込みます。(実体は S3 バケット上のログ)

リージョンを指定してから es-loader を実行

```sh
export AWS_DEFAULT_REGION=ap-northeast-1
cd
cd siem-on-amazon-elasticsearch/source/lambda/es_loader/
./index.py -q aes-siem-dlq
```

## モニタリング

### メトリクス

ログを正規化して Amazon ES にデータを送信する es-loader のメトリクスを、CloudWatch Metrics で確認できます。

* カスタム名前空間: SIEM
* ディメンション: logtype

|メトリクス|単位|説明|
|------|-------|-----|
|InputLogFileSize|Bytes|es-loader が S3 バケットから取り込んだファイルサイズ|
|OutputDataSize|Bytes|es-loader が Amazon ES に送信したデータサイズ|
|SuccessLogLoadCount|Count|es-loader が Amazon ES へのデータ送信が成功したログ数|
|ErrorLogLoadCount|Count|es-loader が Amazon ES へのデータ送信が失敗したログ数|
|TotalDurationTime|Milliseconds|es-loader が処理を始めてから全ての処理が完了するまでの時間。Lambda Durationとほぼ同じ|
|EsResponseTime|Seconds|es-loader が Amazon ES にデータを送信して処理が完了するまでの時間|
|TotalLogFileCount|Count|es-loader が 処理をしたログファイルの数|
|TotalLogCount|Count|ログファイルに含まれるログから処理対象となったログの数。フィルターをして取り込まれなかったログも含む|

### ロギング

SIEM で利用している Lambda 関数のログを CloudWatch Logs で確認できます。
es-loader のログは JSON 形式で出力しているため、CloudWatch Logs Insights でフィルターをして検索できます。

|フィールド|説明|
|-----|------|
|level|ログの重要度。デフォルトでは info 以上を記録しています。トラブル時に aes-siem-es-loader の環境変数 の LOG_LEVEL を debug に変更に変更することで、debug のログを一時的に記録することができます。大量にログが出るので確認が終わったら info に戻すことをおすすめします|
|s3_key|S3 バケットに保存されているログファイルの オブジェクトキー です。対象ログファイルを処理した場合には s3_key を検索キーにして、処理一連のログと上記のメトリクスの生データを抽出して確認できます|
|message|ログのメッセージ。場合によっては JSON 形式|

その他のフィールドは、AWS Lambda Powertools Python を使用しています。詳細は、[AWS Lambda Powertools Python のドキュメント](https://awslabs.github.io/aws-lambda-powertools-python/core/metrics/)を参照してください。

[READMEに戻る](../README_ja.md)
