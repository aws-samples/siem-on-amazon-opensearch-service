# SIEM on Amaozon ES の設定変更

[In English](configure_siem.md) | [READMEに戻る](../README_ja.md)

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

## SIEM on Amazon ES の設定変更 (上級者向け)

SIEM on Amazon ES のアプリケーションの設定を変更できます。設定は以下のような項目がありインデックス毎に定義できます。

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

## AWS以外のログの取り込み

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

この定義ファイルだけでは処理できない場合、Python スクリプトでカスタムロジックを入れることも可能です。例えば user-agent から OS や プラットフォームを抽出するロジックを入れるなどです。ファイル名は sf_ログの種類.py としてください。この例では、sf_apache.py となります。このファイルを es-loader の siem ディレクトリに保存するか、Lambda レイヤーの siem ディレクトリに保存してください。

Lambda レイヤーの zip 圧縮ファイルの内部は以下のディレクトリ構成にしてください

```text
|- user.ini
|- siem
    |- sf_apache.py
    |- sf_他のログ種類.py
```

zip を作成し Lambda レイヤーに登録すれば設定完了です

[READMEに戻る](../README_ja.md)
