# よくある質問

## 不具合

AWS 公式ページに該当の不具合があるかをご確認下さい

* [Amazon Elasticsearch Service トラブルシューティング](https://docs.aws.amazon.com/ja_jp/elasticsearch-service/latest/developerguide/aes-handling-errors.html)
* [AWS ナレッジセンター](https://aws.amazon.com/jp/premiumsupport/knowledge-center/#Amazon_Elasticsearch_Service)

## Amazon Elasticsearch Service や Kibana の使用方法を学びたい

GitHub に Amazon ES の ワークショップを公開していますのでご活用下さい

* [Amazon Elasticsearch Service Intro Workshop を公開しました！- 基本的な使い方から最新アップデートまで 2 時間で体験](https://aws.amazon.com/jp/blogs/news/amazon-elasticsearch-service-hands-on/)
* [Amazon Elasticsearch Service Intro Workshop](https://github.com/aws-samples/amazon-s3-datalake-handson/blob/master/JP/README.md)

## デプロイが終わらない

30分以上待っても終わらない時があります。Amazon Elasticsearch Service(Amazon ES) のドメイン作成でなんらかの不具合が予想されます。Amazon ES のデプロイは、Lambda 関数の deploy-aes と configure-aes で行っています。CloudWatch Logs の aes-siem-deploy-aes と aes-siem-configure-aes でログを確認できますので、進行中なのか、不具合なのかを確認して下さい。不具合である場合はそれを解消するか、README に記載のクリーンアップをしてから再デプロイをしてください。

## コンテナログの stderr を Firelens で送信した場合に、Amazon ES にログが取り込まれない

stderr のログはデフォルトでは取り込まない設定にしています。取り込む時は、user.ini に下記の設定を追加してください。

```ini
ignore_container_stderr = False
```

## コンテナログの stderr を Firelens で送信して取り込んだ場合に、ログが発生した時刻と、Amazon ES 上の時刻が異なっている

stderrは様々なログフォーマットがあり、ログの中に時刻フィールドが含まれていないこともあるので、ログを取り込んだ時間を @timestamp としています

## マスターユーザー (aesadmin) のパスワードを忘れて Kibana にログインができなくなった

AWS マネジメントコンソールから新しいパスワードを設定できます。

1. [Amazon ES コンソール](https://console.aws.amazon.com/es/home?) に移動します
1. aes-siem ドメインを選択します
1. 画面上部の [**アクション**] ボタンを選択して、プルダウンメニューから [**認証を変更**] を選択します
1. [細かいアクセスコントロール - Open Distro for Elasticsearch を搭載] の [**マスターユーザー**] ラジオボックスにチェックを入れます
1. [マスターユーザー名]に [**aesadmin**]、[マスターパスワード]/[マスターパスワードの確認] に [**任意のパスワード**] を入力します
1. 画面右下の [**送信**] を選択します

## 大量にログが出力されストレージを圧迫する

AWS アカウントやログの特定フィールドと値を条件にして、Amazon ES へのログ取り込みを除外することが可能です。

※ ログ取り込みの除外をすると Amazon ES からは検索できなくなるので Athena 等で検索をして下さい。また、ログを時系列に並べても除外したフィールドが表示されないことで、ログ分析に影響が出る可能性があります。

例1) 本番環境の AWSアカウント 111111111111 と 222222222222 だけを取り込んで、開発環境等の他の AWS アカウントは取り込まない

設定ファイル: user.ini

```ini
[vpcflowlogs]
s3_key_ignored = ^(?!.*(111111111111|222222222222)).*
```

user.ini の設定方法と詳細については[「SIEM on Amazon ES の設定変更」の 「AWS Lambda レイヤーによる追加方法(推奨)」](configure_siem_ja.md#AWS-Lambda-レイヤーによる追加方法推奨)で確認できます。

例2) 大量発生する傾向のあるログの除外設定

ログの特定フィールドと値による除外をします。

設定ファイル: exclude_log_patterns.csv

```
log_type,field,pattern,pattern_type,comment
cloudtrail,eventName,GenerateDataKey|Decrypt,regex,ignore Decyrpt and GenerateDataKey of KMS API
cloudtrail,userIdentity.invokedBy,macie.amazonaws.com,text,ignore Macie scan
vpcflowlogs,log_status,NODATA,text,ignore NODATA
vpcflowlogs,subnet_id,subnet-aaaaaaaaaaaaaaaaa|subnet-bbbbbbbbbbbbbbbbb,regex,micro service works in these subnet
```

exclude_log_patterns.csv の設定方法と詳細については[「SIEM on Amazon ES の設定変更」の「ログのフィールドと値による除外」](configure_siem_ja.md#ログのフィールドと値による除外)で確認できます。

[READMEに戻る](../README_ja.md)
