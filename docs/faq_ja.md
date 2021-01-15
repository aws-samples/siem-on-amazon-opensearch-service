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
