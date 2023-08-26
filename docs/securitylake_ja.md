# Amazon Security Lake との統合

[In English](securitylake.md) | [READMEに戻る](../README_ja.md)

![Security Lake Architecture](images/securitylake-arch.svg)

Amazon Security Lake のデータをそのまま SIEM on OpenSearch に取り込むことができます。

## ログの取り込み

### SIEM on OpenSearch Service のデプロイ

[README](../README_ja.md) を参照して SIEM on OpenSearch をデプロイしてください。

アカウントは、Amazon Security Lake と同じアカウントででも異なるアカウントでも可能ですが、推奨は Security Lake と異なるアカウントです。

リージョンは、Security Lake を有効化したリージョンと同じである必要があります。

CDK / CloudFormation 実行時の Security Lake 関連のパラメーターは無視してください。

### Security Lake の有効化と設定

1. AWS Organizations を利用の場合は delegated administrator を設定します (オプション) [Doc](https://docs.aws.amazon.com/security-lake/latest/userguide/multi-account-management.html)
1. Security Lake を有効化します。[Doc](https://docs.aws.amazon.com/security-lake/latest/userguide/getting-started.html)
1. 複数リージョンを監視する場合は集約の設定をします。(オプション) [Doc](https://docs.aws.amazon.com/security-lake/latest/userguide/manage-regions.html)
1. SIEM on OpenSearch をデプロイするリージョンでサブスクライバーを設定します。[Doc](https://docs.aws.amazon.com/security-lake/latest/userguide/subscriber-management.html)
    * ログとイベントソース
        * `すべてのログとイベントのソース` を選択します。または、取り込みたいカスタムログソースが `特定のログとイベントのソース` で選択されていることを確認します。
    * データアクセス方法: `S3`
    * サブスクライバーの認証情報
        * アカウント ID: `SIEMをデプロイしたAWSアカウント`
        * 外部 ID: (任意の文字列)
1. **【必須】** 作成されたサブスクライバーの SQS の変更
    * 対象の SQS: AmazonSecurityLake-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX-Main-Queue
    * 可視性タイムアウトを 5 分から `10 分に変更`

作成されたサブスクライバーを確認してください。

|リソース種別|リソース ARN|
|------|----------|
|サブスクリプションエンドポイント|arn:aws:sqs:ap-northeast-1:888888888888:AmazonSecurityLake-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX-Main-Queue|
|AWS ロール ID|arn:aws:iam::888888888888:role/AmazonSecurityLake-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX|
|外部 ID|(任意の文字列)|

次のステップの CloudFormation のパラメーターに使用します。

### SIEM アカウント

CloudFormation の aes-siem または siem スタックをアップデートして、Security Lake 関連のパラメーターを入力してください。

Security Lake Integration パラメータ例

|Parameter|入力値|
|------|----------|
|SecurityLakeSubscriberSqs|arn:aws:sqs:ap-northeast-1:888888888888:AmazonSecurityLake-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX-Main-Queue|
|SecurityLakeRoleArn|arn:aws:iam::888888888888:role/AmazonSecurityLake-XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX|
|SecurityLakeExternalId|(設定済み外部 ID の文字列)|

設定直後はログの取り込み失敗になる可能性がありますが、新しい Lambda 関数 (es-loader) のインスタンスが作成されると、取り込みが成功します。または、手動で es-loader を deploy し、強制的に新しいインスタンスを起動させることでエラーが解消します。

以上で Security Lake のログ取り込み設定は完了です

### カスタムソース

Security Lake の S3 バケットに [カスタムソースからデータを配置](https://docs.aws.amazon.com/ja_jp/security-lake/latest/userguide/custom-sources.html)できます。SIEM on OpenSearch で取り込むことはできますが、想定しているファイル名と一致しない場合は、user.ini に追加の設定が必要です

* 想定しているファイル名: `[0-9a-f]{32}\.gz\.parquet`
* 想定しているディレクトリ名: `[Ss]ecurity[Ll]ake/`

もし、どちらにも一致しない場合は user.ini に以下のような設定をしてください

user.ini

```ini
[securitylake]
s3_key = [0-9a-f]{32}\.gz\.parquet|[Ss]ecurity[Ll]ake/|parquetのファイル名
```

または

```ini
[securitylake]
s3_key = [0-9a-f]{32}\.gz\.parquet|[Ss]ecurity[Ll]ake/|S3パスに付与されるサービス名
```

既存の s3_key のパラメータを残すように設定してください。差分の設定は継承されるので、s3_key 以外で変更が不要であれば転記は不要です
