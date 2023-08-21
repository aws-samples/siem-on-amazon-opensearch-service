# AWS Control Tower との統合
<!-- markdownlint-disable-file MD033 -->

[In English](controltower.md) | [READMEに戻る](../README_ja.md)

![Control Tower Architecture](images/controltower-arch-log.svg)

AWS Control Tower の Log Archive アカウントにあるログバケットのデータをそのまま SIEM on OpenSearch に取り込むことができます。デフォルトで作成される AWS CloudTrail と AWS Config 用の S3 バケットのデータ、及び、独自に作成した S3 バケットのデータも対応しているフォーマットであれば取り込めます。

次にシングルサインオンを OpenSearch Service に対して実現します

## 目次

1. [ログの取り込み](#ログの取り込み)
    * [SIEM on OpenSearch Service のデプロイ](#siem-on-opensearch-service-のデプロイ)
    * [Log Archive アカウントでの準備](#log-archive-アカウントでの準備)
    * [管理者アカウントでの準備 (オプション)](#管理者アカウントでの準備-オプション)
    * [SIEM アカウントでの準備](#siem-アカウントでの準備)
1. [SAML 認証](#saml-認証)
    * [AWS IAM Identity Center でアプリケーションの割り当て](#aws-iam-identity-center-でアプリケーションの割り当て)
    * [Amazon OpenSearch Service の SAML 認証設定](#amazon-opensearch-service-の-saml-認証設定)
    * [Amazon OpenSearch Serverless の SAML 認証設定](#amazon-opensearch-serverless-の-saml-認証設定)
    * [AWS IAM Identity Center の SAML 認証設定](#aws-iam-identity-center-の-saml-認証設定)
    * [Amazon OpenSearch Service へ一般ユーザーグループの追加](#amazon-opensearch-service-へ一般ユーザーグループの追加)
    * [Amazon OpenSearch Serverless へ一般ユーザーグループの追加](#amazon-opensearch-serverless-へ一般ユーザーグループの追加)
    * [IAM Identity Center に一般ユーザーグループの追加](#iam-identity-center-に一般ユーザーグループの追加)

## ログの取り込み

### SIEM on OpenSearch Service のデプロイ

[README](../README_ja.md) を参照して SIEM on OpenSearch をデプロイしてください。

アカウントは、メンバーアカウントに Security Tooling アカウントを作成するか(推奨)、Audit アカウント等を活用してください。

リージョンは、Control Tower と統合するためには、Log Archive アカウントのログバケットがあるリージョンを選択してください。

CDK / CloudFormation の初期実行時では Control Tower 関連のパラメーターは無視してください。

デプロイ後に Lambda 関数の aes-siem-es-loader で使われている IAM Role の ARN を確認してください。

例) `arn:aws:iam::123456789012:role/aes-siem-LambdaEsLoaderServiceRoleXXXXXXXX-XXXXXXXXXXXX`

次のステップの CloudFormation のパラメーターに使用します。

### Log Archive アカウントでの準備

Log Archive アカウントで Amazon SQS と IAM Role を作成します。下記の CloudFormation Template を利用して作成してください。CDK / CloudFormation のパラメーターに上記 es-loader の IAM Role の ARN が必要です。CDK / CloudFormation によりリソースは新規に作成され、既存のリソースを変更することはありません。

[![core resource](./images/cloudformation-launch-stack-button.png)](https://console.aws.amazon.com/cloudformation/home#/stacks/create/template?stackName=siem-integration-with-control-tower&templateURL=https://aes-siem.s3.ap-northeast-1.amazonaws.com/log-exporter/siem-integration-with-control-tower.template) [Direct Link](https://aes-siem.s3.ap-northeast-1.amazonaws.com/log-exporter/siem-integration-with-control-tower.template)

作成されるリソース例

|タイプ|リソース ARN|
|------|----------|
|AWS::IAM::Role|arn:aws:iam::999999999999:role/ct-role-for-siem|
|AWS::SQS::Queue|arn:aws:sqs:ap-northeast-1:999999999999:aes-siem-ct|
|AWS::SQS::Queue|arn:aws:sqs:ap-northeast-1:999999999999:aes-siem-ct-dlq|

次に、ログを取り込みたい S3 バケットにイベント通知を設定します。

* 対象の S3 バケット例
  * aws-controltower-logs-999999999999-ap-northeast-1
  * aws-controltower-s3-access-logs-999999999999-ap-northeast-1
* イベントタイプ: すべてのオブジェクト作成イベント ( s3:ObjectCreated:* )
* 送信先: SQS の aes-siem-ct

以上で、Log Archive アカウントでの設定は完了です。

次のステップで必要な情報をメモします。SIEM の CloudFormation Stack のパラメーターに使います。

例)

* ログを取り込みたい S3 バケット名: `aws-controltower-logs-999999999999-ap-northeast-1, aws-controltower-s3-access-logs-999999999999-ap-northeast-1`
* SQS ARN: `arn:aws:sqs:ap-northeast-1:999999999999:aes-siem-ct`
* IAM Role: `arn:aws:iam::999999999999:role/ct-role-for-siem`

### 管理者アカウントでの準備 (オプション)

ログバケットを暗号化している場合は手動で管理者アカウントの KMS のキーポリシーをアップデートしてください。

許可するプリンシパルは **Log Archie アカウント**になります。SIEM のアカウントではありません。

設定例)

```json
{
    "Effect": "Allow",
    "Principal": {
        "AWS": "arn:aws:iam::999999999999:role/ct-role-for-siem"
    },
    "Action": "kms:Decrypt",
    "Resource": "*"
},
```

参考: [AWS KMS keysの設定 (任意)](https://docs.aws.amazon.com/ja_jp/controltower/latest/userguide/configure-kms-keys.html#kms-key-policy-update)

### SIEM アカウントでの準備

CloudFormation の aes-siem または siem スタックをアップデートして、Control Tower 関連のパラメーターを入力してください。

Control Tower Integration パラメータ例

|Parameter|入力値|
|------|----------|
|ControlTowerLogBucketNameList|aws-controltower-logs-999999999999-ap-northeast-1, aws-controltower-s3-access-logs-999999999999-ap-northeast-1|
|ControlTowerSqsForLogBuckets|arn:aws:sqs:ap-northeast-1:999999999999:aes-siem-ct|
|ControlTowerRoleArnForEsLoader|arn:aws:iam::999999999999:role/ct-role-for-siem|

設定直後はログの取り込みが失敗する可能性がありますが、Lambda 関数 (es-loader) の新しいインスタンスが作成されると、取り込みが成功します。または、手動で es-loader を deploy し、強制的に新しいインスタンスを起動させることでエラーが解消します。

以上で Log Archive アカウントのログ取り込み設定は完了です

## SAML 認証

Control Tower の AWS IAM Identity Center を利用して、シングルサインオンで OpenSearch へアクセスするユーザーを制御することができます。ユーザーは、ポータルにログインすると、ワンクリックで OpenSearch にログインすることができます。このプロセスは、アイデンティティソースは、Identity Center ディレクトリを使うことを前提としています。他のソースを使っている場合は、適宜変更をしてください。

以下の IAM Identity Center のグループに属しているユーザーが、OpenSearch の Role でシングルサインオンができるようにします。権限は適宜変更してください

**OpenSearch Service の場合**

|IAM Identity Center Group|OpenSearch Role|説明|
|---|---|----|
|OpenSearchDashboardsSuperUsers|security_manager<br>all_access|全権限を所有|
|OpenSearchDashboardsAdmins|all_access|セキュリティ以外の全権限を所有|
|OpenSearchDashboardsReadOnlyUsers|opensearch_dashboards_user<br>readall_and_monitor|Indexに対して読み込み権限のみ所有|

**OpenSearch Serverless の場合**

|IAM Identity Center Group|OpenSearch Serverless のデータアクセス|説明|
|---|---|----|
|OpenSearchDashboardsSuperUsers|コレクションアクセス許可<br>aoss:\*<br>インデックスアクセス許可<br>aoss:\*|全権限を所有|
|OpenSearchDashboardsAdmins|インデックスアクセス許可<br>aoss:*|indexに対する読み書き権限を所有|
|OpenSearchDashboardsReadOnlyUsers|インデックスアクセス許可<br>aoss:ReadDocument<br>aoss:DescribeIndex|Indexに対して読み込み権限のみ所有|

設定は、IAM Identity Center と Amazon OpenSearch Service のアカウントを交互に設定するため、別々のブラウザで 2 つの AWS アカウントにログインした状態で行うことをおすすめします。

1. 1つ目のブラウザで Control Tower 管理者アカウントの [AWS IAM Identity Centr のコンソール](https://console.aws.amazon.com/singlesignon) を開きます
1. 上記の IAM Identity Center のグループを作成して、それぞれのグループ ID をメモしてください

### AWS IAM Identity Center でアプリケーションの割り当て

OpenSearch Service または OpenSearch Serverless をアプリケーションに割り当てます。

1. 1つ目のブラウザで Control Tower 管理者アカウントの [AWS IAM Identity Centr のコンソール](https://console.aws.amazon.com/singlesignon) を開きます
1. 画面左側のナビゲーションペインで **[アプリケーション]** を選択します
1. **[アプリケーションの追加]** を選択します
1. [アプリケーションを選択] ページで、**[カスタム SAML 2.0 アプリケーションの追加]** を選択します。次に、[次へ] を選択します
1. [アプリケーションを設定] ページの [表示名] に、**[SIEM Dashboards]** と入力します。[説明] 項目は任意です
1. [IAM Identity Center SAML メタデータファイル] の **[ダウンロード]** を選択して、メタデータをダウンロードしてください。ファイル名の例は `Custom SAML 2.0 application_ins-abcdef1234567890.xml` となります

この状態で、2つ目のブラウザから OpenSearch の SAML 認証設定をします

参考: [カスタム SAML 2.0 アプリケーション](https://docs.aws.amazon.com/ja_jp/singlesignon/latest/userguide/samlapps.html)

### Amazon OpenSearch Service の SAML 認証設定

OpenSearch Service のマネージドインスタンスを使用している場合の設定です。OpenSearch Serverless を使用してる場合はこのセクションはスキップして下さい。

1. 2つ目のブラウザで SIEM アカウントの [Amazon OpenSearch Service のコンソール](https://console.aws.amazon.com/singlesignon) を開きます
1. 画面左側のナビゲーションペインで **[ドメイン]**、**[aes-siem]** の順に選択します。ドメイン名を変更している場合は、ご自身で設定したドメイン名を選択
1. 画面右上の **[アクション]**、**[セキュリティの設定の編集]** の順に選択
1. [OpenSearch Dashboards/Kibana 用の SAML 認証] パネルで、**[SAML 認証を有効化]** にチェックを入れます
1. [IdP からのメタデータ] の **[XML ファイルからインポート]** を選択して、IAM Identity Center からダウンロードした XML ファイルをアップロードします。ファイル名の例は `Custom SAML 2.0 application_ins-abcdef1234567890.xml` です。
1. [SAML マスターバックエンドロール - オプション] に IAM Identity Center の **[OpenSearchDashboardsSuperUsers の グループ ID]** を入力します。例) `abcd1234-5678-9012-3456-111111111111`
1. **[その他の設定]** を選択して詳細オプションを表示します
1. [ロールキー - オプション] に **[ Group ]** を入力します
1. [セッションの有効期間] を任意の時間に変更します
1. **[変更の保存]** を選択して、OpenSearch での設定を完了します
1. 参照用に **[アクション]**、**[セキュリティの設定の編集]** の順に選択して SAML 関連のパラメーターを表示します。次のセクションで使います。

この状態で IAM Identity Center へ戻ります

参考: [OpenSearch Dashboards の SAML 認証](https://docs.aws.amazon.com/ja_jp/opensearch-service/latest/developerguide/saml.html)

### Amazon OpenSearch Serverless の SAML 認証設定

OpenSearch Serverless のコレクションを使用している場合の設定です。OpenSearch Service のマネージドインスタンスで設定済みの場合はこのセクションはスキップして下さい。

SAML 認証

1. 2つ目のブラウザで SIEM アカウントの [Amazon OpenSearch Service のコンソール](https://console.aws.amazon.com/singlesignon) を開きます
1. 画面左側のナビゲーションペインで サーバーレスの **[SAML 認証]**、**[SAML プロバイダーを作成]** の順に選択します
1. [SAML プロバイダーを作成] 画面で名前に **[ iam-identity-center ]** と入力します
1. [ステップ 3: IdP からのメタデータを提供する] の **[XML ファイルからインポート]** を選択して、IAM Identity Center からダウンロードした XML ファイルをアップロードします。ファイル名の例は `Custom SAML 2.0 application_ins-abcdef1234567890.xml` です。
1. [グループ属性 - オプション] に **[ Group ]** と入力します
1. [OpenSearch Dashboards のタイムアウト] を任意の時間に変更します
1. **[SAML プロバイダーの作成]** を選択して、SAML 認証の設定を完了します

データアクセスポリシー

1. 画面左側のナビゲーションペインで サーバーレスの **[データアクセスポリシー]**、**[データアクセスポリシーの作成]** の順に選択します
1. [アクセスポリシーを作成] 画面でアクセスポリシー名に **[ siem-superusers ]** と入力します
1. [ルール 1] の **[プリンシパルを追加]** を選択して、**[SAML ユーザーとグループの選択]** を選択します
    1. [SAML プロバイダー名] に **[ SAML/123456789012/iam-identity-center ]** を選択します
    1. [SAML ユーザーまたはグループ] に **[ group/OpenSearchDashboardsSuperUsersのグループID ]** を入力します。例) `group/12345678-1234-5678-abcd-111111111111`
    1. **[保存]** を選択します
1. **[付与]** を選択します
    1. [エイリアスとテンプレートの許可] の **[すべて選択]**
    1. テキストボックスに **[ aes-siem ]** を入力して改行キーを入力。コレクション名は適宜変更してください。
    1. [インデックスの許可] の **[すべて選択]** を選択
    1. [コレクションを選択] に **[ aes-siem ]** を入力して改行キーを入力。コレクション名は適宜変更してください。
    1. [特定のインデックスまたはインデックスパターン] にワイルドカードの **[ * ]** を入力します
    1. **[保存]** を選択します
1. **[保存]** を選択して、アクセスポリシーの作成を終了します

参考: [Amazon OpenSearch Serverless での SAML 認証](https://docs.aws.amazon.com/ja_jp/opensearch-service/latest/developerguide/serverless-saml.html)

### AWS IAM Identity Center の SAML 認証設定

1つ目のブラウザで IAM Identity Center へ戻り、SAML 連携の残りの設定を行います。

1. [セッション期間] を任意の時間に変更します
1. [アプリケーションメタデータ] の **[メタデータ値をマニュアルで入力する]** を選択して、OpenSearch SAML連携のパラメーターを参照しながら入力します

    **OpenSearch Service の場合**

    | IAM Identity Center |<<| OpenSearch |例|
    |---------------------|--|------------|--|
    |アプリケーション ACS URL|<<|IdP によって開始された SSO URL| `https://search-aes-siem-abcd1234567890ulzml47mmaui.ap-northeast-1.es.amazonaws.com/_dashboards/_opendistro/_security/saml/acs/idpinitiated` |
    |アプリケーション SAML 対象者|<<|サービスプロバイダーエンティティ ID| `https://search-aes-siem-abcd1234567890ulzml47mmaui.ap-northeast-1.es.amazonaws.com` |

    **OpenSearch Serverless の場合**

    | IAM Identity Center |<<| OpenSearch Serverless|例|
    |---------------------|--|------------|----|
    |アプリケーション開始 URL - (オプション)|<<| OpenSearch Dashboards の URL | `https://abcdef1234567890123456.ap-northeast-1.aoss.amazonaws.com/_dashboards`|
    |アプリケーション ACS URL|<<|[SAML 認証]<br>アサーションコンシューマーサービス (ACS) の URL|`https://collection.ap-northeast-1.aoss.amazonaws.com/_saml/acs`|
    |アプリケーション SAML 対象者|<<|aws:opensearch:<OpenSearchのアカウントID>|aws:opensearch:123456789012|

1. **[送信]** を選択して、SAML の設定を完了します

次に、属性マッピングを設定します。

1. 画面右上の **[アクション]**、**[属性マッピングを編集]** の順に選択します
1. 下記の属性を入力します
    |アプリケーションのユーザー属性|この文字列値または IAM Identity Center のユーザー属性にマッピング|形式|
    |---------------------------|-------|---------|
    |Subject| **${user:subject}** |unspecified|
    |**Group**| **${user:groups}** |unspecified|
1. **[変更の保存]** を選択します。

次に、ログインを認可するグループを指定します

1. **[ユーザーを割り当て]** を選択します
1. タブメニューから **[グループ]** タブを選んで、**[OpenSearchDashboardsSuperUsers]** を選択します
1. **[ユーザーを割り当て]** を選択します

管理者ユーザーの設定は完了です。次に、一般ユーザーの設定を行います

### Amazon OpenSearch Service へ一般ユーザーグループの追加

一般ユーザーグループを OpenSearch の Fine-grained access control に設定を追加します

1. 2つ目のブラウザで、SAML 認証 を行い OpenSearch Dashboards に管理者権限でログインします
1. 画面左上のプルダウンメニューから、**[Security]**、**[Roles]** の順に選択します
1. Role の **[all_access]** を選択します。
1. タブメニューの **[Mapped users]** を選択します
1. **[Manage mapping]** を選択します
1. **[Add another backend role]** を選択します
1. IAM Identity Center の **[OpenSearchDashboardsAdmins の グループ ID]** 入力します。例) abcd1234-5678-9012-3456-222222222222
1. グループの OpenSearchDashboardsAdmins の追加が完了しました
1. グループの OpenSearchDashboardsReadOnlyUsers を追加するために、同様に下記の OpenSearch Role にIAM Identity Center のグループ ID を Map してください
    | OpenSearch Role | Backend roles |
    |-----------------|---------------------------|
    | opensearch_dashboards_user | OpenSearchDashboardsReadOnlyUsers のグループ ID |
    | readall_and_monitor | OpenSearchDashboardsReadOnlyUsers のグループ ID |

別のユーザーグループを作る場合は、この設定を繰り返してください

### Amazon OpenSearch Serverless へ一般ユーザーグループの追加

Amazon OpenSearch Serverless に OpenSearchDashboardsAdmins グループを追加します

1. 2つ目のブラウザで SIEM アカウントの [Amazon OpenSearch Service のコンソール](https://console.aws.amazon.com/singlesignon) を開きます
1. 画面左側のナビゲーションペインで サーバーレスの **[データアクセスポリシー]**、**[データアクセスポリシーの作成]** の順に選択します
1. [アクセスポリシーを作成] 画面でアクセスポリシー名に **[ siem-admins ]** と入力します
1. [ルール 1] の **[プリンシパルを追加]** を選択して、**[SAML ユーザーとグループの選択]** を選択し追加します
    1. [SAML プロバイダー名] に **[ SAML/123456789012/iam-identity-center ]** を選択します
    1. [SAML ユーザーまたはグループ] に **[ group/OpenSearchDashboardsAdminsのグループID ]** を入力します。例) `group/12345678-1234-5678-abcd-222222222222`
    1. **[保存]** を選択します
1. **[付与]** を選択します
    1. [エイリアスとテンプレートの許可] は **何も選択しません**
    1. [インデックスの許可] の **[すべて選択]** を選択
    1. [コレクションを選択] に **[ aes-siem ]** を入力してリターンを入力。コレクション名を適宜変更してください。
    1. 特定のインデックスまたはインデックスパターンにワイルドカードの **[ * ]** を入力します
    1. **[保存]** を選択します
1. **[保存]** を選択して、アクセスポリシー **[ siem-admins ]** を更新します

次に、OpenSearchDashboardsReadOnlyUsers グループを追加します

1. 画面左側のナビゲーションペインで サーバーレスの **[データアクセスポリシー]**、**[データアクセスポリシーの作成]** の順に選択します
1. [アクセスポリシーを作成] 画面でアクセスポリシー名に **[ siem-readonly-users  ]** と入力します
1. [ルール 1] の **[プリンシパルを追加]** を選択して、**[SAML ユーザーとグループの選択]** を選択します
    1. [SAML プロバイダー名] に **[ SAML/123456789012/iam-identity-center ]** を選択します
    1. [SAML ユーザーまたはグループ] に **[ group/OpenSearchDashboardsReadOnlyUsersのグループID ]** を入力します。例) `group/12345678-1234-5678-abcd-333333333333`
    1. **[保存]** を選択します
1. **[付与]** を選択します
    1. [エイリアスとテンプレートの許可] は **何も選択しません**
    1. [インデックスの許可] の **[説明]** と **[ドキュメントを読む]** を選択
    1. [コレクションを選択] に **[ aes-siem ]** を入力してリターンを入力。コレクション名を適宜変更してください。
    1. 特定のインデックスまたはインデックスパターンにワイルドカードの **[ * ]** を入力します
    1. **[保存]** を選択します
1. **[保存]** を選択して、アクセスポリシーの作成を終了します

別のユーザーグループを作る場合は、必要に応じてこの設定を繰り返してください

### IAM Identity Center に一般ユーザーグループの追加

1つ目のブラウザで IAM Identity Center へ戻り、一般ユーザーグループを追加します

1. 画面左側のナビゲーションペインで **[アプリケーション]** を選択します
1. 設定済みのアプリケーションを選択します
1. **[ユーザーを割り当て]** を選択します
1. タブメニューから **[グループ]** タブを選んで、**[OpenSearchDashboardsAdmins]** と **[OpenSearchDashboardsReadOnlyUsers]** を選択します
1. **[ユーザーを割り当て]** を選択します

以上で SAML 認証の設定が完了です
