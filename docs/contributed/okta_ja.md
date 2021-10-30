# es_loader による Okta のログ取り込み

以下の流れで Okta の監査ログを取り込みます。

1. Okta コンソールでログ取得用のトークンを発行
2. 発行したトークンを使い Fetch スクリプトでログ取得の API を叩く
3. API で取得したログを S3 へ出力
4. S3 へのオブジェクト配置で es-loader がキックされ OpenSearch へロード

## Okta のログを S3 へ保存

[こちら](https://github.com/yopiyama/fetch-okta-logs-lambda) の Fetch スクリプトを使用し、Okta のログ取得を行います。

### Installation

[Fetch スクリプト側の README](https://github.com/yopiyama/fetch-okta-logs-lambda/blob/master/README.md) に記載してあります。

## Template

`log-intra-audit-okta` と `log-audit-saas` の Index Pattern をコンソールなどで別途生成する必要があります。

### Component Template

```json
PUT _component_template/component_template_log-intra-audit-okta
{
  "template": {
    "mappings": {
      "properties": {
        "okta.client.ip": {
          "type": "ip"
        },
        "okta.security_context.as.number": {
          "type": "long"
        },
        "okta.security_context.as.organization.name": {
          "fields": {
          "text": {
            "type": "text"
          }
          },
          "type": "keyword"
        }
      }
    },
    "aliases":{
      "log-intra-audit-okta":{},
      "log-audit-saas": {}
    }
  }
 }
```

### Index Template

```json
PUT _index_template/log-intra-okta-audit
{
  "index_patterns": [
    "log-intra-audit-okta-*"
  ],
  "composed_of": [
    "component_template_log",
    "component_template_log-intra-audit-okta"
    ]
}
```
