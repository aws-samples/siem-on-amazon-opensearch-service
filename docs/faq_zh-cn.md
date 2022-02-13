# FAQ

[In English](faq.md) | [Back to README](../README_zh-cn.md)

## 如果发现bug以后，该怎么了办?

查看以下 AWS 官方网页，查看该错误是否已在处理中。

* [Troubleshooting Amazon OpenSearch Service](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/handling-errors.html)
* [AWS Knowledge Center](https://aws.amazon.com/premiumsupport/knowledge-center/#Amazon_OpenSearch_Service)

## 我想了解如何使用 Amazon OpenSearch Service 或 OpenSearch Dashboards

Amazon OpenSearch Service Workshop 内容在 GitHub 上为您提供。

* [We have published “Amazon Elasticsearch Service Intro Workshop”!- Learn & experience the service in 2 hours -- from basic usage to the latest update](https://aws.amazon.com/jp/blogs/news/amazon-elasticsearch-service-hands-on/) (Japanese language)
* [Amazon Elasticsearch Service Intro Workshop](https://github.com/aws-samples/amazon-s3-datalake-handson/tree/master/EN)

## 部署不成功

可能是由于在 Amazon OpenSearch Service 中创建域时发生了一些错误，可能导致您在等待 30 分钟或更长时间，该部署也可能没有完成。  OpenSearch 服务由 deploy-aes 和 configure-aes 两个 AWS Lambda 函数进行部署 因此，您可以在 CloudWatch Logs 中检查 aes-siem-deploy-aes 和 aes-siem-configure-aes 错误日志，以查看部署是仍在进行中，还是由于错误而导致堆栈停止。 如果您看到错误，请按照文件中的说明修复或清理，然后重新部署。

## OpenSearch 服务不会加载通过 Firelens 发送的容器日志的 STDERR

默认情况下不加载 STDERR 日志。 如果需要加载它们，请将以下内容添加到 user.ini。

```ini
ignore_container_stderr = False
```

## 通过Firelens加载容器日志的STDERR时，日志生成时间与OpenSearch服务中的时间戳存在差异

@timestamp 基于日志加载的时间，因为 STDERR 有许多不同的日志格式，有些日志格式甚至不包含时间字段。

## 我忘记了主用户 (aesadmin) 密码，无法登录 Kibana

您可以使用 AWS 管理控制台设置新密码。

1. 导航到 [OpenSearch Service 控制台](https://console.amazonaws.cn/esv3/home?)
1. 选择[**aes-siem**]域
1. 选择屏幕顶部的 [**Actions**]，然后从下拉菜单中选择 [**Modify authnication**]。
1. 从[细粒度访问控制 - 由 Open Distro for Elasticsearch 提供支持] 中勾选【**Create master User**】
1. 在[Master usernames]中输入[**aesadmin**]，在[Master password]/[Confirm master password]中输入[**any password**]
1. 选择屏幕右下方的[**Submit**]

[返回 README](../README_zhcn.md)
