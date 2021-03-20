# FAQ

[View this page in Japanese (日本語)](faq_ja.md) | [Back to README](../README.md)

## What if I find a bug?

- Check out the following AWS official web pages to see if the bug is already being worked on.

* [Amazon Elasticsearch Service Troubleshooting](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/aes-handling-errors.html)
* [AWS Knowledge Center](https://aws.amazon.com/premiumsupport/knowledge-center/#Amazon_Elasticsearch_Service)

## I want to learn how to use Amazon Elasticsearch Service or Kibana.

- Amazn ES Workshop content is available for you on GitHub.

* [We have published “Amazon Elasticsearch Service Intro Workshop”!- Learn & experience the service in 2 hours -- from basic usage to the latest update](https://aws.amazon.com/jp/blogs/news/amazon-elasticsearch-service-hands-on/) (Japanese language)
* [Amazon Elasticsearch Service Intro Workshop](https://github.com/aws-samples/amazon-s3-datalake-handson/tree/master/EN)

## Deployment doesn’t complete.

There may be a time when deployment doesn’t finish even after waiting for 30 minutes or longer. This may be because something happened when creating a domain in Amazon Elasticsearch Service (Amazon ES). Amazon ES is deployed by AWS Lambda functions: deploy-aes and configure-aes. So you can check aes-siem-deploy-aes and aes-siem-configure-aes in CloudWatch Logs to see whether deployment is still in progress, or stopped due to an error. If you see an error, please fix it or clean up as described in README and then redeploy.

## Amazon ES does not load STDERR of container logs sent via Firelens.

STDERR logs are not loaded by default. Add the following to user.ini if you need to load them.

```ini
ignore_container_stderr = False
```

## There is a discrepancy between the time when the log was generated and the timestamp in Amazon ES when STDERR of container logs is loaded via Firelens.

@timestamp is based on the time when the log is loaded because STDERR has many different log formats and some log formats do not even contain a time field.

[Back to README](../README.md)