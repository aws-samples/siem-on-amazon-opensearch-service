# FAQ

[View this page in Japanese (日本語)](faq_ja.md) | [Chinese (简体中文)](faq_zh-cn.md) | [Back to README](../README.md)

## What if I find a bug?

Check out the following AWS official web pages to see if the bug is already being worked on.

* [Troubleshooting Amazon OpenSearch Service](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/handling-errors.html)
* [AWS Knowledge Center](https://aws.amazon.com/premiumsupport/knowledge-center/#Amazon_OpenSearch_Service)

## I want to learn how to use Amazon OpenSearch Service or OpenSearch Dashboards

Amazon OpenSearch Service Workshop content is available for you on GitHub.

* [We have published “Amazon Elasticsearch Service Intro Workshop”!- Learn & experience the service in 2 hours -- from basic usage to the latest update](https://aws.amazon.com/jp/blogs/news/amazon-elasticsearch-service-hands-on/) (Japanese language)
* [Amazon Elasticsearch Service Intro Workshop](https://github.com/aws-samples/amazon-elasticsearch-intro-workshop/blob/master/README.md)

## Deployment doesn’t complete

There may be a time when deployment doesn’t finish even after waiting for 30 minutes or longer. This may be because something happened when creating a domain in Amazon OpenSearch Service. OpenSearch Service is deployed by AWS Lambda functions: deploy-aes and configure-aes. So you can check aes-siem-deploy-aes and aes-siem-configure-aes in CloudWatch Logs to see whether deployment is still in progress, or stopped due to an error. If you see an error, please fix it or clean up as described in README and then redeploy.

## OpenSearch Service does not load STDERR of container logs sent via Firelens

STDERR logs are not loaded by default. Add the following to user.ini if you need to load them.

```ini
ignore_container_stderr = False
```

## There is a discrepancy between the time when the log was generated and the timestamp in OpenSearch Service when STDERR of container logs is loaded via Firelens

@timestamp is based on the time when the log is loaded because STDERR has many different log formats and some log formats do not even contain a time field.

## I forgot my master user (aesadmin) password and can not login to OpenSearch Dashboards

You can set a new password with AWS Management Console.

1. Navigate to the [OpenSearch Service console](https://console.aws.amazon.com/aos/home?)
1. Select [**aes-siem**] domain
1. Select [**Actions**] at the top of screen and choose the [**Edit security configuration**] from the drop-down menu.
1. Check [**Create master user**] from [Fine-grained access control - powered by Open Distro for Elasticsearch]
1. Type [**aesadmin**] to [Master usernames] and [**any password**] to [Master password]/[Confirm master password]
1. Select [**Submit**] at the bottom right of the screen

## How can I configure the OpenSearch SIEM solution to ingest logs from a custom S3 bucket?
The OpenSearch SIEM solution is designed to ingest logs from the default S3 bucket locations. However, it is possible to configure it to ingest from other custom S3 buckets as well.
1. Identify the Lambda function responsible for loading logs from S3 to Elasticsearch - This is usually called [aes-siem-es-loader](https://github.com/aws-samples/siem-on-amazon-opensearch-service/tree/main?tab=readme-ov-file#aes-siem-es-loader)
2. Update the [S3 bucket policy to allow the Lambda execution role to access the custom bucket(s).](https://github.com/aws-samples/siem-on-amazon-opensearch-service/blob/main/docs/configure_siem.md#near-real-time-loading-from-other-s3-buckets)
3. Configure [S3 Event Notifications on the custom bucket(s) to trigger the Lambda function on new log files](https://github.com/aws-samples/siem-on-amazon-opensearch-service/blob/main/docs/configure_siem.md#amazon-s3-event-notifications).
4. Deploy the Lambda code changes. New logs in the custom buckets should now be ingested into OpenSearch.
5. Verify in the OpenSearch management console or Kibana that the custom logs are being indexed as expected.

[Back to README](../README.md)
