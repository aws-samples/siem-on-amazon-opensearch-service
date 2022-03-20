# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.6.2-beta.3'
__license__ = 'MIT-0'
__author__ = 'Ryotaro Tsuzuki'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import json
import os

import boto3

ES_LOADER_FUNCTION_ARN = os.environ['ES_LOADER_FUNCTION_ARN']
AES_SIEM_ALERT_TOPIC_ARN = os.environ['AES_SIEM_ALERT_TOPIC_ARN']
DOCS_URL = ('https://github.com/aws-samples/siem-on-amazon-opensearch-service/'
            'blob/main/README.md#throttling-of-es-loader-in-an-emergency')

lambda_client = boto3.client('lambda')
sns = boto3.client('sns')


def lambda_handler(event, context):
    print(f'Event: {json.dumps(event)}')
    try:
        res = lambda_client.put_function_concurrency(
            FunctionName=ES_LOADER_FUNCTION_ARN,
            ReservedConcurrentExecutions=0
        )
        if res['ReservedConcurrentExecutions'] != 0:
            raise Exception('The reserved concurrency is not zero.')
    except Exception as err:
        raise Exception(f'Failed to throttle es-loader: {err}') from err
    else:
        print('Successfully stopped future invocations of es-loader.\n'
              'If you want to unthrottle es-loader again, you can manually '
              'increase the reserved concurrency for es-loader.')

        # send notification
        try:
            aws_account_id = context.invoked_function_arn.split(":")[4]
            sns.publish(
                TopicArn=AES_SIEM_ALERT_TOPIC_ARN,
                Subject=('[SIEM on OpenSearch Service] '
                         'es-loader has been throttled.'),
                Message=('The aes-siem-es-loader has been throttled '
                         'by es-loader-stopper.\n'
                         f'To learn more, see {DOCS_URL}\n\n'
                         f'AWS Account ID: {aws_account_id}\n'
                         f'Region: {os.environ["AWS_REGION"]}\n'
                         f'Event: {json.dumps(event)}')
            )
        except Exception as err:
            print(f'Failed to send notification: {err}')
