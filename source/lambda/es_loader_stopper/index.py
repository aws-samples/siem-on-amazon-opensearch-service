# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Ryotaro Tsuzuki'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import json
import os

import boto3

ES_LOADER_FUNCTION_ARN = os.environ['ES_LOADER_FUNCTION_ARN']
ES_LOADER_RESERVED_CONCURRENCY = os.environ['ES_LOADER_RESERVED_CONCURRENCY']
AES_SIEM_ALERT_TOPIC_ARN = os.environ['AES_SIEM_ALERT_TOPIC_ARN']
DOCS_URL = ('https://github.com/aws-samples/siem-on-amazon-opensearch-service/'
            'blob/main/README.md#throttling-of-es-loader-in-an-emergency')

THROTTLE = 'THROTTLE'
UNTHROTTLE = 'UNTHROTTLE'
PASS = 'PASS'

lambda_client = boto3.client('lambda')
sns = boto3.client('sns')


def lambda_handler(event, context):
    print(f'Event: {json.dumps(event)}')
    aws_account_id = context.invoked_function_arn.split(":")[4]

    action = direct_action(event)
    if action == THROTTLE:
        throttle_es_loader()

        # send notification
        notif_subject = ('[SIEM on OpenSearch Service] '
                         'es-loader has been throttled.')
        notif_message = ('The aes-siem-es-loader has been throttled '
                         'by es-loader-stopper.\n'
                         f'To learn more, see {DOCS_URL}\n\n'
                         f'AWS Account ID: {aws_account_id}\n'
                         f'Region: {os.environ["AWS_REGION"]}\n'
                         f'Event: {json.dumps(event)}')
        send_notification(notif_subject, notif_message)
    elif action == UNTHROTTLE:
        unthrottle_es_loader()

        # send notification
        notif_subject = ('[SIEM on OpenSearch Service] '
                         'es-loader has been unthrottled.')
        notif_message = ('The aes-siem-es-loader has been unthrottled '
                         'by es-loader-stopper.\n'
                         f'To learn more, see {DOCS_URL}\n\n'
                         f'AWS Account ID: {aws_account_id}\n'
                         f'Region: {os.environ["AWS_REGION"]}\n'
                         f'Event: {json.dumps(event)}')
        send_notification(notif_subject, notif_message)
    elif action == PASS:
        print('es_loader_stopper was invoked but did nothing.')


def direct_action(event):
    # receive event and decide whether to throttle es-loader
    alarm_state = event['detail']['state']['value']

    if alarm_state == 'ALARM':
        return THROTTLE
    elif alarm_state == 'OK':
        return UNTHROTTLE
    else:
        return PASS


def throttle_es_loader():
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


def unthrottle_es_loader():
    desired_reserved_concurrency = int(ES_LOADER_RESERVED_CONCURRENCY)
    try:
        res = lambda_client.put_function_concurrency(
            FunctionName=ES_LOADER_FUNCTION_ARN,
            ReservedConcurrentExecutions=desired_reserved_concurrency
        )
        if res['ReservedConcurrentExecutions'] != desired_reserved_concurrency:
            raise Exception('The reserved concurrency is not '
                            f'{desired_reserved_concurrency}.')
    except Exception as err:
        raise Exception(f'Failed to unthrottle es-loader: {err}') from err
    else:
        print('Successfully unthrottle es-loader.')


def send_notification(subject, message):
    try:
        sns.publish(
            TopicArn=AES_SIEM_ALERT_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
    except Exception as err:
        print(f'Failed to send notification: {err}')
