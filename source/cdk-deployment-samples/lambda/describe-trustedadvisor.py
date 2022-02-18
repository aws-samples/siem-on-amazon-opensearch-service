# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = 'Amazon.com, Inc. or its affiliates'
__version__ = '2.6.1-beta.2'
__license__ = 'MIT-0'
__author__ = 'Katsuya Matsuoka'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import datetime
import gzip
import json
import os
import time

import boto3
import botocore.exceptions

client = boto3.Session(region_name='us-east-1').client('support')
s3_resource = boto3.resource('s3')
bucket = s3_resource.Bucket(os.environ['log_bucket_name'])
AWS_ID = str(boto3.client("sts").get_caller_identity()["Account"])
AWS_REGION = os.environ['AWS_DEFAULT_REGION']
is_enable_japanese = (
    os.environ['enable_japanese_description'] == 'Yes')

checks_response = client.describe_trusted_advisor_checks(language='en')
if is_enable_japanese:
    checks_ja = {}
    for check_ja in client.describe_trusted_advisor_checks(
            language='ja')['checks']:
        checks_ja[check_ja['id']] = check_ja


def execute_check():
    check_ids = []
    unrefreshable_check_ids = []
    for check in checks_response['checks']:
        check_id = check['id']
        check_ids.append(check_id)
        try:
            client.refresh_trusted_advisor_check(checkId=check_id)
        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == \
                    'InvalidParameterValueException':
                unrefreshable_check_ids.append(check_id)
            else:
                print(err)
    return check_ids, unrefreshable_check_ids


def wait_check_completion(check_ids):
    count = 0
    while True:
        response = client.describe_trusted_advisor_check_refresh_statuses(
            checkIds=check_ids)
        all_done = True
        for status in response['statuses']:
            all_done &= (status['status'] in ['abandoned', 'none', 'success'])
        if all_done:
            break
        count += 1
        if count > 2:
            break
        time.sleep(30)


def lambda_handler(event, context):
    now = datetime.datetime.now()
    file_name = (
        'trustedadvisor-check-results-'
        f'{now.strftime("%Y%m%d_%H%M%S")}.json.gz')
    s3file_name = (
        f'AWSLogs/{AWS_ID}/TrustedAdvisor/{AWS_REGION}/'
        f'{now.strftime("%Y/%m/%d")}/{file_name}')
    f = gzip.open(f'/tmp/{file_name}', 'tw')
    print('Total nummber of checks: '
          f'{len(checks_response["checks"])}')

    check_ids, unrefreshable_check_ids = execute_check()
    wait_check_completion(check_ids)

    for check in checks_response['checks']:
        check_id = check['id']
        response = client.describe_trusted_advisor_check_result(
            checkId=check_id)
        dt = datetime.datetime.strptime(
            response['ResponseMetadata']['HTTPHeaders']['date'],
            "%a, %d %b %Y %H:%M:%S GMT")
        jsonobj = {
            'id': response['ResponseMetadata']['RequestId'],
            'time': dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "account": AWS_ID,
            'region': AWS_REGION,
            "resources": [],
            'check': check,
            'result': response['result'],
            'refreshable': check_id not in unrefreshable_check_ids}
        if is_enable_japanese:
            jsonobj['check_ja'] = checks_ja[check_id]
        if 'flaggedResources' in response['result'] and \
                len(response['result']['flaggedResources']) > 0:
            resource_num = len(response['result']['flaggedResources'])
            for i in range(resource_num):
                jsonobj['result']['flaggedResource'] = \
                    response['result']['flaggedResources'][i]
                jsonobj['result']['flaggedResource']['number'] = i + 1
                f.write(json.dumps(jsonobj, ensure_ascii=False))
                f.flush()
        else:
            f.write(json.dumps(jsonobj, ensure_ascii=False))
            f.flush()
    f.close()
    print(f'Upload path: s3://{bucket.name}/{s3file_name}')
    bucket.upload_file(f'/tmp/{file_name}', s3file_name)


if __name__ == '__main__':
    lambda_handler(None, None)
