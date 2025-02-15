# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = 'Amazon.com, Inc. or its affiliates'
__version__ = '2.10.4-beta.1'
__license__ = 'MIT-0'
__author__ = 'Katsuya Matsuoka'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import copy
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
AWS_REGION = 'us-east-1'
is_enable_japanese = (os.environ['enable_japanese_description'] == 'Yes')

try:
    res = client.describe_trusted_advisor_checks(language='en')
except botocore.exceptions.ClientError:
    print('Aborted. Business or Enterprise Support Subscription is required')
    raise
CHECKS_EN = res['checks']

CHECKS_JA = {}
if is_enable_japanese:
    for check_ja in client.describe_trusted_advisor_checks(
            language='ja')['checks']:
        CHECKS_JA[check_ja['id']] = check_ja


def execute_check():
    check_ids = []
    unrefreshable_check_ids = []
    for check in CHECKS_EN:
        check_ids.append(check['id'])
        try:
            client.refresh_trusted_advisor_check(checkId=check['id'])
        except botocore.exceptions.ClientError as err:
            err_code = err.response['Error']['Code']
            if err_code == 'InvalidParameterValueException':
                unrefreshable_check_ids.append(check['id'])
            else:
                print(err)
    return check_ids, unrefreshable_check_ids


CHECK_IDS, UNREFRESHABLE_CHECK_IDS = execute_check()


def refresh_and_wait_check_completion():
    count = 0
    all_done = False
    while not all_done:
        response = client.describe_trusted_advisor_check_refresh_statuses(
            checkIds=CHECK_IDS)
        time.sleep(30)
        all_done = True
        for status in response['statuses']:
            if status['status'] not in ['abandoned', 'none', 'success']:
                all_done = False
        if count > 2:
            break
        count += 1


def query_and_transform_and_save(f, check):
    res = client.describe_trusted_advisor_check_result(
        checkId=check['id'])
    jsonobj = {
        'requestid': res['ResponseMetadata']['RequestId'],
        'creation_date': datetime.datetime.utcnow().isoformat(),
        'account': AWS_ID, 'check': check, 'result': copy.copy(res['result']),
        'refreshable': check['id'] not in UNREFRESHABLE_CHECK_IDS}
    if is_enable_japanese:
        jsonobj['check_ja'] = CHECKS_JA[check['id']]
    f.write(json.dumps(jsonobj, ensure_ascii=False))
    if ('flaggedResources' in res['result']
            and len(res['result']['flaggedResources']) > 0):
        del jsonobj['result']['flaggedResources']
        del jsonobj['result']['resourcesSummary']
        del jsonobj['result']['categorySpecificSummary']
        for i in range(len(res['result']['flaggedResources'])):
            jsonobj['result']['flaggedResource'] = (
                res['result']['flaggedResources'][i])
            jsonobj['result']['flaggedResource']['number'] = i + 1
            f.write(json.dumps(jsonobj, ensure_ascii=False))


def lambda_handler(event, context):
    now = datetime.datetime.now()
    file_name = (
        'trustedadvisor-check-results-'
        f'{now.strftime("%Y%m%d_%H%M%S")}.json.gz')
    s3file_name = (
        f'AWSLogs/{AWS_ID}/TrustedAdvisor/{AWS_REGION}/'
        f'{now.strftime("%Y/%m/%d")}/{file_name}')
    f = gzip.open(f'/tmp/{file_name}', 'tw')
    print(f'Total nummber of checks: {len(CHECKS_EN)}')
    refresh_and_wait_check_completion()
    for check in CHECKS_EN:
        query_and_transform_and_save(f, check)
    f.close()
    print(f'Upload path: s3://{bucket.name}/{s3file_name}')
    bucket.upload_file(f'/tmp/{file_name}', s3file_name)


if __name__ == '__main__':
    lambda_handler(None, None)
