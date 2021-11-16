# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = 'Amazon.com, Inc. or its affiliates'
__version__ = '2.5.1-beta.4'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import datetime
import gzip
import json
import os

import boto3

ws_client = boto3.client('workspaces')
s3_resource = boto3.resource('s3')
bucket = s3_resource.Bucket(os.environ['log_bucket_name'])
AWS_ID = str(boto3.client("sts").get_caller_identity()["Account"])
AWS_REGION = os.environ['AWS_DEFAULT_REGION']
paginator = ws_client.get_paginator('describe_workspaces')


def lambda_handler(event, context):
    num = 0
    now = datetime.datetime.now()
    file_name = f'workspaces-inventory-{now.strftime("%Y%m%d_%H%M%S")}.json.gz'
    s3file_name = (
        f'AWSLogs/{AWS_ID}/WorkSpaces/Inventory/{AWS_REGION}/'
        f'{now.strftime("%Y/%m/%d")}/{file_name}')
    f = gzip.open(f'/tmp/{file_name}', 'tw')
    response_iterator = paginator.paginate(PaginationConfig={'PageSize': 25})
    for response in response_iterator:
        print(f'{response["ResponseMetadata"]["RequestId"]}: '
              f'{len(response["Workspaces"])}')
        dt = datetime.datetime.strptime(
            response['ResponseMetadata']['HTTPHeaders']['date'],
            "%a, %d %b %Y %H:%M:%S GMT")
        jsonobj = {
            'id': response['ResponseMetadata']['RequestId'],
            'time': dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            'detail-type': 'WorkSpaces Fake',
            "source": "aws.fake.workspaces",
            "account": AWS_ID,
            'region': AWS_REGION,
            "resources": [],
            'detail': {}}
        jsonobj['detail']['Workspaces'] = response['Workspaces']
        num += len(response['Workspaces'])
        f.write(json.dumps(jsonobj))
        f.flush()
    f.close()
    print(f'Total nummber of WorkSpaces inventory: {num}')
    print(f'Upload path: s3://{bucket}/{s3file_name}')
    bucket.upload_file(f'/tmp/{file_name}', s3file_name)


if __name__ == '__main__':
    lambda_handler(None, None)
