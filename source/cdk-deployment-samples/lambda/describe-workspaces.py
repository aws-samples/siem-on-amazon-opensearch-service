# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.9.0'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import datetime
import gzip
import json
import os
import time

import boto3
from botocore.config import Config

config = Config(retries={'max_attempts': 10, 'mode': 'standard'})
ws_client = boto3.client('workspaces', config=config)
s3_resource = boto3.resource('s3')
bucket = s3_resource.Bucket(os.environ['log_bucket_name'])
AWS_ID = str(boto3.client("sts").get_caller_identity()["Account"])
AWS_REGION = os.environ['AWS_DEFAULT_REGION']


def json_serial(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return str(obj)


def lambda_handler(event, context):
    num = 0
    now = datetime.datetime.now()
    file_name = f'workspaces-inventory-{now.strftime("%Y%m%d_%H%M%S")}.json.gz'
    s3file_name = (
        f'AWSLogs/{AWS_ID}/WorkSpaces/Inventory/{AWS_REGION}/'
        f'{now.strftime("%Y/%m/%d")}/{file_name}')
    f = gzip.open(f'/tmp/{file_name}', 'tw')

    api = 'describe_workspaces_connection_status'
    print(api)
    ws_cons = {}
    num = 0
    paginator = ws_client.get_paginator(api)
    for response in paginator.paginate():
        for ws_con in response['WorkspacesConnectionStatus']:
            ws_cons[ws_con['WorkspaceId']] = ws_con
            num += 1
        time.sleep(0.75)
    print(f'Number of {api}: {num}')

    api = 'describe_workspaces'
    print(api)
    num = 0
    paginator = ws_client.get_paginator(api)
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
            'detail': {'Workspaces': []}}
        for item in response['Workspaces']:
            try:
                item = {**item, **ws_cons[item['WorkspaceId']]}
            except Exception:
                pass
            jsonobj['detail']['Workspaces'].append(item)
        num += len(response['Workspaces'])
        f.write(json.dumps(jsonobj, default=json_serial))
        f.flush()
        # sleep 0.75 second to avoid reaching AWS API rate limit (2rps)
        time.sleep(0.75)
    print(f'Total nummber of WorkSpaces inventory: {num}')

    f.close()
    print(f'Upload path: s3://{bucket.name}/{s3file_name}')
    bucket.upload_file(f'/tmp/{file_name}', s3file_name)


if __name__ == '__main__':
    lambda_handler(None, None)
