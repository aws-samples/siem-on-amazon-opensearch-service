#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = 'Amazon.com, Inc. or its affiliates'
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


import json
import logging
import os

import boto3
from crhelper import CfnResource

print('version: ' + __version__)

logger = logging.getLogger(__name__)
helper = CfnResource(
    json_logging=False, log_level='DEBUG', boto_level='CRITICAL',
    sleep_on_delete=120, ssl_verify=None)

pandas_layers = {
    "ap-northeast-1": "arn:aws:lambda:ap-northeast-1:336392948345:layer:AWSDataWrangler-Python38-Arm64:4",
    "ap-northeast-2": "arn:aws:lambda:ap-northeast-2:336392948345:layer:AWSDataWrangler-Python38:5",
    "ap-northeast-3": "arn:aws:lambda:ap-northeast-3:336392948345:layer:AWSDataWrangler-Python38:5",
    "ap-south-1": "arn:aws:lambda:ap-south-1:336392948345:layer:AWSDataWrangler-Python38-Arm64:5",
    "ap-southeast-1": "arn:aws:lambda:ap-southeast-1:336392948345:layer:AWSDataWrangler-Python38-Arm64:4",
    "ap-southeast-2": "arn:aws:lambda:ap-southeast-2:336392948345:layer:AWSDataWrangler-Python38-Arm64:4",
    "ca-central-1": "arn:aws:lambda:ca-central-1:336392948345:layer:AWSDataWrangler-Python38:5",
    "eu-central-1": "arn:aws:lambda:eu-central-1:336392948345:layer:AWSDataWrangler-Python38-Arm64:4",
    "eu-north-1": "arn:aws:lambda:eu-north-1:336392948345:layer:AWSDataWrangler-Python38:4",
    "eu-west-1": "arn:aws:lambda:eu-west-1:336392948345:layer:AWSDataWrangler-Python38-Arm64:4",
    "eu-west-2": "arn:aws:lambda:eu-west-2:336392948345:layer:AWSDataWrangler-Python38-Arm64:4",
    "eu-west-3": "arn:aws:lambda:eu-west-3:336392948345:layer:AWSDataWrangler-Python38:5",
    "sa-east-1": "arn:aws:lambda:sa-east-1:336392948345:layer:AWSDataWrangler-Python38:4",
    "us-east-1": "arn:aws:lambda:us-east-1:336392948345:layer:AWSDataWrangler-Python38-Arm64:4",
    "us-east-2": "arn:aws:lambda:us-east-2:336392948345:layer:AWSDataWrangler-Python38-Arm64:4",
    "us-west-1": "arn:aws:lambda:us-west-1:336392948345:layer:AWSDataWrangler-Python38:7",
    "us-west-2": "arn:aws:lambda:us-west-2:336392948345:layer:AWSDataWrangler-Python38-Arm64:4",
}
VER = '2.16.1'


@helper.update
@helper.create
def create(event, context):
    logger.info("Got Create/Update")
    pandas_layer = 'NotPandasLayerArn'
    try:
        pandas_layer = update_layer()
    except Exception:
        logger.exception('something was happend')

    return pandas_layer


@helper.delete
def delete(event, context):
    logger.info("Got Delete")


def lambda_handler(event, context):
    if 'ResourceType' in event \
            and event['ResourceType'] == 'AWS::CloudFormation::CustomResource':
        helper(event, context)
    else:
        create(event, context)
    return {"statusCode": 200}


def update_layer():
    lambda_client = boto3.client('lambda')
    s3_resource = boto3.resource('s3')

    logger.info('M001: check es-loader configuration')
    response = lambda_client.get_function(FunctionName='aes-siem-es-loader')
    es_layers = response['Configuration'].get('Layers', [])
    new_layers = []
    for layer in es_layers:
        new_layers.append(layer['Arn'])
        if 'AWSDataWrangler' in layer['Arn']:
            logger.info('X001: The Lambda Layer is already added')
            return layer['Arn']
    runtime = response['Configuration']['Runtime']
    arch = response['Configuration'].get('Architectures', ['x86_64'])
    region = response['Configuration']['FunctionArn'].split(':')[3]
    account = response['Configuration']['FunctionArn'].split(':')[4]

    logger.info('M100: Check pandas layers')
    pandas_layer_arn = pandas_layers.get(region)
    if pandas_layer_arn:
        logger.info('X101: Found the managed layer')
    else:
        layers = lambda_client.list_layers(
            CompatibleRuntime=runtime, CompatibleArchitecture=arch[0])
        for layer in layers['Layers']:
            layer_arn = layer['LatestMatchingVersion']['LayerVersionArn']
            if 'AWSDataWrangler' in layer_arn:
                pandas_layer_arn = layer_arn
                logger.info('X102: Found the custom layer')
                break

    if not pandas_layer_arn:
        logger.info('X103: Not Found the layer')
        logger.info('M201: publish custom layer')
        s3bucket = os.getenv('GEOIP_BUCKET', f'aes-siem-{account}-geo')
        s3key = f'releases/{VER}/awswrangler-layer-{VER}-py3.8.zip'
        s3_resource.meta.client.copy(
            {'Bucket': 'aws-data-wrangler-public-artifacts', 'Key': s3key},
            s3bucket, f'aws_sdk_pandas/{s3key}')
        response = lambda_client.publish_layer_version(
            LayerName='AWSDataWrangler-Python38',
            Description=f'From s3://{s3bucket}/aws_sdk_pandas/{s3key}',
            Content={'S3Bucket': s3bucket, 'S3Key': f'aws_sdk_pandas/{s3key}'},
            CompatibleRuntimes=[runtime],
            CompatibleArchitectures=arch,)
        pandas_layer_arn = response['LayerVersionArn']

    logger.info('M301: Add pandas layer')
    new_layers.append(pandas_layer_arn)
    response = lambda_client.update_function_configuration(
        FunctionName='aes-siem-es-loader', Layers=new_layers)
    logger.info(f'X301: response')
    print(json.dumps(response))
    return pandas_layer_arn


if __name__ == '__main__':
    update_layer()
