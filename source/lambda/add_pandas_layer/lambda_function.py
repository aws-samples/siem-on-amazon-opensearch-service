#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = 'Amazon.com, Inc. or its affiliates'
__version__ = '2.10.0'
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
    sleep_on_delete=3, ssl_verify=None)

VER = '3.1.0'
"""
curl -s https://raw.githubusercontent.com/aws/aws-sdk-pandas/main/docs/source/layers.rst \
   | grep '| 3.8' | sort -k2,6 | awk -F'|' '{print $2, $4, $5}' \
   | awk '!colname[$1]++{printf "    \"%s\": \"%s\",\n", $1, $3}'
"""

pandas_layers = {
    "af-south-1": "arn:aws:lambda:af-south-1:336392948345:layer:AWSSDKPandas-Python38-Arm64:7",
    "ap-northeast-1": "arn:aws:lambda:ap-northeast-1:336392948345:layer:AWSSDKPandas-Python38-Arm64:7",
    "ap-northeast-2": "arn:aws:lambda:ap-northeast-2:336392948345:layer:AWSSDKPandas-Python38-Arm64:3",
    "ap-northeast-3": "arn:aws:lambda:ap-northeast-3:336392948345:layer:AWSSDKPandas-Python38-Arm64:3",
    "ap-south-1": "arn:aws:lambda:ap-south-1:336392948345:layer:AWSSDKPandas-Python38-Arm64:7",
    "ap-southeast-1": "arn:aws:lambda:ap-southeast-1:336392948345:layer:AWSSDKPandas-Python38-Arm64:7",
    "ap-southeast-2": "arn:aws:lambda:ap-southeast-2:336392948345:layer:AWSSDKPandas-Python38-Arm64:7",
    "ca-central-1": "arn:aws:lambda:ca-central-1:336392948345:layer:AWSSDKPandas-Python38-Arm64:3",
    "eu-central-1": "arn:aws:lambda:eu-central-1:336392948345:layer:AWSSDKPandas-Python38-Arm64:7",
    "eu-north-1": "arn:aws:lambda:eu-north-1:336392948345:layer:AWSSDKPandas-Python38-Arm64:3",
    "eu-west-1": "arn:aws:lambda:eu-west-1:336392948345:layer:AWSSDKPandas-Python38-Arm64:8",
    "eu-west-2": "arn:aws:lambda:eu-west-2:336392948345:layer:AWSSDKPandas-Python38-Arm64:7",
    "eu-west-3": "arn:aws:lambda:eu-west-3:336392948345:layer:AWSSDKPandas-Python38-Arm64:3",
    "sa-east-1": "arn:aws:lambda:sa-east-1:336392948345:layer:AWSSDKPandas-Python38-Arm64:3",
    "us-east-1": "arn:aws:lambda:us-east-1:336392948345:layer:AWSSDKPandas-Python38-Arm64:7",
    "us-east-2": "arn:aws:lambda:us-east-2:336392948345:layer:AWSSDKPandas-Python38-Arm64:7",
    "us-west-1": "arn:aws:lambda:us-west-1:336392948345:layer:AWSSDKPandas-Python38-Arm64:3",
    "us-west-2": "arn:aws:lambda:us-west-2:336392948345:layer:AWSSDKPandas-Python38-Arm64:7",
}


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


def get_lambda_info(lambda_client):
    logger.info('X000: get_lambda_info started')
    response = lambda_client.get_function(FunctionName='aes-siem-es-loader')
    account = response['Configuration']['FunctionArn'].split(':')[4]
    region = response['Configuration']['FunctionArn'].split(':')[3]
    es_layers = response['Configuration'].get('Layers', [])
    pandas_layer_arn = ''
    new_layers = []
    for layer in es_layers:
        if 'AWSDataWrangler' in layer['Arn'] or 'AWSSDKPandas' in layer['Arn']:
            pandas_layer_arn = layer['Arn']
        else:
            new_layers.append(layer['Arn'])
    runtime = response['Configuration']['Runtime']
    arch = response['Configuration'].get('Architectures', ['x86_64'])
    if pandas_layer_arn and (account not in pandas_layer_arn):
        is_managed = True
    else:
        is_managed = False

    lambda_info = {'account': account, 'region': region, 'runtime': runtime,
                   'arch': arch[0], 'is_managed': is_managed,
                   'pandas_layer_arn': pandas_layer_arn,
                   'new_layers': new_layers}

    logger.info(lambda_info)
    logger.info('X099: get_lambda_info ended')
    return lambda_info


def check_if_latest_pandas_sdk_is_deployed(lambda_client, lambda_info):
    logger.info('X100: check_if_latest_pandas_sdk_is_deployed started')
    pandas_layer_arn = lambda_info['pandas_layer_arn']
    py_ver = lambda_info['runtime'].replace('py', 'Py').replace('.', '')
    arch = lambda_info['arch']

    if py_ver in pandas_layer_arn:
        if ((arch == 'arm64' and 'Arm64' in pandas_layer_arn)
                or (arch != 'arm64' and 'Arm64' not in pandas_layer_arn)):
            if lambda_info['region'] in pandas_layers.keys():
                if lambda_info['pandas_layer_arn'] in pandas_layers.values():
                    logger.info(
                        'X101: The latest pandas sdk was already deployed')
                    return True
            elif lambda_info['pandas_layer_arn']:
                response = lambda_client.get_layer_version_by_arn(
                    Arn=lambda_info['pandas_layer_arn'])
                if VER in response['Description']:
                    logger.info(
                        'X102: The latest pandas sdk was already deployed')
                    return True

    logger.info('X110: The latest pandas sdk is NOT deployed')
    return False


def setup_lambda_layer(lambda_client, lambda_info):
    logger.info('X200: setup_lambda_layer started')
    py_ver = lambda_info['runtime'].replace('py', 'Py').replace('.', '')
    arch = lambda_info['arch']

    maanged_pandas = pandas_layers.get(lambda_info['region'])
    new_pandas_layer_arn = None
    if maanged_pandas:
        if py_ver in maanged_pandas:
            if ((arch == 'arm64' and 'Arm64' in maanged_pandas)
                    or (arch != 'arm64' and 'Arm64' not in maanged_pandas)):
                new_pandas_layer_arn = maanged_pandas
                logger.info('X201: The managed layer is found')
    if not new_pandas_layer_arn:
        logger.info('X203: The managed layer is not found')
        logger.info('M201: publish custom layer')
        s3_resource = boto3.resource('s3')
        s3bucket = os.getenv(
            'GEOIP_BUCKET', f"aes-siem-{lambda_info['account']}-geo")

        py_ver1 = lambda_info['runtime'].replace('python', '')
        py_ver2 = lambda_info['runtime'].replace('py', 'Py').replace('.', '')
        if lambda_info['arch'] == 'arm64':
            _arch1 = '-' + lambda_info['arch']
            _arch2 = '-' + lambda_info['arch'].capitalize()
        else:
            _arch1 = ''
            _arch2 = ''
        s3key = (
            f'releases/{VER}/awswrangler-layer-{VER}-py{py_ver1}{_arch1}.zip')
        s3_resource.meta.client.copy(
            {'Bucket': 'aws-data-wrangler-public-artifacts', 'Key': s3key},
            s3bucket, f'aws_sdk_pandas/{s3key}')

        _layer_name = f'AWSSDKPandas-{py_ver2}{_arch2}'
        _description = f'From s3://{s3bucket}/aws_sdk_pandas/{s3key}'
        _s3Key = f'aws_sdk_pandas/{s3key}'
        _compatible_runtimes = [lambda_info['runtime']]
        _compatible_architectures = [lambda_info['arch']]

        try:
            response = lambda_client.publish_layer_version(
                LayerName=_layer_name, Description=_description,
                Content={'S3Bucket': s3bucket, 'S3Key': _s3Key},
                CompatibleRuntimes=_compatible_runtimes,
                CompatibleArchitectures=_compatible_architectures,
            )
            new_pandas_layer_arn = response['LayerVersionArn']
        except Exception:
            response = lambda_client.publish_layer_version(
                LayerName=_layer_name, Description=_description,
                Content={'S3Bucket': s3bucket, 'S3Key': _s3Key},
                CompatibleRuntimes=_compatible_runtimes,
            )
            new_pandas_layer_arn = response['LayerVersionArn']

    logger.info(f'X299: {new_pandas_layer_arn} will be added')
    return new_pandas_layer_arn


def update_lambda_conf_to_add_pandas_sdk(lambda_client, lambda_info,
                                         new_pandas_layer_arn):
    logger.info('X300: update_lambda_conf_to_add_pandas_sdk started')
    new_layers = lambda_info['new_layers']
    new_layers.append(new_pandas_layer_arn)
    response = lambda_client.update_function_configuration(
        FunctionName='aes-siem-es-loader', Layers=new_layers)
    logger.info('X399: response')
    logger.info(json.dumps(response))


def update_layer():
    lambda_client = boto3.client('lambda')
    lambda_info = get_lambda_info(lambda_client)
    is_latest_pandas = check_if_latest_pandas_sdk_is_deployed(
        lambda_client, lambda_info)
    if is_latest_pandas:
        return
    new_pandas_layer_arn = setup_lambda_layer(lambda_client, lambda_info)
    update_lambda_conf_to_add_pandas_sdk(lambda_client, lambda_info,
                                         new_pandas_layer_arn)


if __name__ == '__main__':
    update_layer()
