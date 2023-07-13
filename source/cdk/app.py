#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.0-beta.3'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import os

import aws_cdk as cdk

from mysiem.aes_siem_stack import MyAesSiemStack

app = cdk.App()
CDK_DEFAULT_REGION = os.getenv(
    "CDK_DEFAULT_REGION", os.environ["AWS_DEFAULT_REGION"])
region = os.environ.get("CDK_DEPLOY_REGION", CDK_DEFAULT_REGION)
account = os.environ.get(
    "CDK_DEPLOY_ACCOUNT", os.environ["CDK_DEFAULT_ACCOUNT"])

MyAesSiemStack(app, "aes-siem",
               description=f'SIEM on Amazon OpenSearch Service v{__version__}',
               env=cdk.Environment(account=account, region=region))
app.synth()
