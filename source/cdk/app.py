#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.7.2-beta.2'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import os

from aws_cdk import core

from mysiem.aes_siem_stack import MyAesSiemStack

app = core.App()
MyAesSiemStack(app, "aes-siem",
               description=f'SIEM on Amazon OpenSearch Service v{__version__}',
               env=core.Environment(
                    account=os.environ['CDK_DEFAULT_ACCOUNT'],
                    region=os.environ['CDK_DEFAULT_REGION']))
app.synth()
