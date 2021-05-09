#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import os

from aws_cdk import core

from mysiem.aes_siem_stack import MyAesSiemStack

app = core.App()
MyAesSiemStack(app, "aes-siem", description='SIEM on Amazon ES',
               env=core.Environment(
                    account=os.environ['CDK_DEFAULT_ACCOUNT'],
                    region=os.environ['CDK_DEFAULT_REGION']))
app.synth()
