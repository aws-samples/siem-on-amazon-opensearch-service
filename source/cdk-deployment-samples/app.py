#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from aws_cdk import core
from deployment_samples.deployment_samples_stack import DeploymentSamplesStack
from deployment_samples.deployment_samples_stack import WorkSpacesLogExporterStack
from deployment_samples.deployment_samples_stack import BasicLogExporterStack

app = core.App()
DeploymentSamplesStack(app, "DeploymentSamplesStack")
basic_logging = BasicLogExporterStack(
    app, "aes-siem-log-exporter-basic",
    description='SIEM on Amazon ES: log export basic resource')
workspaces_logging = WorkSpacesLogExporterStack(
    app, "aes-siem-log-exporter-workspaces",
    description='SIEM on Amazon ES: Workspaces log exporter')

app.synth()
