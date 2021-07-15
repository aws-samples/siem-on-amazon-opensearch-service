#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from aws_cdk import core
from deployment_samples.deployment_samples_stack import (
    ADLogExporterStack,
    BasicLogExporterStack,
    CWLNoCompressExporterStack,
    DeploymentSamplesStack,
    WorkSpacesLogExporterStack
)

app = core.App()
DeploymentSamplesStack(app, "DeploymentSamplesStack")
basic_logging = BasicLogExporterStack(
    app, "siem-log-exporter-basic",
    description='SIEM: log export basic resource')
cwl_nocompresss_logging = CWLNoCompressExporterStack(
    app, "siem-log-exporter-cwl-nocompress",
    description='SIEM: log export CWL resource without compress')
workspaces_logging = WorkSpacesLogExporterStack(
    app, "siem-log-exporter-workspaces",
    description='SIEM: Workspaces log exporter')
ad_logging = ADLogExporterStack(
    app, "siem-log-exporter-ad",
    description='SIEM: Active Directory log exporter')

app.synth()
