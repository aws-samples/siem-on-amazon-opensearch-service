#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.2b'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import aws_cdk as cdk

from deployment_samples.deployment_samples_stack import (
    ADLogExporterStack,
    ApacheCWLogsExporterStack,
    ClientVpnLogExporterStack,
    CloudHsmCWLogsExporterStack,
    ControlTowerIntegrationStack,
    CoreLogExporterStack,
    CWLNoCompressExporterStack,
    DeploymentSamplesStack,
    EventBridgeEventsExporterStack,
    FirehoseExporterStack,
    LinuxCWLogsExporterStack,
    NginxCWLogsExporterStack,
    TrustedAdvisorLogExporterStack,
    WorkSpacesLogExporterStack,
)

app = cdk.App()
DeploymentSamplesStack(app, "DeploymentSamplesStack")
core_logging = CoreLogExporterStack(
    app, "siem-log-exporter-core",
    description=(f'SIEM on Amazon OpenSearch Service v{__version__}: '
                 'log exporter - core resource'))
cwl_nocompresss_logging = CWLNoCompressExporterStack(
    app, "siem-log-exporter-cwl-nocompress",
    description=(f'SIEM on Amazon OpenSearch Service v{__version__}: '
                 'log exporter - CWL resource without compress'))
fsx_logging = FirehoseExporterStack(
    app, "siem-log-exporter-fsx",
    description=(f'SIEM on Amazon OpenSearch Service v{__version__}: '
                 'log exporter - FSx resource without compress'),
    default_firehose_name='aws-fsx-',
    firehose_compression_format='GZIP')
workspaces_logging = WorkSpacesLogExporterStack(
    app, "siem-log-exporter-workspaces",
    description=(f'SIEM on Amazon OpenSearch Service v{__version__}: '
                 'log exporter - Workspaces'))
trustedadvisor_logging = TrustedAdvisorLogExporterStack(
    app, "siem-log-exporter-trustedadvisor",
    description=(f'SIEM on Amazon OpenSearch Service v{__version__}: '
                 'log exporter - TrustedAdvisor'))
ad_logging = ADLogExporterStack(
    app, "siem-log-exporter-ad",
    description=(f'SIEM on Amazon OpenSearch Service v{__version__}: '
                 'log exporter - Active Directory'))
cloudhsm_logging = CloudHsmCWLogsExporterStack(
    app, "siem-log-exporter-cloudhsm-cwl",
    description=(f'SIEM on Amazon OpenSearch Service v{__version__}: '
                 'log exporter - CloudHSM'))
linux_logging = LinuxCWLogsExporterStack(
    app, "siem-log-exporter-linux-cwl",
    description=(f'SIEM on Amazon OpenSearch Service v{__version__}: '
                 'log exporter - Linux'))
apache_logging = ApacheCWLogsExporterStack(
    app, "siem-log-exporter-apache-cwl",
    description=(f'SIEM on Amazon OpenSearch Service v{__version__}: '
                 'log exporter - Apache'))
nginx_logging = NginxCWLogsExporterStack(
    app, "siem-log-exporter-nginx-cwl",
    description=(f'SIEM on Amazon OpenSearch Service v{__version__}: '
                 'log exporter - Nginx'))
clientvpn_logging = ClientVpnLogExporterStack(
    app, "siem-log-exporter-clientvpn",
    description=(f'SIEM on Amazon OpenSearch Service v{__version__}: '
                 'log exporter - ClientVPN'))
eventbridge_events_logging = EventBridgeEventsExporterStack(
    app, "siem-log-exporter-eventbridge-events",
    description=(f'SIEM on Amazon OpenSearch Service v{__version__}: '
                 'log exporter - EventBridge events '
                 '(SecurityHub, ConfigRules, Inspector)'))

control_tower_integration = ControlTowerIntegrationStack(
    app, "control-tower-integration",
    description=(f'SIEM on Amazon OpenSearch Service v{__version__}: '
                 'Control Tower Integration'))

app.synth()
