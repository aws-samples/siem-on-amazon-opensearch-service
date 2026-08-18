# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.6'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re

from aws_lambda_powertools import Logger

from siem import utils

logger = Logger(child=True)

RE_GD_TYPE = re.compile(
    r"(?P<ThreatPurpose>\w*):(?P<ResourceTypeAffected>\w*)/"
    r"(?P<ThreatFamilyName>[\w\&]*)(\.(?P<DetectionMechanism>\w*))?"
    r"(\!(?P<Artifact>\w*))?")

# Fields extracted from the finding type. Kept as a constant so that the
# fallback in transform() cannot drift from the parsed result.
GD_TYPE_KEYS = ('ThreatPurpose', 'ResourceTypeAffected', 'ThreatFamilyName',
                'DetectionMechanism', 'Artifact')


def transform(logdata):
    logdata['rule']['name'] = logdata['rule']['name'].strip().rstrip('.')
    severity = logdata['severity']
    if severity <= 3.9:
        label = "low"
    elif severity <= 6.9:
        label = "medium"
    elif severity <= 8.9:
        label = "high"
    elif severity <= 10.0:
        label = "critical"
    else:
        logger.warning(
            f'GuardDuty severity {severity} is outside the documented '
            'range of 1.0-10.0. Labelled as unknown')
        label = "unknown"
    m = RE_GD_TYPE.match(logdata['type'])
    if m:
        gd_type = {key: m.group(key) for key in GD_TYPE_KEYS}
    else:
        # An unparsable finding type must not cost us the whole document.
        logger.warning(
            f"GuardDuty finding type is not parsable: {logdata['type']}")
        gd_type = dict.fromkeys(GD_TYPE_KEYS)
    gd = {'severitylabel': label, **gd_type}
    try:
        action_type = logdata['service']['action']['actionType']
    except KeyError:
        action_type = ''
    if action_type == 'NETWORK_CONNECTION':
        direction = (logdata['service']['action']
                     ['networkConnectionAction']['connectionDirection'])
    elif action_type == 'DNS_REQUEST':
        direction = "OUTBOUND"
    elif gd['ThreatFamilyName'] in ('SuspiciousFile', 'MaliciousFile'):
        direction = None
    else:
        direction = "INBOUND"
    if direction:
        gd['network'] = {'direction': direction.lower()}
    logdata = utils.merge_dicts(logdata, gd)
    if direction == "OUTBOUND":
        logdata['source'], logdata['destination'] = (
            logdata.get('destination'), logdata.get('source'))
        if not logdata['source']:
            del logdata['source']
        if not logdata['destination']:
            del logdata['destination']
    # event.category
    if gd['ThreatPurpose'] in ('Backdoor', 'CryptoCurrency', 'Trojan'):
        logdata['event']['category'] = 'malware'
    elif gd['ThreatFamilyName'] in ('SuspiciousFile', 'MaliciousFile'):
        logdata['event']['category'] = 'malware'
    return logdata
