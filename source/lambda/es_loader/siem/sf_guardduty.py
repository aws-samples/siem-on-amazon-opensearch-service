# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re

from siem import utils

RE_GD_TYPE = re.compile(
    r"(?P<ThreatPurpose>\w*):(?P<ResourceTypeAffected>\w*)/"
    r"(?P<ThreatFamilyName>[\w\&]*)(\.(?P<DetectionMechanism>\w*))?"
    r"(\!(?P<Artifact>\w*))?")


def transform(logdata):
    logdata['rule']['name'] = logdata['rule']['name'].strip().rstrip('.')
    if logdata['severity'] <= 3.9:
        label = "low"
    elif logdata['severity'] <= 6.9:
        label = "medium"
    elif logdata['severity'] <= 8.9:
        label = "high"
    m = RE_GD_TYPE.match(logdata['type'])
    gd = {'severitylabel': label, 'ThreatPurpose': m['ThreatPurpose'],
          'ResourceTypeAffected': m['ResourceTypeAffected'],
          'ThreatFamilyName': m['ThreatFamilyName'],
          'DetectionMechanism': m.group('DetectionMechanism'),
          'Artifact': m.group('Artifact')}
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
    if logdata['ThreatPurpose'] in ('Backdoor', 'CryptoCurrency', 'Trojan'):
        logdata['event']['category'] = 'malware'
    elif gd['ThreatFamilyName'] in ('SuspiciousFile', 'MaliciousFile'):
        logdata['event']['category'] = 'malware'
    return logdata
