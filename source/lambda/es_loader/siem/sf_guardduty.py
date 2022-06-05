# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.7.1'
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
    action_type = logdata['service']['action']['actionType']
    if 'NETWORK_CONNECTION' in action_type:
        direction = (logdata['service']['action']
                     ['networkConnectionAction']['connectionDirection'])
    elif 'DNS_REQUEST' in action_type:
        direction = "OUTBOUND"
    else:
        direction = "INBOUND"
    gd['network'] = {'direction': direction}
    logdata = utils.merge_dicts(logdata, gd)
    if "OUTBOUND" in direction:
        logdata['source'], logdata['destination'] = (
            logdata.get('destination'), logdata.get('source'))
        if not logdata['source']:
            del logdata['source']
        if not logdata['destination']:
            del logdata['destination']
    # event.category
    if logdata['ThreatPurpose'] in ('Backdoor', 'CryptoCurrency', 'Trojan'):
        logdata['event']['category'] = 'malware'
    return logdata
