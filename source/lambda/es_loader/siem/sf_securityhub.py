# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.6.2-beta.3'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re
from collections import namedtuple
from datetime import datetime
from functools import lru_cache

from siem import utils

RE_GD_MACIE_TYPE = re.compile(
    r"(?P<asff_type_namespace>[^/]*)(/(?P<asff_type_category>[^/]*))?/"
    r"((?P<ThreatPurpose>\w*):)?(?P<ResourceTypeAffected>\w*)"
    r"(/|-|\.)(?P<ThreatFamilyName>[\w\&]*)(\.(?P<DetectionMechanism>\w*))?"
    r"(\!(?P<Artifact>\w*))?")

RE_GD_MACIE_ORG_TYPE = re.compile(
    r"(?P<ThreatPurpose>\w*):(?P<ResourceTypeAffected>\w*)/"
    r"(?P<ThreatFamilyName>[\w\&]*)(\.(?P<DetectionMechanism>\w*))?"
    r"(\!(?P<Artifact>\w*))?")

FindingTypes = namedtuple(
    'FindingTypes', ['asff_type_namespace', 'asff_type_category',
                     'ThreatPurpose', 'ResourceTypeAffected',
                     'ThreatFamilyName', 'DetectionMechanism', 'Artifact'])


@lru_cache
def split_findings_type(finding_type):
    m = RE_GD_MACIE_TYPE.match(finding_type)
    try:
        asff_type_namespace = m['asff_type_namespace']
        if m.group('asff_type_category'):
            asff_type_category = m.group('asff_type_category')
        else:
            asff_type_category = m.group('ThreatPurpose')
    except TypeError:
        # old security hub log style
        m = RE_GD_MACIE_ORG_TYPE.match(finding_type)
        asff_type_namespace = None
        asff_type_category = m.group('ThreatPurpose')

    if m.group('ThreatPurpose'):
        threat_purpose = m['ThreatPurpose']
    else:
        threat_purpose = m['asff_type_category']
        threat_purpose = threat_purpose.replace(' ', '')
    resource_type_affected = m['ResourceTypeAffected']
    threat_family_name = m['ThreatFamilyName']
    detection_mechanism = m.group('DetectionMechanism')
    artifact = m.group('Artifact')

    return(FindingTypes(asff_type_namespace, asff_type_category,
                        threat_purpose, resource_type_affected,
                        threat_family_name, detection_mechanism, artifact))


def get_values_from_asff_resources(resources):
    resouce_dict = {}
    for resouce in resources:
        if resouce['Type'] == 'AwsEc2Instance':
            instanceid = resouce['Id'].split('/')[-1]
            resouce_dict['cloud'] = {'instance': {'id': instanceid}}
        elif resouce['Type'] == 'AwsIamAccessKey':
            accesskey = resouce['Id'].split(':')[-1]
            if accesskey == 'null':
                accesskey = (resouce['Details']['AwsIamAccessKey']
                             ['PrincipalId']).split(':')[0]
            name = resouce['Details']['AwsIamAccessKey']['PrincipalName']
            resouce_dict['user'] = {'id': accesskey, 'name': name}
        elif resouce['Type'] == 'AwsEc2Volume':
            try:
                instanceid = (resouce['Details']['AwsEc2Volume']['Attachments']
                              [0]['InstanceId'])
            except Exception:
                continue
            resouce_dict['cloud'] = {'instance': {'id': instanceid}}
        elif resouce['Type'] == 'AwsIamRole':
            name = resouce['Id'].split('/')[-1]
            resouce_dict['user'] = {'name': name}
        elif resouce['Type'] == 'AwsS3Bucket':
            pass
        elif resouce['Type'] == 'AwsEksCluster':
            pass

    return resouce_dict


def transform(logdata):
    # event (ecs)
    module = (logdata['ProductFields']['aws/securityhub/ProductName']).lower()
    logdata['event']['module'] = module

    if module in ('guardduty', 'macie'):
        findngs_type = split_findings_type(str(logdata['Types'][0]))
        logdata['ThreatPurpose'] = findngs_type.ThreatPurpose
        logdata['ResourceTypeAffected'] = findngs_type.ResourceTypeAffected
        logdata['ThreatFamilyName'] = findngs_type.ThreatFamilyName
        logdata['DetectionMechanism'] = findngs_type.DetectionMechanism
        logdata['Artifact'] = findngs_type.Artifact

    if 'guardduty' in module:
        logdata['event']['category'] = 'intrusion_detection'

        action_type = (logdata['ProductFields']
                       ['aws/guardduty/service/action/actionType'])
        if 'NETWORK_CONNECTION' in action_type:
            direction_key = ('aws/guardduty/service/action/'
                             'networkConnectionAction/connectionDirection')
            direction = logdata['ProductFields'][direction_key].lower()
        elif 'DNS_REQUEST' in action_type:
            direction = "outbound"
        else:
            direction = "inbound"
        if 'network' in logdata:
            logdata['network']['direction'] = direction
        else:
            logdata['network'] = {'direction': direction}
        if "outbound" in direction:
            logdata['source'], logdata['destination'] = (
                logdata.get('destination'), logdata.get('source'))
            if not logdata['source']:
                del logdata['source']
            if not logdata['destination']:
                del logdata['destination']
        # event.category
        if logdata['ThreatPurpose'] in ('Backdoor', 'CryptoCurrency',
                                        'Trojan'):
            logdata['event']['category'] = 'malware'
    elif 'iam access analyzer' in module:
        pass
    elif 'security hub' in module:
        logdata['__doc_id_suffix'] = int(
            datetime.fromisoformat(logdata['@timestamp']).timestamp())
        logdata['rule']['name'] = logdata['Title']
    elif 'inspector' in module:
        logdata['event']['category'] = 'package'
    elif 'macie' in module:
        logdata['event']['category'] = 'intrusion_detection'
        logdata['rule']['name'] = logdata['Title']

    resouce_dict = get_values_from_asff_resources(logdata['Resources'])
    logdata = utils.merge_dicts(logdata, resouce_dict)

    return logdata
