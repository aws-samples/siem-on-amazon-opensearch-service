# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.7.2-beta.2'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import hashlib
import re
from collections import namedtuple
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
    resouce_dict['_related_ip'] = []
    for resouce in resources:
        if resouce['Type'] == 'AwsEc2Instance':
            instanceid = resouce['Id'].split('/')[-1]
            resouce_dict['cloud'] = {'instance': {'id': instanceid}}
            if ('Details' in resouce
                    and 'AwsEc2Instance' in resouce['Details']):
                resouce_dict['_related_ip'] += resouce['Details'].get(
                    'AwsEc2Instance').get('IpV4Addresses', [])
                resouce_dict['_related_ip'] += resouce['Details'].get(
                    'AwsEc2Instance').get('IpV6Addresses', [])
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


def extract_related_fields(logdata):
    if not logdata.get('related'):
        logdata['related'] = {}
    instance = logdata['cloud'].get('instance', {}).get('id')
    user_id = logdata.get('user', {}).get('id')
    user_name = logdata.get('user', {}).get('name')
    if instance:
        logdata['related']['hosts'] = [instance]
    if user_id or user_name:
        logdata['related']['user'] = []
        if user_id:
            logdata['related']['user'].append(user_id)
        if user_name:
            logdata['related']['user'].append(user_name)
    if logdata.get('_related_ip'):
        if 'ip' not in logdata['related']:
            logdata['related']['ip'] = []
        logdata['related']['ip'] += logdata['_related_ip']
        logdata['related']['ip'] = list(set(logdata['related']['ip']))
        del logdata['_related_ip']
    if not logdata['related']:
        del logdata['related']
    return logdata


def transform(logdata):
    # event (ecs)
    module = (logdata['ProductFields']['aws/securityhub/ProductName']).lower()
    logdata['event']['module'] = module

    # @id / _id
    workflow = logdata['Workflow']['Status']
    if workflow == 'NEW':
        logdata['@timestamp'] = logdata['UpdatedAt'].replace('Z', '+00:00')
    logdata['__doc_id_suffix'] = hashlib.md5(
        f"{logdata['@timestamp']}{workflow}".encode()).hexdigest()

    if module in ('guardduty', 'macie'):
        findngs_type = split_findings_type(str(logdata['Types'][0]))
        logdata['ThreatPurpose'] = findngs_type.ThreatPurpose
        logdata['ResourceTypeAffected'] = findngs_type.ResourceTypeAffected
        logdata['ThreatFamilyName'] = findngs_type.ThreatFamilyName
        logdata['DetectionMechanism'] = findngs_type.DetectionMechanism
        logdata['Artifact'] = findngs_type.Artifact

    if 'security hub' in module:
        logdata['rule']['id'] = logdata['GeneratorId']
    elif 'guardduty' in module:
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
    elif 'inspector' in module:
        v1_id = logdata['ProductFields'].get('aws/inspector/id')
        if v1_id:
            logdata['rule']['name'] = v1_id
            types = logdata['Types']
        else:
            # inspector v2
            if isinstance(logdata['Types'], list):
                types = logdata['Types'][0]
            else:
                types = logdata['Types']
            try:
                types = types.split('/CVE')[0]
            except Exception:
                types = types
            if 'Vulnerabilities' in types:
                cve_id = logdata['Title'].split()[0]
                types = f"{types}/{cve_id}"
        logdata['rule']['id'] = types
        if 'Vulnerabilities' in types:
            logdata['event']['category'] = 'package'
    elif 'iam access analyzer' in module:
        pass
    elif 'systems manager patch manager' in module:
        pass
    elif 'macie' in module:
        logdata['event']['category'] = 'intrusion_detection'

    logdata['rule']['name'] = logdata['rule']['name'].strip().rstrip('.')
    resouce_dict = get_values_from_asff_resources(logdata['Resources'])
    logdata = utils.merge_dicts(logdata, resouce_dict)
    logdata = extract_related_fields(logdata)

    return logdata
