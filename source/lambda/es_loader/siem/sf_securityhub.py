# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
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
    resource_dict = {}
    resource_dict['_related_ip'] = []
    for resource in resources:
        if resource['Type'] == 'AwsEc2Instance':
            instanceid = resource['Id'].split('/')[-1]
            resource_dict['cloud'] = {'instance': {'id': instanceid}}
            if ('Details' in resource
                    and 'AwsEc2Instance' in resource['Details']):
                resource_dict['_related_ip'] += resource['Details'].get(
                    'AwsEc2Instance').get('IpV4Addresses', [])
                resource_dict['_related_ip'] += resource['Details'].get(
                    'AwsEc2Instance').get('IpV6Addresses', [])
        elif resource['Type'] == 'AwsIamAccessKey':
            accesskey = resource['Id'].split(':')[-1]
            if accesskey == 'null':
                accesskey = (resource['Details']['AwsIamAccessKey']
                             ['PrincipalId']).split(':')[0]
            name = resource['Details']['AwsIamAccessKey']['PrincipalName']
            resource_dict['user'] = {'id': accesskey, 'name': name}
        elif resource['Type'] == 'AwsEc2Volume':
            try:
                instanceid = (resource['Details']['AwsEc2Volume']
                              ['Attachments'][0]['InstanceId'])
            except Exception:
                continue
            resource_dict['cloud'] = {'instance': {'id': instanceid}}
        elif resource['Type'] == 'AwsIamRole':
            name = resource['Id'].split('/')[-1]
            resource_dict['user'] = {'name': name}
        elif resource['Type'] == 'AwsS3Bucket':
            pass
        elif resource['Type'] == 'AwsEksCluster':
            pass

    return resource_dict


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

        try:
            action_type = (logdata['ProductFields']
                           ['aws/guardduty/service/action/actionType'])
        except Exception:
            action_type = ''
        if action_type == 'NETWORK_CONNECTION':
            direction_key = ('aws/guardduty/service/action/'
                             'networkConnectionAction/connectionDirection')
            direction = logdata['ProductFields'][direction_key].lower()
        elif action_type == 'DNS_REQUEST':
            direction = "outbound"
        elif logdata['ThreatFamilyName'] in ('SuspiciousFile',
                                             'MaliciousFile'):
            direction = None
        else:
            direction = "inbound"
        if direction:
            if 'network' in logdata:
                logdata['network']['direction'] = direction.lower()
            else:
                logdata['network'] = {'direction': direction.lower()}
        if direction == "outbound":
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
        elif logdata['ThreatFamilyName'] in ('SuspiciousFile',
                                             'MaliciousFile'):
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
    resource_dict = get_values_from_asff_resources(logdata['Resources'])
    logdata = utils.merge_dicts(logdata, resource_dict)
    logdata = extract_related_fields(logdata)

    return logdata
