# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import datetime
import hashlib
import json


def dict_to_list(contents):
    return [v for v in contents.values()]


def update_doc_ids(logdata):
    doc_id_seed = logdata['awsAccountId'] + logdata['awsRegion'] \
        + logdata['resourceType'] + logdata['resourceId']
    logdata['@id'] = hashlib.md5(doc_id_seed.encode()).hexdigest()

    suffix_seed = logdata['event']['module'] + logdata.get('configRuleARN', '')
    suffix = hashlib.md5(suffix_seed.encode()).hexdigest()[:4]
    pubdate = datetime.datetime.fromisoformat(logdata['@timestamp'])
    logdata['__doc_id_suffix'] = (
        f'{pubdate.strftime("%Y%m%d_%H%M%S")}_{suffix}')

    return logdata


def convert_dict_to_list(logdata):
    if logdata['resourceType'] == 'AWS::S3::Bucket':
        try:
            logdata['supplementaryConfiguration']['BucketNotificationConfiguration']['configurations'] = dict_to_list(
                logdata['supplementaryConfiguration']['BucketNotificationConfiguration']['configurations'])
        except (IndexError, KeyError):
            pass
        try:
            logdata['supplementaryConfiguration']['BucketReplicationConfiguration']['rules'] = dict_to_list(
                logdata['supplementaryConfiguration']['BucketReplicationConfiguration']['rules'])
        except (IndexError, KeyError):
            pass

    elif logdata['resourceType'] == 'AWS::SSM::ManagedInstanceInventory':
        # AWS:Application
        try:
            logdata['configuration']['AWS:Application']['Content'] = dict_to_list(
                logdata['configuration']['AWS:Application']['Content'])
        except (IndexError, KeyError):
            pass
        # AWS:AWSComponent
        try:
            logdata['configuration']['AWS:AWSComponent']['Content'] = dict_to_list(
                logdata['configuration']['AWS:AWSComponent']['Content'])
        except (IndexError, KeyError):
            pass
        # AWS:InstanceInformation
        try:
            logdata['configuration']['AWS:InstanceInformation']['Content'] = dict_to_list(
                logdata['configuration']['AWS:InstanceInformation']['Content'])
        except (IndexError, KeyError):
            pass
        # AWS:Network
        try:
            logdata['configuration']['AWS:Network']['Content'] = dict_to_list(
                logdata['configuration']['AWS:Network']['Content'])
        except (IndexError, KeyError):
            pass
        # AWS:WindowsUpdate
        try:
            logdata['configuration']['AWS:WindowsUpdate']['Content'] = dict_to_list(
                logdata['configuration']['AWS:WindowsUpdate']['Content'])
        except (IndexError, KeyError):
            pass

    elif logdata['resourceType'] in (
            'AWS::SSM::PatchCompliance', 'AWS::SSM::AssociationCompliance'):
        # AWS:ComplianceItem, Association
        try:
            logdata['configuration']['AWS:ComplianceItem']['Content']['Association'] = dict_to_list(
                logdata['configuration']['AWS:ComplianceItem']['Content']['Association'])
        except (IndexError, KeyError):
            pass
        # AWS:ComplianceItem, Patch
        try:
            logdata['configuration']['AWS:ComplianceItem']['Content']['Patch'] = dict_to_list(
                logdata['configuration']['AWS:ComplianceItem']['Content']['Patch'])
        except (IndexError, KeyError):
            pass

    return logdata


def rename_config_field_name(logdata):
    # "resourceType": "AWS::S3::Bucket"
    try:
        logdata['configuration']['owner_id'] = (
            logdata['configuration']['owner'].pop('id'))
    except (AttributeError, KeyError, TypeError):
        pass

    # "resourceType": "AWS::EC2::Instance"
    try:
        logdata['configuration']['state_code'] = (
            logdata['configuration']['state'].pop('code'))
    except (AttributeError, KeyError, TypeError):
        pass
    try:
        logdata['configuration']['state_name'] = (
            logdata['configuration']['state'].pop('name'))
    except (AttributeError, KeyError, TypeError):
        pass
    try:
        logdata['tags']['AmazonFSx_FileSystemId'] = (
            logdata['tags'].pop('AmazonFSx.FileSystemId'))
    except Exception:
        pass

    # "resourceType": "AWS::Lambda::Function"
    try:
        if isinstance(logdata['configuration']['stateReason'], str):
            logdata['configuration']['stateReason'] = {
                'message': logdata['configuration']['stateReason']}
            logdata['configuration']['stateReason']['code'] = (
                logdata['configuration'].pop('stateReasonCode'))
    except (AttributeError, KeyError, TypeError):
        pass

    # "resourceType": "AWS::ElasticLoadBalancing::LoadBalancer"
    try:
        if isinstance(logdata['configuration']['securityGroups'][0], str):
            logdata['configuration']['securityGroups'] = [
                {'groupId': item} for item in logdata['configuration']['securityGroups']]

    except (IndexError, KeyError):
        pass
    try:
        if isinstance(logdata['configuration']['availabilityZones'][0], str):
            logdata['configuration']['availabilityZones'] = [
                {'zoneName': item} for item in logdata['configuration']['availabilityZones']]
    except (IndexError, KeyError):
        pass
    try:
        if isinstance(logdata['configuration']['subnets'][0], str):
            logdata['configuration']['subnets'] = [
                {'subnetIdentifier': item} for item in logdata['configuration']['subnets']]
    except (IndexError, KeyError):
        pass

    # "resourceType": "AWS::RDS::DBCluster"
    # "resourceType": "AWS::Elasticsearch::Domain"
    try:
        if isinstance(logdata['configuration']['endpoint'], str):
            logdata['configuration']['endpoint'] = {
                'address': logdata['configuration']['endpoint']}
    except (AttributeError, KeyError, TypeError):
        pass

    # "resourceType": "AWS::AutoScaling::LaunchConfiguration"
    try:
        if isinstance(logdata['configuration']['iamInstanceProfile'], str):
            logdata['configuration']['iamInstanceProfile'] = {
                'arn': logdata['configuration']['iamInstanceProfile']}
    except (AttributeError, KeyError, TypeError):
        pass

    # "resourceType": "AWS::WAFv2::WebACL"
    try:
        if isinstance(logdata['configuration']['rules'][0]['statement'], dict):
            new_list = []
            for item in logdata['configuration']['rules']:
                item['statement'] = json.dumps(item['statement'])
                new_list.append(item)
            logdata['configuration']["rules"] = new_list
    except (IndexError, KeyError):
        pass

    # "resourceType": "AWS::EC2::VPCPeeringConnection"
    try:
        logdata['configuration']['status_message'] = (
            logdata['configuration']['status'].pop('message'))
        logdata['configuration']['status'] = (
            logdata['configuration']['status'].pop('code'))
    except (AttributeError, KeyError, TypeError):
        pass

    return logdata


def extract_ip_from_nic(private_ip_addresses):
    ips = []
    for nic in private_ip_addresses:
        ips.append(nic['privateIpAddress'])
        public_ip = nic.get('association', {}).get('publicIp')
        if public_ip:
            ips.append(public_ip)
    return ips


# required field: resourceId, resourceType
def extract_host(logdata):
    if logdata['resourceType'] in (
            'AWS::EC2::Instance', 'AWS::SSM::ManagedInstanceInventory'):
        logdata['cloud']['instance'] = {'id': logdata['resourceId']}
    elif logdata['resourceType'] == 'AWS::Config::ResourceCompliance':
        target = logdata['resourceId'].split('/')
        if len(target) == 2:
            target_type, target_id = target
            if target_type in ('AWS::EC2::Instance'):
                logdata['user'] = {'id': target_id}
    elif (logdata['resourceType'] in
            ('AWS::SSM::AssociationCompliance', 'AWS::SSM::PatchCompliance')):
        logdata['cloud']['instance'] = {
            'id': logdata['resourceId'].split('/')[-1]}

    if 'instance' in logdata['cloud']:
        if 'related' not in logdata:
            logdata['related'] = {}
        logdata['related']['hosts'] = [logdata['cloud']['instance']['id'], ]

    return logdata


def extract_user(logdata):
    if logdata['resourceType'] in ('AWS::IAM::User', 'AWS::IAM::Role'):
        logdata['user'] = {'id': logdata['resourceId'],
                           'name': logdata.get('resourceName', '')}
    elif logdata['resourceType'] in ('AWS::Config::ResourceCompliance'):
        target = logdata['resourceId'].split('/')
        if len(target) == 2:
            target_type, target_id = target
            if target_type in ('AWS::IAM::Role', 'AWS::IAM::User'):
                logdata['user'] = {'id': target_id}

    if logdata.get('user'):
        if 'related' not in logdata:
            logdata['related'] = {}
        logdata['related']['user'] = []
        if logdata['user'].get('name'):
            logdata['related']['user'].append(logdata['user']['name'])
        if logdata['user'].get('id'):
            logdata['related']['user'].append(logdata['user']['id'])

    return logdata


def extract_ip(logdata):
    configuration = logdata.get('configuration')
    if not configuration:
        return logdata

    private_ip = ''
    public_ip = ''
    ip_list = []
    if logdata['resourceType'] in ('AWS::EC2::EIP'):
        public_ip = logdata['resourceName']
        private_ip = configuration.get('privateIpAddress')
    elif logdata['resourceType'] == 'AWS::EC2::Instance':
        for eni in logdata['configuration']['networkInterfaces']:
            ip_list.extend(extract_ip_from_nic(eni['privateIpAddresses']))
    elif logdata['resourceType'] == 'AWS::EC2::NetworkInterface':
        ip_list = extract_ip_from_nic(
            logdata['configuration']['privateIpAddresses'])
    elif logdata['resourceType'] == 'AWS::EC2::NatGateway':
        private_ip = configuration['natGatewayAddresses'][0].get('publicIp', '')
        public_ip = configuration['natGatewayAddresses'][0].get('privateIp', '')
    elif logdata['resourceType'] == 'AWS::SSM::ManagedInstanceInventory':
        contents = configuration.get('AWS:Network', {}).get('Content')
        if contents:
            for content in contents:
                ip_list.append(content['IPV6'])
                ip_list.append(content['IPV4'])

    if private_ip or public_ip or len(ip_list):
        if 'related' not in logdata:
            logdata['related'] = {}
        logdata['related']['ip'] = []
        if private_ip:
            logdata['related']['ip'].append(private_ip)
        if public_ip:
            logdata['related']['ip'].append(public_ip)
        if len(ip_list):
            logdata['related']['ip'].extend(ip_list)

    return logdata


def transform(logdata):
    logdata = update_doc_ids(logdata)
    logdata = convert_dict_to_list(logdata)
    logdata = rename_config_field_name(logdata)
    logdata = extract_host(logdata)
    logdata = extract_user(logdata)
    logdata = extract_ip(logdata)

    return logdata
