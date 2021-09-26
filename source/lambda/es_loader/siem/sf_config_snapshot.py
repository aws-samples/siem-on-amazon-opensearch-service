# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import datetime
import hashlib
import json


def dict_to_list(contents):
    # new_list = []
    # for key in contents:
    #    new_list.append(contents[key])
    # return new_list
    return [contents[key] for key in contents]


def convert_dict_to_list(logdata):
    # "resourceType": "AWS::S3::Bucket"
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

    # "resourceType": "AWS::SSM::ManagedInstanceInventory"
    ## AWS:Application
    try:
        logdata['configuration']['AWS:Application']['Content'] = dict_to_list(
            logdata['configuration']['AWS:Application']['Content'])
    except (IndexError, KeyError):
        pass
    ## AWS:AWSComponent
    try:
        logdata['configuration']['AWS:AWSComponent']['Content'] = dict_to_list(
            logdata['configuration']['AWS:AWSComponent']['Content'])
    except (IndexError, KeyError):
        pass
    ## AWS:ComplianceItem, Association
    try:
        logdata['configuration']['AWS:ComplianceItem']['Content']['Association'] = dict_to_list(
            logdata['configuration']['AWS:ComplianceItem']['Content']['Association'])
    except (IndexError, KeyError):
        pass
    ## AWS:ComplianceItem, Patch
    try:
        logdata['configuration']['AWS:ComplianceItem']['Content']['Patch'] = dict_to_list(
            logdata['configuration']['AWS:ComplianceItem']['Content']['Patch'])
    except (IndexError, KeyError):
        pass
    ## AWS:InstanceInformation
    try:
        logdata['configuration']['AWS:InstanceInformation']['Content'] = dict_to_list(
            logdata['configuration']['AWS:InstanceInformation']['Content'])
    except (IndexError, KeyError):
        pass
    ## AWS:Network
    try:
        logdata['configuration']['AWS:Network']['Content'] = dict_to_list(
            logdata['configuration']['AWS:Network']['Content'])
    except (IndexError, KeyError):
        pass
    ## AWS:WindowsUpdate
    try:
        logdata['configuration']['AWS:WindowsUpdate']['Content'] = dict_to_list(
            logdata['configuration']['AWS:WindowsUpdate']['Content'])
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
            new_list = []
            for item in logdata['configuration']['securityGroups']:
                new_list.append({'groupId': item})
            logdata['configuration']['securityGroups'] = new_list
    except (IndexError, KeyError):
        pass
    try:
        if isinstance(logdata['configuration']['availabilityZones'][0], str):
            new_list = []
            for item in logdata['configuration']['availabilityZones']:
                new_list.append({'zoneName': item})
            logdata['configuration']['availabilityZones'] = new_list
    except (IndexError, KeyError):
        pass
    try:
        if isinstance(logdata['configuration']['availabilityZones'][0], str):
            new_list = []
            for item in logdata['configuration']['availabilityZones']:
                new_list.append({'zoneName': item})
            logdata['configuration']['availabilityZones'] = new_list
    except (IndexError, KeyError):
        pass
    try:
        if isinstance(logdata['configuration']['subnets'][0], str):
            new_list = []
            for item in logdata['configuration']['subnets']:
                new_list.append({'subnetIdentifier': item})
            logdata['configuration']['subnets'] = new_list
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


def transform(logdata):
    doc_id_seed = logdata['awsAccountId'] + logdata['awsRegion'] \
        + logdata['resourceType'] + logdata['resourceId']
    logdata['@id'] = hashlib.md5(doc_id_seed.encode()).hexdigest()

    pubdate = datetime.datetime.fromisoformat(logdata['@timestamp'])
    logdata['__doc_id_suffix'] = (
        f'{pubdate.year}{pubdate.month}{pubdate.day}'
        f'T{pubdate.hour}{pubdate.minute}{pubdate.second}')

    logdata = convert_dict_to_list(logdata)
    logdata = rename_config_field_name(logdata)

    return logdata
