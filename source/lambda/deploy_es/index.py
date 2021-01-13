#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import configparser
import json
import os
import string
import secrets
import time
import urllib.request
import urllib.parse
import urllib.error
from datetime import date, datetime

import requests
import boto3
from requests_aws4auth import AWS4Auth

__version__ = '2.2.0-beta.2'
print('version: ' + __version__)

client = boto3.client('es')

accountid = os.environ['accountid']
region = os.environ['AWS_REGION']
aesdomain = os.environ['aes_domain_name']
myaddress = os.environ['allow_source_address'].split()
aes_admin_role = os.environ['aes_admin_role']
es_loader_role = os.environ['es_loader_role']
myiamarn = [accountid]
kibanaadmin = 'aesadmin'
vpc_subnet_id = os.environ['vpc_subnet_id']
if vpc_subnet_id == 'None':
    vpc_subnet_id = None
security_group_id = os.environ['security_group_id']

access_policies = {
  'Version': '2012-10-17',
  'Statement': [
    {
      'Effect': 'Allow',
      'Principal': {'AWS': myiamarn},
      'Action': ['es:*'],
      'Resource': f'arn:aws:es:{region}:{accountid}:domain/{aesdomain}/*'
    },
    {
      'Effect': 'Allow',
      'Principal': {'AWS': '*'},
      'Action': ['es:*'],
      'Condition': {'IpAddress': {'aws:SourceIp': myaddress}},
      'Resource': f'arn:aws:es:{region}:{accountid}:domain/{aesdomain}/*'
    }
  ]
}
if vpc_subnet_id:
    access_policies['Statement'][0]['Principal'] = {'AWS': '*'}
    del access_policies['Statement'][1]
access_policies_json = json.dumps(access_policies)

config_domain = {
    'DomainName': aesdomain,
    'ElasticsearchVersion': '7.9',
    'ElasticsearchClusterConfig': {
        'InstanceType': 't3.small.elasticsearch',
        'InstanceCount': 1,
        'DedicatedMasterEnabled': False,
        'ZoneAwarenessEnabled': False,
        # 'ZoneAwarenessConfig': {
        #     'AvailabilityZoneCount': 123
        # },
        # 'DedicatedMasterType': 'c5.large.elasticsearch',
        # 'DedicatedMasterCount': 123,
        'WarmEnabled': False,
        # 'WarmType': 'ultrawarm1.medium.elasticsearch',
        # 'WarmCount': 123
    },
    'EBSOptions': {
        'EBSEnabled': True,
        'VolumeType': 'gp2',
        'VolumeSize': 10,
    },
    'AccessPolicies': access_policies_json,
    'SnapshotOptions': {
        'AutomatedSnapshotStartHour': 16
    },
    # VPCOptions={
    #     'SubnetIds': [
    #         'string',
    #     ],
    #     'SecurityGroupIds': [
    #         'string',
    #     ]
    # },
    # CognitoOptions={
    #     'Enabled': True|False,
    #     'UserPoolId': 'string',
    #     'IdentityPoolId': 'string',
    #     'RoleArn': 'string'
    # },
    'EncryptionAtRestOptions': {
        'Enabled': True,
        # 'KmsKeyId': 'string'
    },
    'NodeToNodeEncryptionOptions': {
        'Enabled': True
    },
    # AdvancedOptions={
    #     'string': 'string'
    # },
    # LogPublishingOptions={
    #     'string': {
    #         'CloudWatchLogsLogGroupArn': 'string',
    #         'Enabled': True|False
    #     }
    # },
    'DomainEndpointOptions': {
        'EnforceHTTPS': True,
        'TLSSecurityPolicy': 'Policy-Min-TLS-1-2-2019-07'
    },
    'AdvancedSecurityOptions': {
        'Enabled': True,
        'InternalUserDatabaseEnabled': False,
        'MasterUserOptions': {
            'MasterUserARN': aes_admin_role,
            # 'MasterUserName': kibanaadmin,
            # 'MasterUserPassword': kibanapass
        }
    }
}
if vpc_subnet_id:
    config_domain['VPCOptions'] = {'SubnetIds': [vpc_subnet_id, ],
                                   'SecurityGroupIds': [security_group_id, ]}


def create_es():
    response = client.create_elasticsearch_domain(**config_domain)
    return response


def make_password(length):
    chars = string.ascii_letters + string.digits + '%&$#@'
    while True:
        password = ''.join(secrets.choice(chars) for i in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password)
                and sum(not c.isalnum() for c in password)):
            break
    return(password)


def create_kibanaadmin(kibanapass):
    response = client.update_elasticsearch_domain_config(
        DomainName=aesdomain,
        AdvancedSecurityOptions={
            # 'Enabled': True,
            'InternalUserDatabaseEnabled': True,
            'MasterUserOptions': {
                'MasterUserName': kibanaadmin,
                'MasterUserPassword': kibanapass
            }
        }
    )
    return response


def auth_aes(es_endpoint):
    service = 'es'
    credentials = boto3.Session().get_credentials()
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, region,
                       service, session_token=credentials.token)
    return awsauth


def query_aes(es_endpoint, awsauth, method=None, path=None, payload=None,
              headers=None):
    if not headers:
        headers = {'Content-Type': 'application/json'}
    url = 'https://' + es_endpoint + '/' + path
    if method.lower() == 'get':
        res = requests.get(url, auth=awsauth, stream=True)
    elif method.lower() == 'post':
        res = requests.post(url, auth=awsauth, json=payload, headers=headers)
    elif method.lower() == 'put':
        res = requests.put(url, auth=awsauth, json=payload, headers=headers)
    elif method.lower() == 'patch':
        res = requests.put(url, auth=awsauth, json=payload, headers=headers)
    return(res)


def output_message(key, res):
    return(f'  {key}: status={res.status_code}, message={res.text}')


def upsert_role_mapping(es_endpoint, role_name, es_app_data=None,
                        added_user=None, added_role=None, added_host=None):
    awsauth = auth_aes(es_endpoint)
    path = '_opendistro/_security/api/rolesmapping/' + role_name
    res = query_aes(es_endpoint, awsauth, 'GET', path)
    print(res.status_code)
    if res.status_code == 404:
        # create role
        path_roles = '_opendistro/_security/api/roles/' + role_name
        payload = json.loads(es_app_data['security']['role_es_loader'])
        print(json.dumps(payload, default=json_serial))
        res_new = query_aes(es_endpoint, awsauth, 'PATCH', path_roles, payload)
        print(output_message('Created' + role_name, res_new))
        time.sleep(3)
        # role mapping for new role
        payload = {'backend_roles': [es_loader_role, ]}
        res = query_aes(es_endpoint, awsauth, 'PATCH', path, payload)
        print(output_message('Mapping' + role_name, res))
        return True
    res_json = json.loads(res.text)
    print(res_json)
    current_conf = res_json[role_name]
    need_updating = 0
    if added_user and (added_user not in current_conf['users']):
        current_conf['users'].append(added_user)
        current_conf['users'] = list(sorted(set(current_conf['users'])))
        need_updating += 1
    if added_role and (added_role not in current_conf['backend_roles']):
        current_conf['backend_roles'].append(added_role)
        current_conf['backend_roles'] = list(
            sorted(set(current_conf['backend_roles'])))
        need_updating += 1
    if added_host and (added_host in current_conf['hosts']):
        current_conf['hosts'].append(added_host)
        current_conf['hosts'] = list(sorted(set(current_conf['hosts'])))
        need_updating += 1
    if need_updating:
        if 'hidden' in current_conf:
            del current_conf['hidden']
        if 'reserved' in current_conf:
            del current_conf['reserved']
        print(json.dumps(current_conf))
        res = query_aes(es_endpoint, awsauth, 'PATCH', path, current_conf)
        print(output_message('Mapping' + role_name, res))
    else:
        print("no update opendistro's role mapping")


def configure_opendistro(es_endpoint, es_app_data):
    upsert_role_mapping(es_endpoint, 'all_access',
                        added_user=kibanaadmin, added_role=aes_admin_role)
    upsert_role_mapping(es_endpoint, 'security_manager',
                        added_user=kibanaadmin, added_role=aes_admin_role)
    upsert_role_mapping(es_endpoint, 'aws_log_loader', es_app_data=es_app_data,
                        added_role=es_loader_role)


def configure_siem(es_endpoint, es_app_data):
    print('Import kibana index patterns')
    awsauth = auth_aes(es_endpoint)
    # create index-template
    index_patterns = es_app_data['index-template']
    for key in index_patterns:
        payload = json.loads(index_patterns[key])
        path = f'_template/{key}'
        res = query_aes(es_endpoint, awsauth, 'PUT', path, payload)
        print(output_message(key, res))


def configure_index_rollover(es_endpoint, es_app_data):
    awsauth = auth_aes(es_endpoint)
    print('start to create IM policy for rollover')
    payload = {'policy': {
        'description': 'rollover by 100gb',
        'default_state': 'rollover',
        'states': [{'name': 'rollover',
                    'actions': [{'rollover': {'min_size': '100gb'}}],
                    'transitions': []}]}}
    path = '_opendistro/_ism/policies/rollover100gb'
    res = query_aes(es_endpoint, awsauth, 'PUT', path, payload)
    print(res)
    # create intex-template for index rollover
    index_patterns = es_app_data['index-rollover']
    for key in index_patterns:
        # create index template for rollover
        payload = json.loads(index_patterns[key])
        path = f'_template/{key}'
        res = query_aes(es_endpoint, awsauth, 'PUT', path, payload)
        print(output_message(key, res))
    # wait to create rollover policy
    time.sleep(10)
    for key in index_patterns:
        # create initial index 000001
        idx = key.replace('_rollover', '-000001')
        alias = key.replace('_rollover', '')
        payload = {'aliases': {alias: {}}}
        res = query_aes(es_endpoint, awsauth, 'PUT', idx, payload)
        print(output_message(idx, res))


def json_serial(obj):
    # for debug to dump various json
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    try:
        return repr(obj)
    except Exception:
        raise TypeError(f'Type {type(obj)} not serializable')


def send(event, context, responseStatus, responseData, physicalResourceId=None,
         noEcho=False):
    # https://docs.aws.amazon.com/ja_jp/AWSCloudFormation/latest/UserGuide/cfn-lambda-function-code-cfnresponsemodule.html
    responseUrl = event['ResponseURL']
    print('Debug: resonponse URL')
    print(responseUrl)

    response_body = {}
    response_body['Status'] = responseStatus
    response_body['Reason'] = ('See the details in CloudWatch Log Stream: '
                               '' + context.log_stream_name)
    response_body['PhysicalResourceId'] = (
        physicalResourceId or context.log_stream_name)
    response_body['StackId'] = event['StackId']
    response_body['RequestId'] = event['RequestId']
    response_body['LogicalResourceId'] = event['LogicalResourceId']
    response_body['NoEcho'] = noEcho
    response_body['Data'] = responseData

    print('DEBUG: ' + str(response_body))
    json_response_body = json.dumps(response_body, default=json_serial)

    print('Response body:\n' + json_response_body)

    headers = {'content-type': 'application/json', }
    req = urllib.request.Request(
        event['ResponseURL'], json_response_body.encode(),
        headers=headers, method='PUT')
    try:
        res = urllib.request.urlopen(req)
        print('Status code: ' + str(res.status))
    except Exception as e:
        print('send(..) failed executing requests.put(..): ' + str(e))


def initial_event_check_and_exit(event, context, physicalResourceId):
    if event:
        print('Debug: Recieved event')
        print(json.dumps(event, default=json_serial))
    if event and 'RequestType' in event and 'Delete' in event['RequestType']:
        # Response For CloudFormation Custome Resource
        response = {}
        send(event, context, 'SUCCESS', response, physicalResourceId)
        return(json.dumps(response, default=json_serial))


def aes_domain_handler(event=None, context=None):
    physicalResourceId = 'aes_domain'
    initial_event_check_and_exit(event, context, physicalResourceId)
    global kibanaadmin
    kibanaadmin = kibanaadmin
    kibanapass = 'MASKED'
    try:
        domain_exist = True
        while domain_exist:
            response = create_es()
            print('Creating domain is processing')
            time.sleep(60)
            print(json.dumps(response, default=json_serial))
            domain_exist = response['DomainStatus']['Processing']
        print('AES Domain is created')

        userdb_enabled = (response['DomainStatus']['AdvancedSecurityOptions']
                          ['InternalUserDatabaseEnabled'])
        if not userdb_enabled:
            kibanapass = make_password(8)
            print(f'ID: {kibanaadmin}, PASSWORD: {kibanapass}')
            update_response = create_kibanaadmin(kibanapass)
            print('Updating configuration is processing')
            while not userdb_enabled:
                userdb_enabled = (update_response['DomainConfig']
                                  ['AdvancedSecurityOptions']
                                  ['Options']['InternalUserDatabaseEnabled'])
                time.sleep(3)
        es_endpoint = None
        # print(json.dumps(response, default=json_serial))
        while not es_endpoint:
            # wait to finish setup of endpoint
            time.sleep(20)
            response = client.describe_elasticsearch_domain(
                DomainName=aesdomain)
            es_endpoint = response['DomainStatus'].get('Endpoint')
            if not es_endpoint and 'Endpoints' in response['DomainStatus']:
                es_endpoint = response['DomainStatus']['Endpoints']['vpc']
    except Exception as e:
        print('Exception occured: ' + str(e))
        response = {'failed_reason': e}
        if event and 'RequestType' in event:
            send(event, context, 'FAILED', response, physicalResourceId)
            return(json.dumps(response))

    if event and 'RequestType' in event:
        # Response For CloudFormation Custome Resource
        response = {'physicalResourceId': physicalResourceId,
                    'es_endpoint': es_endpoint, 'kibanaadmin': kibanaadmin,
                    'kibanapass': kibanapass}
        send(event, context, 'SUCCESS', response, physicalResourceId)
        return(json.dumps(response))


def aes_config_handler(event=None, context=None):
    physicalResourceId = 'aes_config'
    initial_event_check_and_exit(event, context, physicalResourceId)
    es_app_data = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    es_app_data.read('data.ini')
    es_endpoint = os.environ['es_endpoint']

    try:
        # for debug
        # print(json.dumps(es_endpoint, default=json_serial))
        configure_opendistro(es_endpoint, es_app_data)
        configure_siem(es_endpoint, es_app_data)
        configure_index_rollover(es_endpoint, es_app_data)
    except Exception as e:
        print('Exception occured: ' + str(e))
        response = {'failed_reason': e}
        if event and 'RequestType' in event:
            send(event, context, 'FAILED', response, physicalResourceId)

    if event and 'RequestType' in event:
        # Response For CloudFormation Custome Resource
        response = {'physicalResourceId': physicalResourceId}
        send(event, context, 'SUCCESS', response, physicalResourceId)
        return(json.dumps(response, default=json_serial))


if __name__ == '__main__':
    aes_domain_handler()
    aes_config_handler()
