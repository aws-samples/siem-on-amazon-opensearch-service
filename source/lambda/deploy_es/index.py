#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.3-beta.3'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


import configparser
import json
import logging
import os
import pathlib
import secrets
import string
import time
from datetime import date, datetime
from zipfile import ZIP_DEFLATED, ZipFile

import boto3
import botocore
import requests
from crhelper import CfnResource
from opensearchpy import AWSV4SignerAuth

from aoss import MyAoss

print(f'version: {__version__}')
print(f'boto3: {boto3.__version__}')

logger = logging.getLogger(__name__)
helper_validation = CfnResource(json_logging=False, log_level='DEBUG',
                                boto_level='CRITICAL', sleep_on_delete=3)
helper_domain = CfnResource(json_logging=False, log_level='DEBUG',
                            boto_level='CRITICAL', sleep_on_delete=3)
helper_config = CfnResource(json_logging=False, log_level='DEBUG',
                            boto_level='CRITICAL', sleep_on_delete=3)

iam_client = boto3.client('iam')
s3_client = boto3.resource('s3')
ec2_client = boto3.client('ec2')
opensearch_client = boto3.client('opensearch')
ssm_client = boto3.client('ssm')
try:
    serverless_client = boto3.client('opensearchserverless')
except Exception as err:
    serverless_client = None
    logger.info('OpenSearch Serverless API is not supported')
    logger.debug(err)

ACCOUNT_ID = os.environ['ACCOUNT_ID']
REGION = os.environ['AWS_REGION']
try:
    PARTITION = boto3.Session().get_partition_for_region(REGION)
except Exception as e:
    logger.info(e)
    PARTITION = boto3.Session().get_partition_for_region('us-east-1')
DEPLOYMENT_TARGET = os.getenv(
    'DEPLOYMENT_TARGET', 'opensearch_managed_cluster')
# opensearch_managed_cluster or opensearch_serverless
AOS_SUBNET_IDS = os.getenv('AOS_SUBNET_IDS')
VPCE_ID = os.getenv('VPCE_ID')
ENDPOINT = os.getenv('ENDPOINT', '')
DOMAIN_OR_COLLECTION_NAME = os.getenv('DOMAIN_OR_COLLECTION_NAME')

SOLUTION_PREFIX = os.getenv('SOLUTION_PREFIX')
if SOLUTION_PREFIX != 'aes-siem':
    AOS_DOMAIN = SOLUTION_PREFIX
else:
    AOS_DOMAIN = DOMAIN_OR_COLLECTION_NAME
ALLOWED_SOURCE_ADDRESSES = os.getenv('ALLOWED_SOURCE_ADDRESSES', '').split()
ROLE_AOS_ADMIN = os.getenv('ROLE_AOS_ADMIN')
ROLE_ES_LOADER = os.getenv('ROLE_ES_LOADER')
ROLE_METRICS_EXPORTER = os.getenv('ROLE_METRICS_EXPORTER')
ROLE_SNAPSHOT = os.getenv('ROLE_SNAPSHOT')
KIBANAADMIN = 'aesadmin'
KIBANA_HEADERS = {'Content-Type': 'application/json', 'kbn-xsrf': 'true'}
DASHBOARDS_HEADERS = {'Content-Type': 'application/json', 'osd-xsrf': 'true'}
RESTAPI_HEADERS = {'Content-Type': 'application/json'}
AOS_SECURITY_GROUP_ID = os.getenv('AOS_SECURITY_GROUP_ID')
S3_SNAPSHOT = os.getenv('S3_SNAPSHOT')
S3_LOG = os.getenv('S3_LOG')
LOGGROUP_RETENTIONS = [
    (f'/aws/OpenSearchService/domains/{AOS_DOMAIN}/application-logs', 14),
    ('/aws/lambda/aes-siem-add-pandas-layer', 180),
    ('/aws/lambda/aes-siem-configure-aes', 180),
    ('/aws/lambda/aes-siem-deploy-aes', 180),
    ('/aws/lambda/aes-siem-es-loader', 90),
    ('/aws/lambda/aes-siem-geoip-downloader', 90),
    ('/aws/lambda/aes-siem-index-metrics-exporter', 90),
    ('/aws/lambda/aes-siem-ioc-createdb', 90),
    ('/aws/lambda/aes-siem-ioc-download', 90),
    ('/aws/lambda/aes-siem-ioc-plan', 90),
    ('/aws/lambda/aes-siem-resource-validator', 180),
]
if ENDPOINT:
    AOS_SERVICE = ENDPOINT.split('.')[2]
elif DEPLOYMENT_TARGET == 'opensearch_managed_cluster':
    AOS_SERVICE = 'es'
elif DEPLOYMENT_TARGET == 'opensearch_serverless':
    AOS_SERVICE = 'aoss'
else:
    AOS_SERVICE = ''


es_loader_ec2_role = (
    f'arn:{PARTITION}:iam::{ACCOUNT_ID}:role/aes-siem-es-loader-for-ec2')

cwl_resource_policy = {
    'Version': "2012-10-17",
    'Statement': [
        {
            'Effect': 'Allow',
            'Principal': {'Service': "opensearchservice.amazonaws.com"},
            "Action": [
                'logs:PutLogEvents',
                'logs:CreateLogStream',
                'logs:CreateLogGroup'
            ],
            'Resource': [
                (f'arn:{PARTITION}:logs:{REGION}:{ACCOUNT_ID}:log-group:/aws/'
                 f'OpenSearchService/domains/{AOS_DOMAIN}/*'),
                (f'arn:{PARTITION}:logs:{REGION}:{ACCOUNT_ID}:log-group:/aws/'
                 f'OpenSearchService/domains/{AOS_DOMAIN}/*:*'),
            ]
        }
    ]
}

access_policies = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Principal': {'AWS': [ACCOUNT_ID]},
            'Action': ['es:*'],
            'Resource': (f'arn:{PARTITION}:es:{REGION}:{ACCOUNT_ID}'
                         f':domain/{AOS_DOMAIN}/*')
        },
        {
            'Effect': 'Allow',
            'Principal': {'AWS': '*'},
            'Action': ['es:*'],
            'Condition': {
                'IpAddress': {'aws:SourceIp': ALLOWED_SOURCE_ADDRESSES}},
            'Resource': (f'arn:{PARTITION}:es:{REGION}:{ACCOUNT_ID}'
                         f':domain/{AOS_DOMAIN}/*')
        }
    ]
}
if AOS_SUBNET_IDS:
    access_policies['Statement'][0]['Principal'] = {'AWS': '*'}
    del access_policies['Statement'][1]
access_policies_json = json.dumps(access_policies)

config_domain = {
    'DomainName': AOS_DOMAIN,
    'EngineVersion': 'OpenSearch_2.11',
    'ClusterConfig': {
        'InstanceType': 't3.medium.search',
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
        # 'VolumeType': 'gp2',
        'VolumeSize': 10,
    },
    'AccessPolicies': access_policies_json,
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
    'AdvancedOptions': {
        "override_main_response_version": "true"
    },
    'LogPublishingOptions': {
        'ES_APPLICATION_LOGS': {
            'CloudWatchLogsLogGroupArn': (
                f'arn:{PARTITION}:logs:{REGION}:{ACCOUNT_ID}:log-group:/aws/'
                f'OpenSearchService/domains/{AOS_DOMAIN}/application-logs'),
            'Enabled': True
        }
    },
    'DomainEndpointOptions': {
        'EnforceHTTPS': True,
        'TLSSecurityPolicy': 'Policy-Min-TLS-1-2-2019-07'
    },
    'AdvancedSecurityOptions': {
        'Enabled': True,
        'InternalUserDatabaseEnabled': False,
        'MasterUserOptions': {
            'MasterUserARN': ROLE_AOS_ADMIN,
            # 'MasterUserName': kibanaadmin,
            # 'MasterUserPassword': kibanapass
        }
    }
}
if AOS_SUBNET_IDS:
    config_domain['VPCOptions'] = {'SubnetIds': [AOS_SUBNET_IDS.split(',')[0]],
                                   'SecurityGroupIds': [AOS_SECURITY_GROUP_ID]}

if REGION == 'ap-northeast-3':
    config_domain['ClusterConfig']['InstanceType'] = 'r5.large.search'

if S3_SNAPSHOT:
    s3_snapshot_bucket = s3_client.Bucket(S3_SNAPSHOT)


def make_password(length):
    chars = string.ascii_letters + string.digits + '%&$#@'
    while True:
        password = ''.join(secrets.choice(chars) for i in range(length))
        if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password)
                and sum(not c.isalnum() for c in password)):
            break
    return password


def create_kibanaadmin(kibanapass):
    response = opensearch_client.update_domain_config(
        DomainName=AOS_DOMAIN,
        AdvancedSecurityOptions={
            # 'Enabled': True,
            'InternalUserDatabaseEnabled': True,
            'MasterUserOptions': {
                'MasterUserName': KIBANAADMIN,
                'MasterUserPassword': kibanapass
            }
        }
    )
    return response


def auth_aes():
    credentials = boto3.Session().get_credentials()
    awsauth = AWSV4SignerAuth(credentials, REGION, AOS_SERVICE)

    return awsauth


def output_message(key, res):
    return f'{key}: status={res.status_code}, message={res.text}'


def get_dist_version():
    logger.debug('start get_dist_version')
    if AOS_SERVICE == 'aoss':
        dist_name = 'opensearch'
        domain_version = 'serverless'
        return dist_name, domain_version
    awsauth = auth_aes()

    res = requests.get(f'https://{ENDPOINT}/', auth=awsauth, stream=True)
    logger.info(res.text)

    version = json.loads(res.text)['version']
    domain_version = version['number']
    lucene_version = version['lucene_version']
    dist_name = version.get('distribution', 'elasticsearch')
    if domain_version == '7.10.2' and lucene_version != '8.7.0':
        dist_name = 'opensearch'
    return dist_name, domain_version


def upsert_role_mapping(dist_name, role_name, es_app_data=None,
                        added_user=None, added_role=None, added_host=None):
    if AOS_SERVICE == 'aoss':
        return

    awsauth = auth_aes()
    if dist_name == 'opensearch':
        base_url = f'https://{ENDPOINT}/_plugins/'
    else:
        base_url = f'https://{ENDPOINT}/_opendistro/'
    logger.info(f'role_name: {role_name}')
    res = requests.get(
        url=f'{base_url}_security/api/rolesmapping/{role_name}',
        auth=awsauth, stream=True)

    if res.status_code == 404:
        logger.info('Create new role/mapping')

        # create role
        payload = json.loads(es_app_data['security']['role_es_loader'])
        logger.debug(json.dumps(payload, default=json_serial))
        res_new = requests.put(
            url=f'{base_url}_security/api/roles/{role_name}',
            auth=awsauth, json=payload, headers=RESTAPI_HEADERS)
        logger.info(output_message(f'role_{role_name}', res_new))

        time.sleep(3)

        # role mapping for new role
        payload = {'backend_roles': [ROLE_ES_LOADER, ]}
        res = requests.put(
            url=f'{base_url}_security/api/rolesmapping/{role_name}',
            auth=awsauth, json=payload, headers=RESTAPI_HEADERS)
        logger.info(output_message(f'role_mapping_{role_name}', res))
        return True

    elif (res.status_code == 200
            and role_name not in ('all_access', 'security_manager')):
        logger.info('Update role')

        payload = json.loads(es_app_data['security']['role_es_loader'])
        logger.debug(json.dumps(payload, default=json_serial))
        res_new = requests.put(
            url=f'{base_url}_security/api/roles/{role_name}',
            auth=awsauth, json=payload, headers=RESTAPI_HEADERS)
        logger.info(output_message(f'role_{role_name}', res_new))

    logger.debug(f'Current Configration: {res.text}')
    res_json = json.loads(res.text)
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
        logger.info(f'New configuration {json.dumps(current_conf)}')
        res = requests.put(
            url=f'{base_url}_security/api/rolesmapping/{role_name}',
            auth=awsauth, json=current_conf, headers=RESTAPI_HEADERS)
        logger.info(output_message(f'role_apping_{role_name}', res))
    else:
        logger.debug("no updating AOS's role mapping")


def configure_opensearch(dist_name, es_app_data):
    if AOS_SERVICE == 'aoss':
        return
    logger.info("Create or Update role/mapping")
    upsert_role_mapping(dist_name, 'all_access',
                        added_user=KIBANAADMIN, added_role=ROLE_AOS_ADMIN)
    upsert_role_mapping(dist_name, 'security_manager',
                        added_user=KIBANAADMIN, added_role=ROLE_AOS_ADMIN)
    upsert_role_mapping(dist_name, 'aws_log_loader', es_app_data=es_app_data,
                        added_role=ROLE_ES_LOADER)
    upsert_role_mapping(dist_name, 'aws_log_loader', es_app_data=es_app_data,
                        added_role=es_loader_ec2_role)
    upsert_role_mapping(dist_name, 'aws_log_loader', es_app_data=es_app_data,
                        added_role=ROLE_METRICS_EXPORTER)


def upsert_policy(dist_name, awsauth, items):
    if dist_name == 'opensearch':
        base_url = f'https://{ENDPOINT}/_plugins/'
    else:
        base_url = f'https://{ENDPOINT}/_opendistro/'
    for key in items:
        url = f'{base_url}_ism/policies/{key}'
        res = requests.get(url=url, auth=awsauth, stream=True)

        if res.status_code == 200:
            seq_no = json.loads(res.content)['_seq_no']
            primary_term = json.loads(res.content)['_primary_term']
            url = f'{url}?if_seq_no={seq_no}&if_primary_term={primary_term}'

        payload = json.loads(items[key])
        res = requests.put(
            url=url, auth=awsauth, json=payload, headers=RESTAPI_HEADERS)
        logger.info(output_message(key, res))


def upsert_obj(awsauth, items, api):
    for key in items:
        payload = json.loads(items[key])
        for i in range(5):
            res = requests.put(
                url=f'https://{ENDPOINT}/{api}/{key}',
                auth=awsauth, json=payload, headers=RESTAPI_HEADERS)
            if res.status_code == 200:
                logger.debug(output_message(key, res))
                break
            elif res.status_code == 400 and AOS_SERVICE == 'aoss':
                logger.error(res.text)
                time.sleep(2)
                continue
            elif res.status_code == 403 and AOS_SERVICE == 'aoss':
                logger.info(res.text)
                time.sleep(2)
                continue
            logger.error(output_message(key, res))
            break


def delete_obj(awsauth, items, api):
    for key in items:
        url = f'https://{ENDPOINT}/{api}/{key}'
        res = requests.head(url=url, auth=awsauth, stream=True)
        if res.status_code == 200:
            res = requests.delete(url=url, auth=awsauth, stream=True)
            if res.status_code == 200:
                logger.debug(output_message(key, res))
            else:
                logger.error(output_message(key, res))
        elif res.status_code == 404:
            pass
        else:
            logger.error(output_message(key, res))


def configure_siem(dist_name, es_app_data):
    # create cluster settings #48
    logger.info('Configure default cluster setting of OpenSerch Service')
    awsauth = auth_aes()
    cluster_settings = es_app_data['cluster-settings']
    for key in cluster_settings:
        logger.info(f'system setting: {key}')
        payload = json.loads(cluster_settings[key])
        res = requests.put(
            url=f'https://{ENDPOINT}/_cluster/settings',
            auth=awsauth, json=payload, headers=RESTAPI_HEADERS)
        logger.debug(output_message(key, res))

    # new composable index template. v2.4.1-
    logger.info('Create/Update component index templates')
    upsert_obj(awsauth, es_app_data['component-templates'],
               api='_component_template')
    logger.info('Create/Update index templates')
    upsert_obj(awsauth, es_app_data['index-templates'],
               api='_index_template')

    # create index_state_management_policies such as rollover policy
    upsert_policy(
        dist_name, awsauth, es_app_data['index_state_management_policies'])

    # index template for rollover
    upsert_obj(awsauth, es_app_data['index-rollover'],
               api='_index_template')

    # delete legacy index template
    logger.info('Delete legacy index templates')
    delete_obj(awsauth, es_app_data['deleted-old-index-template'],
               api='_template')

    # lagecy intex template. It will be deplecated
    logger.info('Create/Update legacy index templates')
    upsert_obj(awsauth, es_app_data['legacy-index-template'], api='_template')


def configure_index_rollover(es_app_data):
    if AOS_SERVICE == 'aoss':
        return
    awsauth = auth_aes()
    index_patterns = es_app_data['index-rollover']
    logger.info('Delete initial index 000001 for rollover if no documents')
    for key in index_patterns:
        alias = key.replace('_rollover', '')
        res_alias = requests.get(
            f'https://{ENDPOINT}/{alias}', auth=awsauth, stream=True)
        if res_alias.status_code == 200:
            logger.debug(output_message(f'Alias {alias} exists', res_alias))
            idx = list(json.loads(res_alias.content).keys())[0]
            res_count = requests.get(
                f'https://{ENDPOINT}/{idx}/_count', auth=awsauth, stream=True)
            if res_count.status_code == 200:
                doc_count = json.loads(res_count.content)['count']
                if doc_count == 0:
                    requests.delete(
                        f'https://{ENDPOINT}/{idx}', auth=awsauth, stream=True)
                    logger.info(f'{idx} has been deleted due to no documents')

    logger.info('Finished deleing initial index 000001 for rollover')


def json_serial(obj):
    # for debug to dump various json
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    try:
        return repr(obj)
    except Exception:
        raise TypeError(f'Type {type(obj)} not serializable')


def create_loggroup_and_set_retention(cwl_client, log_group, retention):
    response = cwl_client.describe_log_groups(
        logGroupNamePrefix=log_group, limit=1)
    if len(response['logGroups']) == 0:
        logger.info(f'create log group {log_group}')
        response = cwl_client.create_log_group(logGroupName=log_group)
        logger.debug(response)
    logger.info(
        f'put retention policy as {retention} days for {log_group}')
    response = cwl_client.put_retention_policy(
        logGroupName=log_group, retentionInDays=retention)
    logger.debug(response)


def setup_aes_system_log():
    cwl_client = boto3.client('logs')
    logger.info('put_resource_policy for OpenSearch Service system log')
    response = cwl_client.put_resource_policy(
        policyName=f'OpenSearchService-{SOLUTION_PREFIX}-logs',
        policyDocument=json.dumps(cwl_resource_policy)
    )
    logger.debug('Response of put_resource_policy')
    logger.debug(json.dumps(response, default=json_serial))
    for LOGGROUP_RETENTION in LOGGROUP_RETENTIONS:
        log_group = LOGGROUP_RETENTION[0]
        retention = LOGGROUP_RETENTION[1]
        create_loggroup_and_set_retention(cwl_client, log_group, retention)


def set_tenant_get_cookies(dist_name, tenant, auth):
    if AOS_SERVICE == 'aoss':
        return
    logger.debug(f'Set tenant as {tenant} and get cookies')
    logger.debug(f'dist_name is {dist_name}')
    if dist_name == 'opensearch':
        base_url = f'https://{ENDPOINT}/_dashboards'
        headers = DASHBOARDS_HEADERS
    else:
        base_url = f'https://{ENDPOINT}/_plugin/kibana'
        headers = KIBANA_HEADERS
    if isinstance(auth, dict):
        response = requests.post(
            url=f'{base_url}/auth/login?security_tenant={tenant}',
            headers=headers, json=json.dumps(auth))
    elif isinstance(auth, AWSV4SignerAuth):
        response = requests.get(
            url=f'{base_url}/app/dashboards?security_tenant={tenant}',
            headers=headers, auth=auth)
    else:
        logger.error('There is no valid authentication')
        return False
    if response.status_code in (200, ):
        logger.info('Authentication success to access OpenSearch Dashboards')
        return response.cookies
    else:
        print(response.cookies)
        logger.error("Authentication failed to access OpenSearch Dashboards")
        logger.error(response.reason)
        return False


def register_snapshot_repository():
    if AOS_SERVICE == 'aoss':
        return
    logger.info('register snapshot repository')
    payload = {
        "type": "s3",
        "settings": {
            "bucket": S3_SNAPSHOT,
            "region": REGION,
            "role_arn": ROLE_SNAPSHOT,
        }
    }
    awsauth = auth_aes()
    api = '_snapshot/siem-snapshot'
    res = requests.put(
        f'https://{ENDPOINT}/{api}',
        auth=awsauth, json=payload, headers=RESTAPI_HEADERS)
    if res.status_code == 200:
        logger.info(output_message(api, res))
    else:
        logger.error(output_message(api, res))


def get_saved_objects(dist_name, cookies, auth=None):
    if not cookies and AOS_SERVICE == 'es':
        logger.warning("No authentication. Skipped downloading dashboard")
        return False
    if dist_name == 'opensearch':
        url = f'https://{ENDPOINT}/_dashboards/api/saved_objects/_export'
        headers = DASHBOARDS_HEADERS
    else:
        url = f'https://{ENDPOINT}/_plugin/kibana/api/saved_objects/_export'
        headers = KIBANA_HEADERS
    payload = {'type': ['config', 'dashboard', 'visualization',
                        'index-pattern', 'search']}
    if auth:
        response = requests.post(url=url, cookies=cookies, headers=headers,
                                 json=json.dumps(payload), auth=auth)
    else:
        response = requests.post(url=url, cookies=cookies, headers=headers,
                                 json=json.dumps(payload))
    logger.debug(response.status_code)
    logger.debug(response.reason)
    return response.content


def backup_content_to_s3(dir_name, content_type, content_name, content):
    now_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    file_name = f'{content_name}-{content_type}-{now_str}.ndjson'
    if content and isinstance(content, bytes):
        with open(f'/tmp/{file_name}', 'wb') as raw_file:
            raw_file.write(content)
        with ZipFile(f'/tmp/{file_name}.zip', 'w',
                     compression=ZIP_DEFLATED) as zip_file:
            zip_file.write(f'/tmp/{file_name}', arcname=file_name)
    else:
        logging.error(f'failed to export {content_type}')
        return False
    try:
        s3_snapshot_bucket.upload_file(
            Filename=f'/tmp/{file_name}.zip',
            Key=f'{dir_name}/{file_name}.zip')
        return True
    except Exception as err:
        logging.error(f'failed to upload {content_type} to S3')
        logging.error(err)
        return False


def import_saved_objects_into_aos(dist_name, auth, cookies):
    logger.info("import saved objects")

    if dist_name == 'opensearch':
        url = (f'https://{ENDPOINT}/_dashboards/api/saved_objects/'
               f'_import?overwrite=true')
        headers = {'osd-xsrf': 'true'}
    else:
        url = (f'https://{ENDPOINT}/_plugin/kibana/api/saved_objects/'
               f'_import?overwrite=true')
        headers = {'kbn-xsrf': 'true'}

    if AOS_SERVICE == 'es':
        with ZipFile('dashboard.ndjson.zip') as new_dashboard_zip:
            new_dashboard_zip.extractall('/tmp/')
        if os.path.exists('/tmp/dashboard.ndjson'):
            with open('/tmp/dashboard.ndjson', 'rb') as fd:
                # confirmd and ignored Rule-645108
                response = requests.post(
                    url=url, cookies=cookies, files={'file': fd},
                    headers=headers, auth=auth)
                logger.info(response.text)
        else:
            logger.error('dashboard.ndjson is not contained')

    elif AOS_SERVICE == 'aoss':
        with ZipFile('dashboard.serverless.zip') as new_dashboard_zip:
            new_dashboard_zip.extractall('/tmp/')
        temp_dir = pathlib.Path('/tmp')
        files_list = list(temp_dir.glob('config/*.ndjson'))
        files_list += list(temp_dir.glob('each-indexpattern-search/*.ndjson'))
        files_list += list(temp_dir.glob('each-dashboard/*.ndjson'))

        for file_path in files_list:
            files = {'file': open(file_path, 'rb')}
            logger.debug(file_path)
            response = requests.post(
                url, files=files, headers=headers, auth=auth)
            if response.status_code == 200:
                logger.debug(response.text)
            else:
                logger.error(response.text)


def resource_validator_handler(event, context):
    if 'ResourceType' in event \
            and event['ResourceType'] == 'AWS::CloudFormation::CustomResource':
        helper_validation(event, context)
    else:
        validate_resource(event, context)
    return {"statusCode": 200}


def check_slr_aos(vpc_id=None):
    needs_slr = False
    if AOS_SERVICE == 'es' and vpc_id:
        try:
            logger.debug('Check IAM Role')
            response = iam_client.get_role(
                RoleName='AmazonOpenSearchServerlessServiceRole')
            logger.debug(response)
        except Exception:
            needs_slr = True
    return needs_slr


def check_slr_aoss(vpc_id=None):
    needs_slr = False
    if AOS_SERVICE == 'aoss' and vpc_id:
        try:
            logger.debug('Check IAM Role')
            response = iam_client.get_role(
                RoleName='AWSServiceRoleForAmazonOpenSearchService')
            logger.debug(response)
        except Exception:
            needs_slr = True
    return needs_slr


def get_vpcid_subnets_by_vpcendpoints(subnets: list) -> (str, list):
    if REGION.startswith('cn'):
        url_prefix = 'cn.com'
    else:
        url_prefix = 'com'
    service_names = [
        f'{url_prefix}.amazonaws.{REGION}.sqs',
        f'{url_prefix}.amazonaws.{REGION}.sts',
        f'com.amazonaws.{REGION}.ssm',
        f"com.amazonaws.{REGION}.s3"]
    response = ec2_client.describe_vpc_endpoint_services(
        ServiceNames=service_names)
    azs = set()
    for vpce in response['ServiceDetails']:
        if len(azs) == 0:
            azs = set(vpce['AvailabilityZones'])
        if len(azs) > 0:
            azs = azs & set(vpce['AvailabilityZones'])
    azs = list(azs)
    response = ec2_client.describe_subnets(
        Filters=[{'Name': 'availability-zone', 'Values': azs}],
        SubnetIds=subnets)
    vpc_id = response['Subnets'][0]['VpcId']
    subnets = set()
    for subnet in response['Subnets']:
        subnets.add(subnet['SubnetId'])
    subnets = sorted(list(subnets))
    return vpc_id, subnets


@helper_validation.update
@helper_validation.create
def validate_resource(event, context):
    logger.info("Got Create/Update")
    if event:
        logger.debug(json.dumps(event, default=json_serial))

    suffix = ''.join(secrets.choice(string.ascii_uppercase) for i in range(8))
    physicalResourceId = f'vpc-config-{__version__}-{suffix}'

    subnets = sorted(AOS_SUBNET_IDS.split(',')) if AOS_SUBNET_IDS else []
    subnets = list(sorted(set(subnets)))
    vpc_id = ''
    cidr_block = [0, 1, 2, 3]
    route_table_ids = []
    if VPCE_ID and AOS_SERVICE == 'es':
        logger.debug('Check VPCE for OpenSearch Managed Cluster')
        try:
            response = opensearch_client.describe_vpc_endpoints(
                VpcEndpointIds=[VPCE_ID])
            logger.debug(response)
            vpc_options = response['VpcEndpoints'][0].get('VpcOptions')
            vpc_id = vpc_options.get('VPCId')
            subnets = sorted(vpc_options.get('SubnetIds'))
            logger.debug(f'vpc_id: {vpc_id}')
            logger.debug(f'subnets: {subnets}')
        except Exception as err:
            raise Exception(f'VPC endpoint {VPCE_ID} is not found or '
                            f'something wrong. Invalid VPCE ID. {err}')
    elif VPCE_ID and AOS_SERVICE == 'aoss':
        logger.debug('Check VPCE for OpenSearch Serverless')
        try:
            response = serverless_client.batch_get_vpc_endpoint(ids=[VPCE_ID])
            logger.debug(response)
            vpce_detail = response['vpcEndpointDetails'][0]
            vpc_id = vpce_detail.get('vpcId')
            subnets = sorted(vpce_detail.get('subnetIds'))
            logger.debug(f'vpc_id: {vpc_id}')
            logger.debug(f'subnets: {subnets}')
        except Exception as err:
            raise Exception(f'VPC endpoint {VPCE_ID} is not found or '
                            f'something wrong. Invalid VPCE ID. {err}')

    if subnets:
        logger.debug('Check subnets')
        vpc_id, subnets = get_vpcid_subnets_by_vpcendpoints(subnets)

        logger.debug('Check route tables')
        response = ec2_client.describe_route_tables(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
        for x in response['RouteTables']:
            for y in x['Associations']:
                if isinstance(y, dict) and y.get('Main'):
                    main_route_table = y['RouteTableId']
                    break
        for subnet in subnets:
            response = ec2_client.describe_route_tables(
                Filters=[{'Name': 'association.subnet-id',
                          'Values': [subnet]}])
            if len(response['RouteTables']) == 0:
                route_table_ids.append(main_route_table)
            else:
                for x in response['RouteTables']:
                    for y in x['Associations']:
                        if isinstance(y, dict) and y.get('RouteTableId'):
                            route_table_ids.append(y.get('RouteTableId'))
            route_table_ids = sorted(list(set(route_table_ids)))

        logger.debug('Check vpc_id')
        response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        for i in range(4):
            try:
                cidr_block[i] = response['Vpcs'][i]['CidrBlock']
            except Exception:
                cidr_block[i] = response['Vpcs'][0]['CidrBlock']

    logger.info('get and backup s3 bucket policy of log bucket')
    result = s3_client.BucketPolicy(S3_LOG)
    is_valid_policy = False
    try:
        policy = result.policy
        logger.debug(policy)
        is_valid_policy = True
    except s3_client.meta.client.exceptions.NoSuchBucket as err:
        logger.info('The Log bucket is not found. This is probably the first '
                    'deployment. If so, ignore this message.')
        policy = str(err)
    except Exception as err:
        logger.error('Valid bucket policy is not found. '
                     'Select auto_update_policy of LogBucketPolicyUpdate '
                     'in CloudFormation Parameters')
        logger.error(err)
        policy = str(err)
    backup_content_to_s3(
        's3_bucket_policy', 'bucket_policy', S3_LOG, policy.encode())

    if not is_valid_policy:
        bucket_arn = f'arn:{PARTITION}:s3:::{S3_LOG}'
        policy = ('{{"Version":"2012-10-17","Statement":[{{"Effect":"Deny",'
                  '"Principal":{{"AWS":"*"}},"Action":"s3:*","Resource":"{0}",'
                  '"Condition":{{"Bool":{{"aws:SecureTransport":"false"}}}}}}]'
                  '}}'.format(bucket_arn))

    def ssm_put_parameter(param_name, policy):
        if not policy:
            policy = ' '
        ssm_client.put_parameter(Name=f'/siem/bucketpolicy/log/{param_name}',
                                 Value=policy, Type='String', Overwrite=True)

    ssm_put_parameter('policy1', policy[:2560])
    ssm_put_parameter('policy2', policy[2560:5120])
    ssm_put_parameter('policy3', policy[5120:7680])
    ssm_put_parameter('policy4', policy[7680:10240])
    ssm_put_parameter('policy5', policy[10240:12800])
    ssm_put_parameter('policy6', policy[12800:15360])
    ssm_put_parameter('policy7', policy[15360:17920])
    ssm_put_parameter('policy8', policy[17920:20480])

    # needs_slr_aos = check_slr_aos(vpc_id)
    # needs_slr_aoss = check_slr_aoss(vpc_id)

    if event and 'RequestType' in event:
        # Response For CloudFormation Custome Resource
        helper_validation.Data['vpc_id'] = vpc_id
        helper_validation.Data['subnets'] = subnets
        helper_validation.Data['route_table_ids'] = route_table_ids
        helper_validation.Data['cidr_block0'] = cidr_block[0]
        helper_validation.Data['cidr_block1'] = cidr_block[1]
        helper_validation.Data['cidr_block2'] = cidr_block[2]
        helper_validation.Data['cidr_block3'] = cidr_block[3]
        # helper_validation.Data['needs_slr_aos'] = needs_slr_aos
        # helper_validation.Data['needs_slr_aoss'] = needs_slr_aoss
        logger.debug(helper_validation.Data)
        logger.info("End Create/Update")
        return physicalResourceId


def aes_domain_handler(event, context):
    helper_domain(event, context)


@helper_domain.create
def aes_domain_create(event, context):
    logger.info("Got Create")
    if event:
        logger.debug(json.dumps(event, default=json_serial))

    if AOS_SERVICE == 'es':
        try:
            response = opensearch_client.describe_domain(
                DomainName=AOS_DOMAIN)
        except Exception:
            logger.info(f'OpenSearch Domain "{AOS_DOMAIN}" will be created')
            create_new_domain = True
        else:
            logger.info(f'OpenSearch Domain "{AOS_DOMAIN}" already exists')
            create_new_domain = False
    elif AOS_SERVICE == 'aoss':
        aoss = MyAoss(serverless_client, DOMAIN_OR_COLLECTION_NAME)
        create_new_domain = aoss.check_collection_creating_necessity()

    helper_domain.Data.update({"create_new_domain": create_new_domain})

    setup_aes_system_log()

    if AOS_SERVICE == 'es' and create_new_domain:
        try:
            response = opensearch_client.create_domain(**config_domain)
        except botocore.exceptions.ClientError:
            logger.exception('retry in 60s')
            time.sleep(60)
            response = opensearch_client.create_domain(**config_domain)
        time.sleep(3)
        logger.debug(json.dumps(response, default=json_serial))
        kibanapass = make_password(8)
        helper_domain.Data.update({"kibanapass": kibanapass})
    elif AOS_SERVICE == 'aoss' and create_new_domain:
        aoss.create_collection(VPCE_ID)
    elif not create_new_domain:
        pass

    logger.info("End Create. To be continue in poll create")
    return True


@helper_domain.poll_create
def aes_domain_poll_create(event, context):
    logger.info("Got create poll")

    suffix = ''.join(secrets.choice(string.ascii_uppercase) for i in range(8))
    physicalResourceId = f'aes-siem-domain-{__version__}-{suffix}'
    create_new_domain = helper_domain.Data.get('create_new_domain')
    kibanapass = helper_domain.Data.get('kibanapass')
    aoss_type = ''
    if not kibanapass:
        kibanapass = 'MASKED'
    if AOS_SERVICE == 'aoss':
        aoss = MyAoss(serverless_client, DOMAIN_OR_COLLECTION_NAME)

    if AOS_SERVICE == 'es' and create_new_domain:
        response = opensearch_client.describe_domain(DomainName=AOS_DOMAIN)
        logger.debug('Processing domain creation')
        logger.debug(json.dumps(response, default=json_serial))

        domain_processing_status = (
            response['DomainStatus']['DomainProcessingStatus'])
        logger.debug('DomainStatus.DomainProcessingStatus: '
                     f'{domain_processing_status}')
        if domain_processing_status != 'Active':
            logger.info('OpenSearch Service domain creation is in progress')
            return None
        else:
            logger.info('OpenSearch Service domain has just been created')

        userdb_enabled = (response['DomainStatus']['AdvancedSecurityOptions']
                          ['InternalUserDatabaseEnabled'])
        if not userdb_enabled:
            logger.info(f'ID: {KIBANAADMIN}, PASSWORD: {kibanapass}')
            update_response = create_kibanaadmin(kibanapass)
            while not userdb_enabled:
                logger.debug('Processing domain configuration')
                userdb_enabled = (update_response['DomainConfig']
                                  ['AdvancedSecurityOptions']['Options']
                                  ['InternalUserDatabaseEnabled'])
                time.sleep(3)
            logger.info(
                'Finished domain configuration with new random password')

        endpoint = None
        while not endpoint:
            time.sleep(10)  # wait to finish setup of endpoint
            logger.debug('Processing AOS endpoint creation')
            response = opensearch_client.describe_domain(DomainName=AOS_DOMAIN)
            endpoint = response['DomainStatus'].get('Endpoint')
            if not endpoint and 'Endpoints' in response['DomainStatus']:
                endpoint = response['DomainStatus']['Endpoints']['vpc']
            logger.debug('Finished AOS endpoint creation')
        dashboard_admin_name = KIBANAADMIN
    elif AOS_SERVICE == 'es' and not create_new_domain:
        response = opensearch_client.describe_domain(DomainName=AOS_DOMAIN)
        endpoint = response['DomainStatus'].get('Endpoint')
        if not endpoint and 'Endpoints' in response['DomainStatus']:
            endpoint = response['DomainStatus']['Endpoints']['vpc']
        dashboard_admin_name = 'NOT_CREATED'
    elif AOS_SERVICE == 'aoss' and create_new_domain:
        status = aoss.get_collection_status()
        if status != 'ACTIVE':
            return None
        endpoint, aoss_type = aoss.get_endpoint_and_type()
        dashboard_admin_name = 'NOT_CREATED'
    elif AOS_SERVICE == 'aoss' and not create_new_domain:
        endpoint, aoss_type = aoss.get_endpoint_and_type()
        dashboard_admin_name = 'NOT_CREATED'

    if event and 'RequestType' in event:
        # Response For CloudFormation Custome Resource
        helper_domain.Data['endpoint'] = endpoint
        helper_domain.Data['aoss_type'] = aoss_type
        helper_domain.Data['kibanaadmin'] = dashboard_admin_name
        helper_domain.Data['kibanapass'] = kibanapass
        logger.info("End create poll")
        return physicalResourceId


@helper_domain.update
def aes_domain_update(event, context):
    logger.info("Got Update")

    # check whether opensearch domain or collection exists
    endpoint = ''
    aoss_type = ''
    if AOS_SERVICE == 'es':
        try:
            response = opensearch_client.describe_domain(
                DomainName=AOS_DOMAIN)
        except Exception:
            raise Exception(
                f'OpenSearch Domain "{AOS_DOMAIN}" is not found'
            ) from None
        endpoint = response['DomainStatus'].get('Endpoint')
        if not endpoint and 'Endpoints' in response['DomainStatus']:
            endpoint = response['DomainStatus']['Endpoints']['vpc']
        engine_version = response['DomainStatus']['EngineVersion']
        if (engine_version.startswith('Elasticsearch')
                and engine_version != 'Elasticsearch_7.10'):
            raise Exception(f'{engine_version} is not supported version')

    elif AOS_SERVICE == 'aoss':
        aoss = MyAoss(serverless_client, DOMAIN_OR_COLLECTION_NAME)
        status = aoss.get_collection_status()
        if status != 'ACTIVE':
            raise Exception(
                f'Collection {DOMAIN_OR_COLLECTION_NAME} is not found or not '
                f'active. Please ensure {DOMAIN_OR_COLLECTION_NAME} is active')
        endpoint, aoss_type = aoss.get_endpoint_and_type()
        if not endpoint:
            raise Exception(
                f'Collection {DOMAIN_OR_COLLECTION_NAME} is not found')
        aoss.update_collection(VPCE_ID)

    logger.info(f'ENDPOINT: {endpoint}')

    suffix = ''.join(secrets.choice(string.ascii_uppercase) for i in range(8))
    physicalResourceId = f'aes-siem-domain-{__version__}-{suffix}'
    if event and 'RequestType' in event:
        # Response For CloudFormation Custome Resource
        helper_domain.Data['endpoint'] = endpoint
        helper_domain.Data['aoss_type'] = aoss_type
        helper_domain.Data['kibanaadmin'] = KIBANAADMIN
        helper_domain.Data['kibanapass'] = 'MASKED'
        logger.info("End Update")
        return physicalResourceId


@helper_domain.delete
def aes_domain_delete(event, context):
    logger.info('Got Delete')
    # https://github.com/aws-cloudformation/custom-resource-helper/issues/5
    cwe_client = boto3.client('events')
    response = cwe_client.list_rules(NamePrefix='AesSiemDomainDeployed')
    for rule in response['Rules']:
        rule_name = rule['Name']
        cwe_client.remove_targets(Rule=rule_name, Ids=['1', ])
        cwe_client.delete_rule(Name=rule_name)
        logger.info(f"Delete CWE {rule_name} created by crhelper")


def aes_config_handler(event, context):
    if 'ResourceType' in event \
            and event['ResourceType'] == 'AWS::CloudFormation::CustomResource':
        helper_config(event, context)
    else:
        aes_config_create_update(event, context)
    return {"statusCode": 200}


@helper_config.create
@helper_config.update
def aes_config_create_update(event, context):
    logger.info("Got Create/Update")
    suffix = ''.join(secrets.choice(string.ascii_uppercase) for i in range(8))
    physicalResourceId = f'aes-siem-config-{__version__}-{suffix}'
    if event:
        logger.debug(json.dumps(event, default=json_serial))
    es_app_data = configparser.ConfigParser(
        interpolation=configparser.ExtendedInterpolation())
    logger.info('read data.ini')
    es_app_data.read('data.ini')
    if AOS_SERVICE == 'es':
        del es_app_data['index-templates']['log_aws']
    elif AOS_SERVICE == 'aoss':
        logger.info('read data-serverless.ini')
        es_app_data.read('data-serverless.ini')
        es_app_data['cluster-settings'] = {}
        es_app_data['index_state_management_policies'] = {}
        es_app_data['index-rollover'] = {}
        es_app_data['deleted-old-index-template'] = {}
        es_app_data['legacy-index-template'] = {}
        actor = json.loads(es_app_data['ocsf-schema-core']['actor'])
        actor['process'] = {"type": "object"}
        actor['file'] = {"type": "object"}
        es_app_data['ocsf-schema-core']['actor'] = json.dumps(actor)

    dist_name, domain_version = get_dist_version()
    logger.info(f'dist_name: {dist_name}, domain_version: {domain_version}')
    if domain_version in ('7.4.2', '7.7.0', '7.8.0', '7.9.1'):
        raise Exception(f'Your domain version is Amazon ES {domain_version}. '
                        f'Please upgrade the domain to OpenSearch or '
                        f'Amazon ES v7.10')

    configure_opensearch(dist_name, es_app_data)
    configure_siem(dist_name, es_app_data)
    configure_index_rollover(es_app_data)

    register_snapshot_repository()

    # Globalテナントのsaved_objects をバックアップする
    tenant = 'global'
    awsauth = auth_aes()
    cookies = set_tenant_get_cookies(dist_name, tenant, awsauth)
    saved_objects = get_saved_objects(dist_name, cookies, auth=awsauth)
    bk_response = backup_content_to_s3(
        'saved_objects', 'dashboard', tenant, saved_objects)
    if bk_response:
        # Load dashboard and configuration to Global tenant
        import_saved_objects_into_aos(dist_name, awsauth, cookies)

    if event and 'RequestType' in event:
        # Response For CloudFormation Custome Resource
        logger.info("End create poll")
        return physicalResourceId


@helper_config.delete
def aes_config_delete(event, context):
    logger.info("Got Delete. Nothing to delete")


@helper_validation.delete
def custom_resource_delete(event, context):
    logger.info("Got Delete")
    try:
        response = ssm_client.delete_parameters(Names=[
            f'/siem/bucketpolicy/log/policy{n}' for n in range(1, 9)])
        logger.info(response)
    except Exception:
        logger.exception("something wrong")


if __name__ == '__main__':
    aes_domain_handler(None, None)
    aes_config_handler(None, None)
