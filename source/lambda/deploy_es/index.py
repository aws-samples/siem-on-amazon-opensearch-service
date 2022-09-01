#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = 'Amazon.com, Inc. or its affiliates'
__version__ = '2.8.0'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import configparser
import json
import logging
import os
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

print('version: ' + __version__)

logger = logging.getLogger(__name__)
helper_domain = CfnResource(json_logging=False, log_level='DEBUG',
                            boto_level='CRITICAL', sleep_on_delete=120)
helper_config = CfnResource(json_logging=False, log_level='DEBUG',
                            boto_level='CRITICAL', sleep_on_delete=120)

opensearch_client = boto3.client('opensearch')
s3_client = boto3.resource('s3')

accountid = os.environ['accountid']
region = os.environ['AWS_REGION']
PARTITION = boto3.Session().get_partition_for_region(region)
aesdomain = os.getenv('aes_domain_name')
myaddress = os.getenv('allow_source_address', '').split()
aes_admin_role = os.getenv('aes_admin_role')
es_loader_role = os.getenv('es_loader_role')
metrics_exporter_role = os.getenv('metrics_exporter_role')
myiamarn = [accountid]
KIBANAADMIN = 'aesadmin'
KIBANA_HEADERS = {'Content-Type': 'application/json', 'kbn-xsrf': 'true'}
DASHBOARDS_HEADERS = {'Content-Type': 'application/json', 'osd-xsrf': 'true'}
vpc_subnet_id = os.getenv('vpc_subnet_id')
security_group_id = os.getenv('security_group_id')
s3_snapshot = os.getenv('s3_snapshot')
LOGGROUP_RETENTIONS = [
    (f'/aws/OpenSearchService/domains/{aesdomain}/application-logs', 14),
    ('/aws/lambda/aes-siem-configure-aes', 90),
    ('/aws/lambda/aes-siem-deploy-aes', 90),
    ('/aws/lambda/aes-siem-es-loader', 90),
    ('/aws/lambda/aes-siem-geoip-downloader', 90),
]

es_loader_ec2_role = (
    f'arn:{PARTITION}:iam::{accountid}:role/aes-siem-es-loader-for-ec2')

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
                (f'arn:{PARTITION}:logs:{region}:{accountid}:log-group:/aws/'
                 f'OpenSearchService/domains/{aesdomain}/*'),
                (f'arn:{PARTITION}:logs:{region}:{accountid}:log-group:/aws/'
                 f'OpenSearchService/domains/{aesdomain}/*:*')
            ]
        }
    ]
}

access_policies = {
    'Version': '2012-10-17',
    'Statement': [
        {
            'Effect': 'Allow',
            'Principal': {'AWS': myiamarn},
            'Action': ['es:*'],
            'Resource': (f'arn:{PARTITION}:es:{region}:{accountid}'
                         f':domain/{aesdomain}/*')
        },
        {
            'Effect': 'Allow',
            'Principal': {'AWS': '*'},
            'Action': ['es:*'],
            'Condition': {'IpAddress': {'aws:SourceIp': myaddress}},
            'Resource': (f'arn:{PARTITION}:es:{region}:{accountid}:'
                         f'domain/{aesdomain}/*')
        }
    ]
}
if vpc_subnet_id:
    access_policies['Statement'][0]['Principal'] = {'AWS': '*'}
    del access_policies['Statement'][1]
access_policies_json = json.dumps(access_policies)

config_domain = {
    'DomainName': aesdomain,
    'EngineVersion': 'OpenSearch_1.3',
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
                f'arn:{PARTITION}:logs:{region}:{accountid}:log-group:/aws/'
                f'OpenSearchService/domains/{aesdomain}/application-logs'),
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
            'MasterUserARN': aes_admin_role,
            # 'MasterUserName': kibanaadmin,
            # 'MasterUserPassword': kibanapass
        }
    }
}
if vpc_subnet_id:
    config_domain['VPCOptions'] = {'SubnetIds': [vpc_subnet_id, ],
                                   'SecurityGroupIds': [security_group_id, ]}

if region == 'ap-northeast-3':
    config_domain['ClusterConfig']['InstanceType'] = 'r5.large.search'

if s3_snapshot:
    s3_snapshot_bucket = s3_client.Bucket(s3_snapshot)


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
    response = opensearch_client.update_domain_config(
        DomainName=aesdomain,
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


def auth_aes(es_endpoint):
    credentials = boto3.Session().get_credentials()
    awsauth = AWSV4SignerAuth(credentials, region)
    return awsauth


def query_aes(es_endpoint, awsauth, method=None, path=None, payload=None,
              headers=None):
    if not headers:
        headers = {'Content-Type': 'application/json'}
    url = f'https://{es_endpoint}/{path}'
    if method.lower() == 'get':
        res = requests.get(url, auth=awsauth, stream=True)
    elif method.lower() == 'post':
        res = requests.post(url, auth=awsauth, json=payload, headers=headers)
    elif method.lower() == 'put':
        res = requests.put(url, auth=awsauth, json=payload, headers=headers)
    elif method.lower() == 'patch':
        res = requests.put(url, auth=awsauth, json=payload, headers=headers)
    elif method.lower() == 'head':
        res = requests.head(url, auth=awsauth, stream=True)
    elif method.lower() == 'delete':
        res = requests.delete(url, auth=awsauth, stream=True)
    return(res)


def output_message(key, res):
    return(f'{key}: status={res.status_code}, message={res.text}')


def get_dist_version(es_endpoint):
    awsauth = auth_aes(es_endpoint)
    res = query_aes(es_endpoint, awsauth, method='get', path='')
    logger.info(res.text)
    version = json.loads(res.text)['version']
    domain_version = version['number']
    lucene_version = version['lucene_version']
    dist_name = version.get('distribution', 'elasticsearch')
    if domain_version == '7.10.2' and lucene_version != '8.7.0':
        dist_name = 'opensearch'
    return dist_name, domain_version


def upsert_role_mapping(es_endpoint, role_name, es_app_data=None,
                        added_user=None, added_role=None, added_host=None):
    awsauth = auth_aes(es_endpoint)
    logger.info('role_name: ' + role_name)
    path = '_opendistro/_security/api/rolesmapping/' + role_name
    res = query_aes(es_endpoint, awsauth, 'GET', path)
    if res.status_code == 404:
        logger.info('Create new role/mapping')
        # create role
        path_roles = '_opendistro/_security/api/roles/' + role_name
        payload = json.loads(es_app_data['security']['role_es_loader'])
        logger.debug(json.dumps(payload, default=json_serial))
        res_new = query_aes(es_endpoint, awsauth, 'PATCH', path_roles, payload)
        logger.info(output_message('role_' + role_name, res_new))
        time.sleep(3)
        # role mapping for new role
        payload = {'backend_roles': [es_loader_role, ]}
        res = query_aes(es_endpoint, awsauth, 'PATCH', path, payload)
        logger.info(output_message('role_mapping_' + role_name, res))
        return True
    elif (res.status_code == 200
            and role_name not in ('all_access', 'security_manager')):
        logger.info('Update role')
        path_roles = '_opendistro/_security/api/roles/' + role_name
        payload = json.loads(es_app_data['security']['role_es_loader'])
        logger.debug(json.dumps(payload, default=json_serial))
        res_new = query_aes(es_endpoint, awsauth, 'PATCH', path_roles, payload)
        logger.info(output_message('role_' + role_name, res_new))
    logger.debug('Current Configration: ' + res.text)
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
        logger.info('New configuration ' + json.dumps(current_conf))
        res = query_aes(es_endpoint, awsauth, 'PATCH', path, current_conf)
        logger.info(output_message('role_apping_' + role_name, res))
    else:
        logger.debug("no updating opendistro's role mapping")


def configure_opendistro(es_endpoint, es_app_data):
    logger.info("Create or Update role/mapping")
    upsert_role_mapping(es_endpoint, 'all_access',
                        added_user=KIBANAADMIN, added_role=aes_admin_role)
    upsert_role_mapping(es_endpoint, 'security_manager',
                        added_user=KIBANAADMIN, added_role=aes_admin_role)
    upsert_role_mapping(es_endpoint, 'aws_log_loader', es_app_data=es_app_data,
                        added_role=es_loader_role)
    upsert_role_mapping(es_endpoint, 'aws_log_loader', es_app_data=es_app_data,
                        added_role=es_loader_ec2_role)
    upsert_role_mapping(es_endpoint, 'aws_log_loader', es_app_data=es_app_data,
                        added_role=metrics_exporter_role)


def upsert_policy(es_endpoint, awsauth, items):
    for key in items:
        path = f'_opendistro/_ism/policies/{key}'
        res = query_aes(es_endpoint, awsauth, 'GET', path)
        if res.status_code == 200:
            seq_no = json.loads(res.content)['_seq_no']
            primary_term = json.loads(res.content)['_primary_term']
            path = f'{path}?if_seq_no={seq_no}&if_primary_term={primary_term}'
        payload = json.loads(items[key])
        res = query_aes(es_endpoint, awsauth, 'PUT', path, payload)
        logger.info(output_message(path, res))


def upsert_obj(es_endpoint, awsauth, items, api):
    for key in items:
        payload = json.loads(items[key])
        path = f'{api}/{key}'
        res = query_aes(es_endpoint, awsauth, 'PUT', path, payload)
        if res.status_code == 200:
            logger.debug(output_message(key, res))
        else:
            logger.error(output_message(key, res))


def delete_obj(es_endpoint, awsauth, items, api):
    for key in items:
        path = f'{api}/{key}'
        res = query_aes(es_endpoint, awsauth, 'HEAD', path)
        if res.status_code == 200:
            res = query_aes(es_endpoint, awsauth, 'DELETE', path)
            if res.status_code == 200:
                logger.debug(output_message(key, res))
            else:
                logger.error(output_message(key, res))
        elif res.status_code == 404:
            pass
        else:
            logger.error(output_message(key, res))


def configure_siem(es_endpoint, es_app_data):
    awsauth = auth_aes(es_endpoint)
    # create cluster settings #48
    logger.info('Configure default cluster setting of OpenSerch Service')
    cluster_settings = es_app_data['cluster-settings']
    for key in cluster_settings:
        logger.info('system setting :' + key)
        payload = json.loads(cluster_settings[key])
        res = query_aes(
            es_endpoint, awsauth, 'PUT', '_cluster/settings', payload)
        logger.debug(output_message(key, res))

    # new composable index template. v2.4.1-
    logger.info('Create/Update component index templates')
    upsert_obj(es_endpoint, awsauth, es_app_data['component-templates'],
               api='_component_template')
    logger.info('Create/Update index templates')
    upsert_obj(es_endpoint, awsauth, es_app_data['index-templates'],
               api='_index_template')

    # create index_state_management_policies such as rollover policy
    upsert_policy(
        es_endpoint, awsauth, es_app_data['index_state_management_policies'])

    # index template for rollover
    upsert_obj(es_endpoint, awsauth, es_app_data['index-rollover'],
               api='_index_template')

    # delete legacy index template
    logger.info('Delete legacy index templates')
    delete_obj(es_endpoint, awsauth, es_app_data['deleted-old-index-template'],
               api='_template')

    # lagecy intex template. It will be deplecated
    logger.info('Create/Update legacy index templates')
    upsert_obj(es_endpoint, awsauth, es_app_data['legacy-index-template'],
               api='_template')


def configure_index_rollover(es_endpoint, es_app_data):
    awsauth = auth_aes(es_endpoint)
    index_patterns = es_app_data['index-rollover']
    logger.info('Create initial index 000001 for rollover')
    for key in index_patterns:
        alias = key.replace('_rollover', '')
        res_alias = query_aes(es_endpoint, awsauth, 'GET', alias)
        is_refresh = False
        if res_alias.status_code == 200:
            logger.debug(output_message('Already exists ' + alias, res_alias))
            idx = list(json.loads(res_alias.content).keys())[0]
            res_count = query_aes(es_endpoint, awsauth, 'GET', f'{idx}/_count')
            if res_count.status_code == 200:
                doc_count = json.loads(res_count.content)['count']
                if doc_count == 0:
                    query_aes(es_endpoint, awsauth, 'DELETE', idx)
                    logger.info(f'{idx} is deleted and refreshed')
                    is_refresh = True
        else:
            is_refresh = True
            idx = key.replace('_rollover', '-000001')
        if is_refresh:
            payload = {'aliases': {alias: {"is_write_index": True}}}
            res = query_aes(es_endpoint, awsauth, 'PUT', idx, payload)
            if res.status_code == 200:
                logger.info(output_message(idx, res))
            else:
                logger.error(output_message(idx, res))
        """
        # check whether index alias has @timestamp field
        timestamp_field = f'{idx}/_mapping/field/@timestamp'
        res_timestamp = query_aes(es_endpoint, awsauth, 'GET', timestamp_field)
        if '@timestamp' not in res_timestamp.text:
            payload = {"@timestamp": "3000-01-01T00:00:00"}
            res = query_aes(
                es_endpoint, awsauth, 'POST', f'{idx}/_doc', payload)
            time.sleep(1)
            doc_id = json.loads(res.content)['_id']
            res = query_aes(
                es_endpoint, awsauth, 'DELETE', f'{idx}/_doc/{doc_id}')
            logger.info('put and deleted dummy data')
        else:
            pass
        """
    logger.info('Finished creating initial index 000001 for rollover')


def json_serial(obj):
    # for debug to dump various json
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    try:
        return repr(obj)
    except Exception:
        raise TypeError(f'Type {type(obj)} not serializable')


def create_loggroup_and_set_retention(cwl_client, log_group, retention):
    response = cwl_client.describe_log_groups(logGroupNamePrefix=log_group)
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
        policyName=f'OpenSearchService-{aesdomain}-logs',
        policyDocument=json.dumps(cwl_resource_policy)
    )
    logger.debug('Response of put_resource_policy')
    logger.debug(json.dumps(response, default=json_serial))
    for LOGGROUP_RETENTION in LOGGROUP_RETENTIONS:
        log_group = LOGGROUP_RETENTION[0]
        retention = LOGGROUP_RETENTION[1]
        create_loggroup_and_set_retention(cwl_client, log_group, retention)


def set_tenant_get_cookies(es_endpoint, dist_name, tenant, auth):
    logger.debug(f'Set tenant as {tenant} and get cookies')
    if dist_name == 'opensearch':
        base_url = f'https://{es_endpoint}/_dashboards'
        headers = DASHBOARDS_HEADERS
    else:
        base_url = f'https://{es_endpoint}/_plugin/kibana'
        headers = KIBANA_HEADERS
    if isinstance(auth, dict):
        url = f'{base_url}/auth/login?security_tenant={tenant}'
        response = requests.post(
            url, headers=headers, json=json.dumps(auth))
    elif isinstance(auth, AWSV4SignerAuth):
        url = f'{base_url}/app/dashboards?security_tenant={tenant}'
        response = requests.get(url, headers=headers, auth=auth)
    else:
        logger.error('There is no valid authentication')
        return False
    if response.status_code in (200, ):
        logger.info('Authentication success to access kibana')
        return response.cookies
    else:
        print(response.cookies)
        logger.error("Authentication failed to access kibana")
        logger.error(response.reason)
        return False


def get_saved_objects(es_endpoint, dist_name, cookies, auth=None):
    if not cookies:
        logger.warning("No authentication. Skipped downloading dashboard")
        return False
    if dist_name == 'opensearch':
        url = f'https://{es_endpoint}/_dashboards/api/saved_objects/_export'
        headers = DASHBOARDS_HEADERS
    else:
        url = f'https://{es_endpoint}/_plugin/kibana/api/saved_objects/_export'
        headers = KIBANA_HEADERS
    payload = {'type': ['config', 'dashboard', 'visualization',
                        'index-pattern', 'search']}
    if auth:
        response = requests.post(url, cookies=cookies, headers=headers,
                                 json=json.dumps(payload), auth=auth)
    else:
        response = requests.post(url, cookies=cookies, headers=headers,
                                 json=json.dumps(payload))
    logger.debug(response.status_code)
    logger.debug(response.reason)
    return response.content


def backup_dashboard_to_s3(saved_objects, tenant):
    now_str = datetime.now().strftime('%Y%m%d_%H%M%S')
    dashboard_file = f'{tenant}-dashboard-{now_str}.ndjson'
    if saved_objects and isinstance(saved_objects, bytes):
        with open(f'/tmp/{dashboard_file}', 'wb') as ndjson_file:
            ndjson_file.write(saved_objects)
        with ZipFile(f'/tmp/{dashboard_file}.zip', 'w',
                     compression=ZIP_DEFLATED) as bk_dashboard_zip:
            bk_dashboard_zip.write(
                f'/tmp/{dashboard_file}', arcname=dashboard_file)
    else:
        logging.error('failed to export dashboard')
        return False
    try:
        s3_snapshot_bucket.upload_file(
            Filename=f'/tmp/{dashboard_file}.zip',
            Key=f'saved_objects/{dashboard_file}.zip')
        return True
    except Exception as err:
        logging.error('failed to upload dashboard to S3')
        logging.error(err)
        return False


def load_dashboard_into_aes(es_endpoint, dist_name, auth, cookies):
    with ZipFile('dashboard.ndjson.zip') as new_dashboard_zip:
        new_dashboard_zip.extractall('/tmp/')
    files = {'file': open('/tmp/dashboard.ndjson', 'rb')}
    if dist_name == 'opensearch':
        url = (f'https://{es_endpoint}/_dashboards/api/saved_objects/'
               f'_import?overwrite=true')
        headers = {'osd-xsrf': 'true'}
    else:
        url = (f'https://{es_endpoint}/_plugin/kibana/api/saved_objects/'
               f'_import?overwrite=true')
        headers = {'kbn-xsrf': 'true'}
    response = requests.post(url, cookies=cookies, files=files,
                             headers=headers, auth=auth)
    logger.info(response.text)


def aes_domain_handler(event, context):
    helper_domain(event, context)


@helper_domain.create
def aes_domain_create(event, context):
    logger.info("Got Create")
    if event:
        logger.debug(json.dumps(event, default=json_serial))
    setup_aes_system_log()
    try:
        response = opensearch_client.create_domain(**config_domain)
    except botocore.exceptions.ClientError:
        logger.exception('retry in 60s')
        time.sleep(60)
        response = opensearch_client.create_domain(**config_domain)
    time.sleep(3)
    logger.debug(json.dumps(response, default=json_serial))
    if (response['DomainStatus']['Created']
            and not response['DomainStatus']['Processing']):
        raise Exception('OpenSearch Domain already exists. Aborted. '
                        'Remove the domain and re-deploy')
    kibanapass = make_password(8)
    helper_domain.Data.update({"kibanapass": kibanapass})
    logger.info("End Create. To be continue in poll create")
    return True


@helper_domain.poll_create
def aes_domain_poll_create(event, context):
    logger.info("Got create poll")
    suffix = ''.join(secrets.choice(string.ascii_uppercase) for i in range(8))
    physicalResourceId = f'aes-siem-domain-{__version__}-{suffix}'
    kibanapass = helper_domain.Data.get('kibanapass')
    if not kibanapass:
        kibanapass = 'MASKED'
    response = opensearch_client.describe_domain(DomainName=aesdomain)
    logger.debug('Processing domain creation')
    logger.debug(json.dumps(response, default=json_serial))
    is_processing = response['DomainStatus']['Processing']
    if is_processing:
        return None

    logger.info('OpenSearch Service domain is created')

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
        logger.info('Finished doman configuration with new random password')

    es_endpoint = None
    while not es_endpoint:
        time.sleep(10)  # wait to finish setup of endpoint
        logger.debug('Processing ES endpoint creation')
        response = opensearch_client.describe_domain(DomainName=aesdomain)
        es_endpoint = response['DomainStatus'].get('Endpoint')
        if not es_endpoint and 'Endpoints' in response['DomainStatus']:
            es_endpoint = response['DomainStatus']['Endpoints']['vpc']
    logger.debug('Finished ES endpoint creation')

    # ToDo: import dashboard for aesadmin private tenant
    # tenant = 'private'
    # auth = {'username': 'aesadmin', 'password': kibanapass}
    # cookies = set_tenant_get_cookies(es_endpoint, dist_name, tenant, auth)
    # load_dashboard_into_aes(es_endpoint, dist_name, auth, cookies)

    if event and 'RequestType' in event:
        # Response For CloudFormation Custome Resource
        helper_domain.Data['es_endpoint'] = es_endpoint
        helper_domain.Data['kibanaadmin'] = KIBANAADMIN
        helper_domain.Data['kibanapass'] = kibanapass
        logger.info("End create poll")
        return physicalResourceId


@helper_domain.update
def aes_domain_update(event, context):
    logger.info("Got Update")
    response = opensearch_client.describe_domain(DomainName=aesdomain)
    es_endpoint = response['DomainStatus'].get('Endpoint')
    if not es_endpoint and 'Endpoints' in response['DomainStatus']:
        es_endpoint = response['DomainStatus']['Endpoints']['vpc']

    suffix = ''.join(secrets.choice(string.ascii_uppercase) for i in range(8))
    physicalResourceId = f'aes-siem-domain-{__version__}-{suffix}'
    if event and 'RequestType' in event:
        # Response For CloudFormation Custome Resource
        helper_domain.Data['es_endpoint'] = es_endpoint
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
    es_app_data.read('data.ini')
    es_endpoint = os.environ['es_endpoint']

    dist_name, domain_version = get_dist_version(es_endpoint)
    if domain_version in ('7.4.2', '7.7.0', '7.8.0', '7.9.1'):
        raise Exception(f'Your domain version is Amazon ES {domain_version}. '
                        f'Please upgrade the domain to OpenSearch or '
                        f'Amazon ES v7.10')
    configure_opendistro(es_endpoint, es_app_data)
    configure_siem(es_endpoint, es_app_data)
    configure_index_rollover(es_endpoint, es_app_data)

    # Globalテナントのsaved_objects をバックアップする
    tenant = 'global'
    awsauth = auth_aes(es_endpoint)
    cookies = set_tenant_get_cookies(es_endpoint, dist_name, tenant, awsauth)
    saved_objects = get_saved_objects(
        es_endpoint, dist_name, cookies, auth=awsauth)
    bk_response = backup_dashboard_to_s3(saved_objects, tenant)
    if bk_response:
        # Load dashboard and configuration to Global tenant
        load_dashboard_into_aes(es_endpoint, dist_name, awsauth, cookies)

    if event and 'RequestType' in event:
        # Response For CloudFormation Custome Resource
        logger.info("End create poll")
        return physicalResourceId


@helper_config.delete
def aes_config_delete(event, context):
    logger.info("Got Delete. Nothing to delete")


if __name__ == '__main__':
    aes_domain_handler(None, None)
    aes_config_handler(None, None)
