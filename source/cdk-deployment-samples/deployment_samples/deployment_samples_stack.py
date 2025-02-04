# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.4-beta.1'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import os

import aws_cdk as cdk
from aws_cdk import (
    aws_events,
    aws_events_targets,
    aws_iam,
    aws_kinesisfirehose,
    aws_lambda,
    aws_logs,
    aws_sqs,
    region_info,
)
from aws_cdk.aws_kinesisfirehose import CfnDeliveryStream as CDS
from constructs import Construct

region = os.environ.get("CDK_DEPLOY_REGION", os.environ["CDK_DEFAULT_REGION"])
PARTITION = region_info.Fact.find(region, region_info.FactName.PARTITION)

LAMBDA_GET_WORKSPACES_INVENTORY = '''# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.4-beta.1'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import datetime
import gzip
import json
import os
import time

import boto3
from botocore.config import Config

config = Config(retries={'max_attempts': 10, 'mode': 'standard'})
ws_client = boto3.client('workspaces', config=config)
s3_resource = boto3.resource('s3')
bucket = s3_resource.Bucket(os.environ['log_bucket_name'])
AWS_ID = str(boto3.client("sts").get_caller_identity()["Account"])
AWS_REGION = os.environ['AWS_DEFAULT_REGION']


def json_serial(obj):
    if isinstance(obj, datetime.datetime):
        return obj.isoformat()
    else:
        return str(obj)


def lambda_handler(event, context):
    num = 0
    now = datetime.datetime.now()
    file_name = f'workspaces-inventory-{now.strftime("%Y%m%d_%H%M%S")}.json.gz'
    s3file_name = (
        f'AWSLogs/{AWS_ID}/WorkSpaces/Inventory/{AWS_REGION}/'
        f'{now.strftime("%Y/%m/%d")}/{file_name}')
    f = gzip.open(f'/tmp/{file_name}', 'tw')

    api = 'describe_workspaces_connection_status'
    print(api)
    ws_cons = {}
    num = 0
    paginator = ws_client.get_paginator(api)
    for response in paginator.paginate():
        for ws_con in response['WorkspacesConnectionStatus']:
            ws_cons[ws_con['WorkspaceId']] = ws_con
            num += 1
        time.sleep(0.75)
    print(f'Number of {api}: {num}')

    api = 'describe_workspaces'
    print(api)
    num = 0
    paginator = ws_client.get_paginator(api)
    response_iterator = paginator.paginate(PaginationConfig={'PageSize': 25})
    for response in response_iterator:
        print(f'{response["ResponseMetadata"]["RequestId"]}: '
              f'{len(response["Workspaces"])}')
        dt = datetime.datetime.strptime(
            response['ResponseMetadata']['HTTPHeaders']['date'],
            "%a, %d %b %Y %H:%M:%S GMT")
        jsonobj = {
            'id': response['ResponseMetadata']['RequestId'],
            'time': dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            'detail-type': 'WorkSpaces Fake',
            "source": "aws.fake.workspaces",
            "account": AWS_ID,
            'region': AWS_REGION,
            "resources": [],
            'detail': {'Workspaces': []}}
        for item in response['Workspaces']:
            try:
                item = {**item, **ws_cons[item['WorkspaceId']]}
            except Exception:
                pass
            jsonobj['detail']['Workspaces'].append(item)
        num += len(response['Workspaces'])
        f.write(json.dumps(jsonobj, default=json_serial))
        f.flush()
        # sleep 0.75 second to avoid reaching AWS API rate limit (2rps)
        time.sleep(0.75)
    print(f'Total nummber of WorkSpaces inventory: {num}')

    f.close()
    print(f'Upload path: s3://{bucket.name}/{s3file_name}')
    bucket.upload_file(f'/tmp/{file_name}', s3file_name)
'''


LAMBDA_GET_TRUSTEDADVISOR_CHECK_RESULT = '''# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = 'Amazon.com, Inc. or its affiliates'
__version__ = '2.10.4-beta.1'
__license__ = 'MIT-0'
__author__ = 'Katsuya Matsuoka'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import copy
import datetime
import gzip
import json
import os
import time

import boto3
import botocore.exceptions

client = boto3.Session(region_name='us-east-1').client('support')
s3_resource = boto3.resource('s3')
bucket = s3_resource.Bucket(os.environ['log_bucket_name'])
AWS_ID = str(boto3.client("sts").get_caller_identity()["Account"])
AWS_REGION = 'us-east-1'
is_enable_japanese = (os.environ['enable_japanese_description'] == 'Yes')

try:
    res = client.describe_trusted_advisor_checks(language='en')
except botocore.exceptions.ClientError:
    print('Aborted. Business or Enterprise Support Subscription is required')
    raise
CHECKS_EN = res['checks']

CHECKS_JA = {}
if is_enable_japanese:
    for check_ja in client.describe_trusted_advisor_checks(
            language='ja')['checks']:
        CHECKS_JA[check_ja['id']] = check_ja


def execute_check():
    check_ids = []
    unrefreshable_check_ids = []
    for check in CHECKS_EN:
        check_ids.append(check['id'])
        try:
            client.refresh_trusted_advisor_check(checkId=check['id'])
        except botocore.exceptions.ClientError as err:
            err_code = err.response['Error']['Code']
            if err_code == 'InvalidParameterValueException':
                unrefreshable_check_ids.append(check['id'])
            else:
                print(err)
    return check_ids, unrefreshable_check_ids


CHECK_IDS, UNREFRESHABLE_CHECK_IDS = execute_check()


def refresh_and_wait_check_completion():
    count = 0
    all_done = False
    while not all_done:
        response = client.describe_trusted_advisor_check_refresh_statuses(
            checkIds=CHECK_IDS)
        time.sleep(30)
        all_done = True
        for status in response['statuses']:
            if status['status'] not in ['abandoned', 'none', 'success']:
                all_done = False
        if count > 2:
            break
        count += 1


def query_and_transform_and_save(f, check):
    res = client.describe_trusted_advisor_check_result(
        checkId=check['id'])
    jsonobj = {
        'requestid': res['ResponseMetadata']['RequestId'],
        'creation_date': datetime.datetime.utcnow().isoformat(),
        'account': AWS_ID, 'check': check, 'result': copy.copy(res['result']),
        'refreshable': check['id'] not in UNREFRESHABLE_CHECK_IDS}
    if is_enable_japanese:
        jsonobj['check_ja'] = CHECKS_JA[check['id']]
    f.write(json.dumps(jsonobj, ensure_ascii=False))
    if ('flaggedResources' in res['result']
            and len(res['result']['flaggedResources']) > 0):
        del jsonobj['result']['flaggedResources']
        del jsonobj['result']['resourcesSummary']
        del jsonobj['result']['categorySpecificSummary']
        for i in range(len(res['result']['flaggedResources'])):
            jsonobj['result']['flaggedResource'] = (
                res['result']['flaggedResources'][i])
            jsonobj['result']['flaggedResource']['number'] = i + 1
            f.write(json.dumps(jsonobj, ensure_ascii=False))


def lambda_handler(event, context):
    now = datetime.datetime.now()
    file_name = (
        'trustedadvisor-check-results-'
        f'{now.strftime("%Y%m%d_%H%M%S")}.json.gz')
    s3file_name = (
        f'AWSLogs/{AWS_ID}/TrustedAdvisor/{AWS_REGION}/'
        f'{now.strftime("%Y/%m/%d")}/{file_name}')
    f = gzip.open(f'/tmp/{file_name}', 'tw')
    print(f'Total nummber of checks: {len(CHECKS_EN)}')
    refresh_and_wait_check_completion()
    for check in CHECKS_EN:
        query_and_transform_and_save(f, check)
    f.close()
    print(f'Upload path: s3://{bucket.name}/{s3file_name}')
    bucket.upload_file(f'/tmp/{file_name}', s3file_name)
'''

if region.startswith('cn-'):
    LAMBDA_GET_TRUSTEDADVISOR_CHECK_RESULT = (
        LAMBDA_GET_TRUSTEDADVISOR_CHECK_RESULT.replace(
            'us-east-1', 'cn-north-1'))


class MyStack(cdk.Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(
            scope, construct_id,
            synthesizer=cdk.DefaultStackSynthesizer(
                generate_bootstrap_version_rule=False),
            **kwargs)


class FirehoseExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str,
                 default_firehose_name='siem-XXXXXXXXXXX-to-s3',
                 firehose_compression_format='UNCOMPRESSED',
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name-v2')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name-v2')

        kdf_name = cdk.CfnParameter(
            self, 'FirehoseName',
            description=('Define new Kinesis Data Firehose Name to deliver '
                         'log. modify XXXXXXXXX'),
            default=default_firehose_name)
        kdf_buffer_size = cdk.CfnParameter(
            self, 'FirehoseBufferSize', type='Number',
            description='Enter a buffer size between 1 - 128 (MiB)',
            default=1, min_value=1, max_value=128)
        kdf_buffer_interval = cdk.CfnParameter(
            self, 'FirehoseBufferInterval', type='Number',
            description='Enter a buffer interval between 60 - 900 (seconds.)',
            default=60, min_value=60, max_value=900)
        s3_desitination_prefix = cdk.CfnParameter(
            self, 'S3DestPrefix',
            description='Define S3 destination prefix',
            default='AWSLogs/YourAccuntId/LogType/Region/')

        self.kdf_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "Kdf",
            delivery_stream_name=kdf_name.value_as_string,
            s3_destination_configuration=CDS.S3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                prefix=s3_desitination_prefix.value_as_string,
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format=firehose_compression_format,
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}')
            )
        )


class CWLNoCompressExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name-v2')
        role_name_cwl_to_kdf = cdk.Fn.import_value(
            'siem-cwl-to-kdf-role-name-v2')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name-v2')

        kdf_name = cdk.CfnParameter(
            self, 'KdfName',
            description=(
                'Define new Kinesis Data Firehose Name to deliver CWL event'),
            default='siem-XXXXXXXXXXX-to-s3')
        kdf_buffer_size = cdk.CfnParameter(
            self, 'KdfBufferSize', type='Number',
            description='Enter a buffer size between 1 - 128 (MiB)',
            default=1, min_value=1, max_value=128)
        kdf_buffer_interval = cdk.CfnParameter(
            self, 'KdfBufferInterval', type='Number',
            description='Enter a buffer interval between 60 - 900 (seconds.)',
            default=60, min_value=60, max_value=900)
        cwl_loggroup_name = cdk.CfnParameter(
            self, 'CwlLogGroupName',
            description='Define existing CloudWatch Logs group name',
            default='/aws/XXXXXXXXXXXXXXXXX')
        s3_desitination_prefix = cdk.CfnParameter(
            self, 'S3DestPrefix',
            description='Define S3 destination prefix',
            default='AWSLogs/YourAccuntId/LogType/Region/')

        kdf_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "Kdf",
            delivery_stream_name=kdf_name.value_as_string,
            s3_destination_configuration=CDS.S3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                prefix=s3_desitination_prefix.value_as_string,
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}')
            )
        )

        aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscription',
            destination_arn=kdf_to_s3.attr_arn,
            filter_pattern='',
            log_group_name=cwl_loggroup_name.value_as_string,
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )


class EventBridgeEventsExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name-v2')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name-v2')

        kdf_name = cdk.CfnParameter(
            self, 'KdfName',
            description=(
                'Define new Kinesis Data Firehose Name to deliver EventBridge '
                'Events to S3 bucket. This Firehose will be created'),
            default='siem-eventbridge-events-to-s3')
        kdf_buffer_size = cdk.CfnParameter(
            self, 'KdfBufferSize', type='Number',
            description='Enter a buffer size between 64 - 128 (MiB)',
            default=64, min_value=64, max_value=128)
        kdf_buffer_interval = cdk.CfnParameter(
            self, 'KdfBufferInterval', type='Number',
            description='Enter a buffer interval between 60 - 900 (seconds.)',
            default=60, min_value=60, max_value=900)
        load_inspector = cdk.CfnParameter(
            self, 'LoadInspector',
            description=('Do you enable to load Inspector events to '
                         'OpenSearch Service?'),
            allowed_values=['Yes', 'No'], default='Yes')
        load_security_hub = cdk.CfnParameter(
            self, 'LoadSecurtyHub',
            description=('Do you enable to load SecurityHub events to '
                         'OpenSearch Service?'),
            allowed_values=['Yes', 'No'], default='Yes')
        load_config_rules = cdk.CfnParameter(
            self, 'LoadConfigRules',
            description=('Do you enable to load Config Rules events to '
                         'OpenSearch Service?'),
            allowed_values=['Yes', 'No'], default='Yes')

        s3_desitination_prefix = cdk.CfnParameter(
            self, 'S3DestPrefix',
            description='Define S3 destination prefix',
            default='AWSLogs/')

        self.template_options.metadata = {
            'AWS::CloudFormation::Interface': {
                'ParameterGroups': [
                    {'Label': {'default': 'Amazon Kinesis Data Firehose'},
                     'Parameters': [kdf_name.logical_id,
                                    s3_desitination_prefix.logical_id,
                                    kdf_buffer_size.logical_id,
                                    kdf_buffer_interval.logical_id]},
                    {'Label': {'default': 'Events'},
                     'Parameters': [load_inspector.logical_id,
                                    load_security_hub.logical_id,
                                    load_config_rules.logical_id]}]}}

        kdf_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "Kdf",
            delivery_stream_name=kdf_name.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                # Destination settings
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',

                error_output_prefix="ErrorLogs/",
                prefix=(s3_desitination_prefix.value_as_string + "!{partitionKeyFromQuery:account}/!{partitionKeyFromQuery:service}/!{partitionKeyFromQuery:detailtype}/!{partitionKeyFromQuery:region}/!{timestamp:yyyy}/!{timestamp:MM}/!{timestamp:dd}/"),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='GZIP',
                dynamic_partitioning_configuration=aws_kinesisfirehose.CfnDeliveryStream.DynamicPartitioningConfigurationProperty(
                    enabled=True,
                    retry_options=aws_kinesisfirehose.CfnDeliveryStream.RetryOptionsProperty(
                        duration_in_seconds=30)
                ),
                processing_configuration=aws_kinesisfirehose.CfnDeliveryStream.ProcessingConfigurationProperty(
                    enabled=True,
                    processors=[
                        aws_kinesisfirehose.CfnDeliveryStream.ProcessorProperty(
                            type="MetadataExtraction",
                            parameters=[
                                aws_kinesisfirehose.CfnDeliveryStream.ProcessorParameterProperty(
                                    parameter_name="MetadataExtractionQuery",
                                    parameter_value="""{service: .source, account: .account, region: .region, detailtype: ."detail-type"| gsub(" "; "_")}"""),
                                aws_kinesisfirehose.CfnDeliveryStream.ProcessorParameterProperty(
                                    parameter_name="JsonParsingEngine",
                                    parameter_value="JQ-1.6")

                            ]
                        )
                    ]
                ),
                # Permissions
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}'),
            )
        )

        is_inspector = cdk.CfnCondition(
            self, "IsInspector",
            expression=cdk.Fn.condition_equals(load_inspector.value_as_string, "Yes"))
        rule_inspector = aws_events.Rule(
            self, "RuleInspector", rule_name='siem-inspector-to-firehose',
            description=f'SIEM on OpenSearch Service v{__version__}:',
            event_pattern=aws_events.EventPattern(
                source=["aws.inspector2"],
                detail_type=["Inspector2 Coverage", "Inspector2 Finding"]
            ))
        rule_inspector.node.default_child.cfn_options.condition = is_inspector
        rule_inspector.add_target(aws_events_targets.KinesisFirehoseStream(kdf_to_s3))

        is_security_hub = cdk.CfnCondition(
            self, "IsSecurityHub",
            expression=cdk.Fn.condition_equals(load_security_hub.value_as_string, "Yes"))
        rule_security_hub = aws_events.Rule(
            self, "RuleSecurityHub", rule_name='siem-securityhub-to-firehose',
            description=f'SIEM on OpenSearch Service v{__version__}:',
            event_pattern=aws_events.EventPattern(
                source=["aws.securityhub"],
                detail_type=["Security Hub Findings - Imported"]))
        rule_security_hub.node.default_child.cfn_options.condition = is_security_hub
        rule_security_hub.add_target(aws_events_targets.KinesisFirehoseStream(kdf_to_s3))

        is_config_rules = cdk.CfnCondition(
            self, "IsConfigRules",
            expression=cdk.Fn.condition_equals(load_config_rules.value_as_string, "Yes"))
        rule_config_rules = aws_events.Rule(
            self, "RuleConfigRules", rule_name='siem-configrules-to-firehose',
            description=f'SIEM on OpenSearch Service v{__version__}:',
            event_pattern=aws_events.EventPattern(
                source=["aws.config"],
                detail_type=["Config Rules Compliance Change"]))
        rule_config_rules.node.default_child.cfn_options.condition = is_config_rules
        rule_config_rules.add_target(aws_events_targets.KinesisFirehoseStream(kdf_to_s3))


class ADLogExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name-v2')
        role_name_cwl_to_kdf = cdk.Fn.import_value(
            'siem-cwl-to-kdf-role-name-v2')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name-v2')

        kdf_ad_name = cdk.CfnParameter(
            self, 'KdfAdName',
            description=('Define new Kinesis Data Firehose Name '
                         'to deliver AD event'),
            default='siem-ad-event-to-s3')
        kdf_buffer_size = cdk.CfnParameter(
            self, 'KdfBufferSize', type='Number',
            description='Enter a buffer size between 1 - 128 (MiB)',
            default=1, min_value=1, max_value=128)
        kdf_buffer_interval = cdk.CfnParameter(
            self, 'KdfBufferInterval', type='Number',
            description='Enter a buffer interval between 60 - 900 (seconds.)',
            default=60, min_value=60, max_value=900)
        cwl_ad_name = cdk.CfnParameter(
            self, 'CwlAdName',
            description='Specify CloudWatch Logs group name',
            default='/aws/directoryservice/d-XXXXXXXXXXXXXXXXX')

        kdf_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KDFForAdEventLog",
            delivery_stream_name=kdf_ad_name.value_as_string,
            s3_destination_configuration=CDS.S3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                prefix=f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/DirectoryService/MicrosoftAD/',
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}')
            )
        )

        aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscription',
            destination_arn=kdf_to_s3.attr_arn,
            filter_pattern='',
            log_group_name=cwl_ad_name.value_as_string,
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )


class WorkSpacesLogExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name-v2')
        service_role_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name-v2')

        cwe_frequency = cdk.CfnParameter(
            self, 'cweRulesFrequency', type='Number',
            description=(
                'How often do you get WorkSpaces Inventory? (every minutes)'),
            default=720)
        kdf_workspaces_name = cdk.CfnParameter(
            self, 'KdfWorkSpacesName',
            description=(
                'Define new Kinesis Data Firehose Name to deliver '
                'workspaces event'),
            default='siem-workspaces-event-to-s3',)
        kdf_buffer_size = cdk.CfnParameter(
            self, 'KdfBufferSize', type='Number',
            description='Enter a buffer size between 1 - 128 (MiB)',
            default=1, min_value=1, max_value=128)
        kdf_buffer_interval = cdk.CfnParameter(
            self, 'KdfBufferInterval', type='Number',
            description='Enter a buffer interval between 60 - 900 (seconds.)',
            default=60, min_value=60, max_value=900)

        role_get_workspaces_inventory = aws_iam.Role(
            self, 'getWorkspacesInventoryRole',
            role_name='siem-get-workspaces-inventory-role',
            inline_policies={
                'describe-workspaces': aws_iam.PolicyDocument(
                    statements=[
                        aws_iam.PolicyStatement(
                            actions=['workspaces:Describe*'], resources=['*'],
                            sid='DescribeWorkSpacesPolicyGeneratedBySiemCfn')
                    ]
                ),
                'firehose-to-s3': aws_iam.PolicyDocument(
                    statements=[
                        aws_iam.PolicyStatement(
                            actions=['s3:PutObject'],
                            resources=[f'arn:{PARTITION}:s3:::{log_bucket_name}/*'],
                            sid='FirehoseToS3PolicyGeneratedBySiemCfn'
                        )
                    ]
                )
            },
            managed_policies=[
                aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                    'service-role/AWSLambdaBasicExecutionRole'),
            ],
            assumed_by=aws_iam.ServicePrincipal('lambda.amazonaws.com')
        )

        # Lambda Functions to get workspaces inventory
        lambda_func = aws_lambda.Function(
            self, 'lambdaGetWorkspacesInventory',
            runtime=aws_lambda.Runtime.PYTHON_3_11,
            code=aws_lambda.InlineCode(LAMBDA_GET_WORKSPACES_INVENTORY),
            function_name='siem-get-workspaces-inventory',
            description='SIEM: get workspaces inventory',
            handler='index.lambda_handler',
            memory_size=160,
            timeout=cdk.Duration.seconds(600),
            role=role_get_workspaces_inventory,
            environment={'log_bucket_name': log_bucket_name}
        )
        rule = aws_events.Rule(
            self, 'eventBridgeRuleWorkSpaceInventory',
            rule_name='siem-workspaces-inventory-to-lambda',
            schedule=aws_events.Schedule.rate(
                cdk.Duration.minutes(cwe_frequency.value_as_number)))
        rule.add_target(aws_events_targets.LambdaFunction(lambda_func))

        kdf_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KDFForWorkSpacesEvent",
            delivery_stream_name=kdf_workspaces_name.value_as_string,
            s3_destination_configuration=CDS.S3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                prefix=f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/WorkSpaces/Event/',
                compression_format='GZIP',
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{service_role_kdf_to_s3}')
            )
        )

        pattern = aws_events.EventPattern(
            detail_type=["WorkSpaces Access"], source=['aws.workspaces'])

        aws_events.Rule(
            self, 'eventBridgeRuleWorkSpacesEvent', event_pattern=pattern,
            rule_name='siem-workspaces-event-to-kdf',
            targets=[aws_events_targets.KinesisFirehoseStream(kdf_to_s3)])


class TrustedAdvisorLogExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name-v2')

        cwe_frequency = cdk.CfnParameter(
            self, 'cweRulesFrequency', type='Number',
            description=(
                'How often do you get TrustedAdvisor check result? (every minutes)'),
            default=720)
        enable_japanese_description = cdk.CfnParameter(
            self, 'enableJapaneseDescription',
            description=(
                'Do you enable Japanese check descriptino in addition to English?'),
            allowed_values=['Yes', 'No'], default='Yes')

        role_get_trustedadvisor_check_result = aws_iam.Role(
            self, 'getTrustedAdvisorCheckResultRole',
            role_name='siem-get-trustedadvisor-check-result-role',
            inline_policies={
                'describe-trustedadvisor': aws_iam.PolicyDocument(
                    statements=[
                        aws_iam.PolicyStatement(
                            actions=[
                                'support:DescribeTrustedAdvisorCheck*',
                                'support:RefreshTrustedAdvisorCheck'
                            ],
                            resources=['*'],
                            sid='DescribeTrustedAdvisorPolicyGeneratedBySiemCfn')
                    ]
                ),
                'lambda-to-s3': aws_iam.PolicyDocument(
                    statements=[
                        aws_iam.PolicyStatement(
                            actions=['s3:PutObject'],
                            resources=[f'arn:{PARTITION}:s3:::{log_bucket_name}/*'],
                            sid='LambdaToS3PolicyGeneratedBySiemCfn'
                        )
                    ]
                )
            },
            managed_policies=[
                aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                    'service-role/AWSLambdaBasicExecutionRole'),
            ],
            assumed_by=aws_iam.ServicePrincipal('lambda.amazonaws.com')
        )

        # Lambda Functions to get trustedadvisor check result
        lambda_func = aws_lambda.Function(
            self, 'lambdaGetTrustedAdvisorCheckResult',
            runtime=aws_lambda.Runtime.PYTHON_3_8,
            code=aws_lambda.InlineCode(LAMBDA_GET_TRUSTEDADVISOR_CHECK_RESULT),
            function_name='siem-get-trustedadvisor-check-result',
            description='SIEM: get trustedadvisor check result',
            handler='index.lambda_handler',
            timeout=cdk.Duration.seconds(600),
            role=role_get_trustedadvisor_check_result,
            environment={
                'log_bucket_name': log_bucket_name,
                'enable_japanese_description': enable_japanese_description.value_as_string}
        )
        rule = aws_events.Rule(
            self, 'eventBridgeRuleTrustedAdvisorCheckResult',
            rule_name='siem-trustedadvisor-check-result-to-lambda',
            schedule=aws_events.Schedule.rate(
                cdk.Duration.minutes(cwe_frequency.value_as_number)))
        rule.add_target(aws_events_targets.LambdaFunction(lambda_func))


class CloudHsmCWLogsExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name-v2')
        role_name_cwl_to_kdf = cdk.Fn.import_value(
            'siem-cwl-to-kdf-role-name-v2')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name-v2')

        kdf_hsm_name = cdk.CfnParameter(
            self, 'KdfHsmName',
            description=('Define new Kinesis Data Firehose Name '
                         'to deliver CloudHSM CloudWatch Logs'),
            default='siem-cloudhsm-cwl-to-s3')
        kdf_buffer_size = cdk.CfnParameter(
            self, 'KdfBufferSize', type='Number',
            description='Enter a buffer size between 64 - 128 (MiB)',
            default=64, min_value=64, max_value=128)
        kdf_buffer_interval = cdk.CfnParameter(
            self, 'KdfBufferInterval', type='Number',
            description='Enter a buffer interval between 60 - 900 (seconds.)',
            default=60, min_value=60, max_value=900)
        cwl_hsm_name = cdk.CfnParameter(
            self, 'CwlHsmName',
            description='Specify CloudWatch Logs group name',
            default='/aws/cloudhsm/cluster-XXXXXXXXXXX')

        self.template_options.metadata = {
            'AWS::CloudFormation::Interface': {
                'ParameterGroups': [
                    {'Label': {'default': 'CloudWatch Logs'},
                     'Parameters': [cwl_hsm_name.logical_id]},
                    {'Label': {'default': 'Amazon Kinesis Data Firehose'},
                     'Parameters': [kdf_hsm_name.logical_id,
                                    kdf_buffer_size.logical_id,
                                    kdf_buffer_interval.logical_id]}]
            }
        }

        kdf_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "Kdf",
            delivery_stream_name=kdf_hsm_name.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/",
                prefix=(f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/CloudHSM/'
                        f'{cdk.Aws.REGION}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}'),
            )
        )

        aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscription',
            destination_arn=kdf_to_s3.attr_arn,
            filter_pattern='',
            log_group_name=cwl_hsm_name.value_as_string,
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )


class RDSMySQLCWLogsExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name-v2')
        role_name_cwl_to_kdf = cdk.Fn.import_value(
            'siem-cwl-to-kdf-role-name-v2')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name-v2')

        cw_log_group_name_of_mysql_audit_log = cdk.CfnParameter(
            self, 'CwLogGroupNameOfMySQLAuditLog',
            description=('Specify CloudWatch Logs group name of '
                         'RDS MySQL audit log. '
                         'e.g.) /aws/rds/instance/wordpress-db/audit . '
                         'If you would not like to the log to SIEM, '
                         'leave it blank.'),)
        cw_log_group_name_of_mysql_error_log = cdk.CfnParameter(
            self, 'CwLogGroupNameOfMySQLErrorLog',
            description=('Specify CloudWatch Logs group name of '
                         'RDS MySQL error log. '
                         'e.g.) /aws/rds/instance/wordpress-db/error . '
                         'If you would not like to the log to SIEM, '
                         'leave it blank.'),)
        cw_log_group_name_of_mysql_general_log = cdk.CfnParameter(
            self, 'CwLogGroupNameOfMySQLGeneralLog',
            description=('Specify CloudWatch Logs group name of '
                         'RDS MySQL general log. '
                         'e.g.) /aws/rds/instance/wordpress-db/general . '
                         'If you would not like to the log to SIEM, '
                         'leave it blank.'),)
        cw_log_group_name_of_mysql_slowquery_log = cdk.CfnParameter(
            self, 'CwLogGroupNameOfMySQLSlowQueryLog',
            description=('Specify CloudWatch Logs group name of '
                         'RDS MySQL slowquery log. '
                         'e.g.) /aws/rds/instance/wordpress-db/slowquery . '
                         'If you would not like to the log to SIEM, '
                         'leave it blank.'),)

        create_firehose = cdk.CfnParameter(
            self, 'CreateFirehose',
            description=('Would you like to create Kinesis Data Firehose for '
                         'SIEM solution and RDS?'),
            allowed_values=['create_a_new_one', 'use_existing'],
            default='create_a_new_one')
        kdf_buffer_size = cdk.CfnParameter(
            self, 'KdfBufferSize', type='Number',
            description='Enter a buffer size between 64 - 128 (MiB)',
            default=64, min_value=64, max_value=128)
        kdf_buffer_interval = cdk.CfnParameter(
            self, 'KdfBufferInterval', type='Number',
            description='Enter a buffer interval between 60 - 900 (seconds.)',
            default=60, min_value=60, max_value=900)

        kdf_name_of_mysql_audit_log = cdk.CfnParameter(
            self, 'FirehoseNameForMySqlAudit',
            description=('Define Kinesis Data Firehose Name for '
                         'RDS (Aurora MySQL / MySQL / MariaDB) audit log. '
                         'e.g.) siem-rds-mysql-audit-log-cwl-to-s3'),
            default='siem-rds-mysql-audit-log-cwl-to-s3')
        kdf_name_of_mysql_error_log = cdk.CfnParameter(
            self, 'FirehoseNameForMySqlError',
            description=('Define Kinesis Data Firehose Name for '
                         'RDS (Aurora MySQL / MySQL / MariaDB) error log. '
                         'e.g.) siem-rds-mysql-error-log-cwl-to-s3'),
            default='siem-rds-mysql-error-log-cwl-to-s3')
        kdf_name_of_mysql_general_log = cdk.CfnParameter(
            self, 'FirehoseNameForMySqlGeneral',
            description=('Define Kinesis Data Firehose Name for '
                         'RDS (Aurora MySQL / MySQL / MariaDB) general log. '
                         'e.g.) siem-rds-mysql-general-log-cwl-to-s3'),
            default='siem-rds-mysql-general-log-cwl-to-s3')
        kdf_name_of_mysql_slowquery_log = cdk.CfnParameter(
            self, 'FirehoseNameForMySqlSlowQuery',
            description=('Define Kinesis Data Firehose Name for '
                         'RDS (Aurora MySQL / MySQL / MariaDB) slowquery log. '
                         'e.g.) siem-rds-mysql-slowquery-log-cwl-to-s3'),
            default='siem-rds-mysql-slowquery-log-cwl-to-s3')

        self.template_options.metadata = {
            'AWS::CloudFormation::Interface': {
                'ParameterGroups': [
                    {'Label': {'default': 'CloudWatch Logs'},
                     'Parameters': [
                        cw_log_group_name_of_mysql_audit_log.logical_id,
                        cw_log_group_name_of_mysql_error_log.logical_id,
                        cw_log_group_name_of_mysql_general_log.logical_id,
                        cw_log_group_name_of_mysql_slowquery_log.logical_id]},
                    {'Label': {'default': 'Amazon Kinesis Data Firehose conf'},
                     'Parameters': [create_firehose.logical_id,
                                    kdf_buffer_size.logical_id,
                                    kdf_buffer_interval.logical_id
                                    ]},
                    {'Label': {'default': 'Amazon Kinesis Data Firehose Name'},
                     'Parameters': [kdf_name_of_mysql_audit_log.logical_id,
                                    kdf_name_of_mysql_error_log.logical_id,
                                    kdf_name_of_mysql_general_log.logical_id,
                                    kdf_name_of_mysql_slowquery_log.logical_id
                                    ]},
                ]
            }
        }

        # conditions
        kdf_is_required = cdk.CfnCondition(
            self, "KdfIsRequired",
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_equals(
                    create_firehose.value_as_string, 'create_a_new_one')))

        create_kdf_for_mysql_audit = cdk.CfnCondition(
            self, "CreateKdfForMySQLAudit",
            expression=cdk.Fn.condition_and(
                kdf_is_required,
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        kdf_name_of_mysql_audit_log.value_as_string, ''))))
        create_kdf_for_mysql_error = cdk.CfnCondition(
            self, "CreateKdfForMySQLError",
            expression=cdk.Fn.condition_and(
                kdf_is_required,
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        kdf_name_of_mysql_error_log.value_as_string, ''))))
        create_kdf_for_mysql_general = cdk.CfnCondition(
            self, "CreateKdfForMySQLGeneral",
            expression=cdk.Fn.condition_and(
                kdf_is_required,
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        kdf_name_of_mysql_general_log.value_as_string, ''))))
        create_kdf_for_mysql_slowquery = cdk.CfnCondition(
            self, "CreateKdfForMySQLSlowQuery",
            expression=cdk.Fn.condition_and(
                kdf_is_required,
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        kdf_name_of_mysql_slowquery_log.value_as_string, ''))))

        use_subscription_filter_for_mysql_audit = cdk.CfnCondition(
            self, "SubscribeCwlOfMySQLAudit",
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_not(cdk.Fn.condition_equals(
                    kdf_name_of_mysql_audit_log.value_as_string, '')),
                cdk.Fn.condition_not(cdk.Fn.condition_equals(
                    cw_log_group_name_of_mysql_audit_log.value_as_string, ''))))
        use_subscription_filter_for_mysql_error = cdk.CfnCondition(
            self, "SubscribeCwlOfMySQLError",
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_not(cdk.Fn.condition_equals(
                    kdf_name_of_mysql_error_log.value_as_string, '')),
                cdk.Fn.condition_not(cdk.Fn.condition_equals(
                    cw_log_group_name_of_mysql_error_log.value_as_string, ''))))
        use_subscription_filter_for_mysql_general = cdk.CfnCondition(
            self, "SubscribeCwlOfMySQLGeneral",
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_not(cdk.Fn.condition_equals(
                    kdf_name_of_mysql_general_log.value_as_string, '')),
                cdk.Fn.condition_not(cdk.Fn.condition_equals(
                    cw_log_group_name_of_mysql_general_log.value_as_string,
                    ''))))
        use_subscription_filter_for_mysql_slowquery = cdk.CfnCondition(
            self, "SubscribeCwlOfMySQLSlowQuery",
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_not(cdk.Fn.condition_equals(
                    kdf_name_of_mysql_slowquery_log.value_as_string, '')),
                cdk.Fn.condition_not(cdk.Fn.condition_equals(
                    cw_log_group_name_of_mysql_slowquery_log.value_as_string,
                    ''))))

        # resource
        # ## KDF
        kdf_mysql_audit_log_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KdfRDSMySQLAudit",
            delivery_stream_name=kdf_name_of_mysql_audit_log.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/RDS/MySQL/audit/",
                prefix=(f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/RDS/MySQL/audit/'
                        f'{cdk.Aws.REGION}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}')))
        kdf_mysql_audit_log_to_s3.cfn_options.condition = (
            create_kdf_for_mysql_audit)

        kdf_mysql_error_log_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KdfRDSMySQLError",
            delivery_stream_name=kdf_name_of_mysql_error_log.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/RDS/MySQL/error/",
                prefix=(f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/RDS/MySQL/error/'
                        f'{cdk.Aws.REGION}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}')))
        kdf_mysql_error_log_to_s3.cfn_options.condition = (
            create_kdf_for_mysql_error)

        kdf_mysql_general_log_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KdfRDSMySQLGeneral",
            delivery_stream_name=kdf_name_of_mysql_general_log.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/RDS/MySQL/general/",
                prefix=(f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/RDS/MySQL/general/'
                        f'{cdk.Aws.REGION}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}')))
        kdf_mysql_general_log_to_s3.cfn_options.condition = (
            create_kdf_for_mysql_general)

        kdf_mysql_slowquery_log_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KdfRDSMySQLSlowQuery",
            delivery_stream_name=kdf_name_of_mysql_slowquery_log.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/RDS/MySQL/slowquery/",
                prefix=(f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/RDS/MySQL/slowquery/'
                        f'{cdk.Aws.REGION}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}')))
        kdf_mysql_slowquery_log_to_s3.cfn_options.condition = (
            create_kdf_for_mysql_slowquery)

        # ##  CWL subscription fileter
        subscription_of_audit_logs = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionMySQLAudit',
            destination_arn=(f'arn:{PARTITION}:firehose:{cdk.Aws.REGION}:'
                             f'{cdk.Aws.ACCOUNT_ID}:deliverystream/'
                             f'{kdf_name_of_mysql_audit_log.value_as_string}'),
            filter_pattern='',
            log_group_name=(
                cw_log_group_name_of_mysql_audit_log.value_as_string),
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}'))
        subscription_of_audit_logs.cfn_options.condition = (
            use_subscription_filter_for_mysql_audit)
        subscription_of_audit_logs.add_property_override(
            "DestinationArn",
            cdk.Fn.condition_if(
                create_kdf_for_mysql_audit.logical_id,
                kdf_mysql_audit_log_to_s3.attr_arn,
                (f'arn:{PARTITION}:firehose:{cdk.Aws.REGION}:'
                 f'{cdk.Aws.ACCOUNT_ID}:deliverystream/'
                 f'{kdf_name_of_mysql_audit_log.value_as_string}')
            ),
        )

        subscription_of_error_logs = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionMySQLError',
            destination_arn=(f'arn:{PARTITION}:firehose:{cdk.Aws.REGION}:'
                             f'{cdk.Aws.ACCOUNT_ID}:deliverystream/'
                             f'{kdf_name_of_mysql_error_log.value_as_string}'),
            filter_pattern='',
            log_group_name=(
                cw_log_group_name_of_mysql_error_log.value_as_string),
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}'))
        subscription_of_error_logs.cfn_options.condition = (
            use_subscription_filter_for_mysql_error)
        subscription_of_error_logs.add_property_override(
            "DestinationArn",
            cdk.Fn.condition_if(
                create_kdf_for_mysql_error.logical_id,
                kdf_mysql_error_log_to_s3.attr_arn,
                (f'arn:{PARTITION}:firehose:{cdk.Aws.REGION}:'
                 f'{cdk.Aws.ACCOUNT_ID}:deliverystream/'
                 f'{kdf_name_of_mysql_error_log.value_as_string}')
            ),
        )

        subscription_of_general_logs = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionMySQLGeneral',
            destination_arn=(f'arn:{PARTITION}:firehose:{cdk.Aws.REGION}:'
                             f'{cdk.Aws.ACCOUNT_ID}:deliverystream/'
                             f'{kdf_name_of_mysql_general_log.value_as_string}'),
            filter_pattern='',
            log_group_name=(
                cw_log_group_name_of_mysql_general_log.value_as_string),
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}'))
        subscription_of_general_logs.cfn_options.condition = (
            use_subscription_filter_for_mysql_general)
        subscription_of_general_logs.add_property_override(
            "DestinationArn",
            cdk.Fn.condition_if(
                create_kdf_for_mysql_general.logical_id,
                kdf_mysql_general_log_to_s3.attr_arn,
                (f'arn:{PARTITION}:firehose:{cdk.Aws.REGION}:'
                 f'{cdk.Aws.ACCOUNT_ID}:deliverystream/'
                 f'{kdf_name_of_mysql_general_log.value_as_string}')
            ),
        )

        subscription_of_slowquery_logs = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionMySQLSlowQuery',
            destination_arn=(f'arn:{PARTITION}:firehose:{cdk.Aws.REGION}:'
                             f'{cdk.Aws.ACCOUNT_ID}:deliverystream/'
                             f'{kdf_name_of_mysql_slowquery_log.value_as_string}'),
            filter_pattern='',
            log_group_name=(
                cw_log_group_name_of_mysql_slowquery_log.value_as_string),
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}'))
        subscription_of_slowquery_logs.cfn_options.condition = (
            use_subscription_filter_for_mysql_slowquery)
        subscription_of_slowquery_logs.add_property_override(
            "DestinationArn",
            cdk.Fn.condition_if(
                create_kdf_for_mysql_slowquery.logical_id,
                kdf_mysql_slowquery_log_to_s3.attr_arn,
                (f'arn:{PARTITION}:firehose:{cdk.Aws.REGION}:'
                 f'{cdk.Aws.ACCOUNT_ID}:deliverystream/'
                 f'{kdf_name_of_mysql_slowquery_log.value_as_string}')
            ),
        )


class RDSPostgreSQLCWLogsExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name-v2')
        role_name_cwl_to_kdf = cdk.Fn.import_value(
            'siem-cwl-to-kdf-role-name-v2')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name-v2')

        cw_log_group_name_of_postgresql_log = cdk.CfnParameter(
            self, 'CwLogGroupNameOfPostgreSQLLog',
            description=('Specify CloudWatch Logs group name of '
                         'RDS PostgreSQL general log. '
                         'e.g.) /aws/rds/instance/db-instance-name/postgresql'
                         ' . If you would not like to the log to SIEM, '
                         'leave it blank.'),)
        """
        cw_log_group_name_of_postgresql_upgrade_log = cdk.CfnParameter(
            self, 'CwLogGroupNameOfPostgreSQLUpgradeLog',
            description=('Specify CloudWatch Logs group name of '
                         'RDS PostgreSQL upgrade log. '
                         'e.g.) /aws/rds/instance/db-instance-name/upgrade . '
                         'If you would not like to the log to SIEM, '
                         'leave it blank.'),)
        """

        create_firehose = cdk.CfnParameter(
            self, 'CreateFirehose',
            description=('Would you like to create Kinesis Data Firehose for '
                         'SIEM solution and RDS?'),
            allowed_values=['create_a_new_one', 'use_existing'],
            default='create_a_new_one')
        kdf_buffer_size = cdk.CfnParameter(
            self, 'KdfBufferSize', type='Number',
            description='Enter a buffer size between 64 - 128 (MiB)',
            default=64, min_value=64, max_value=128)
        kdf_buffer_interval = cdk.CfnParameter(
            self, 'KdfBufferInterval', type='Number',
            description='Enter a buffer interval between 60 - 900 (seconds.)',
            default=60, min_value=60, max_value=900)

        kdf_name_of_postgresql_log = cdk.CfnParameter(
            self, 'FirehoseNameForPostgreSql',
            description=('Define Kinesis Data Firehose Name for '
                         'RDS (Aurora PostgreSQL / PostgreSQL) postgresql log.'
                         ' e.g.) siem-rds-postgresql-log-cwl-to-s3'),
            default='siem-rds-postgresql-log-cwl-to-s3')
        """
        kdf_name_of_postgresql_upgrade_log = cdk.CfnParameter(
            self, 'FirehoseNameForPostgreSqlUpgrade',
            description=('Define Kinesis Data Firehose Name for '
                         'RDS (Aurora PostgreSQL / PostgreSQL) upgrade log. '
                         'e.g.) siem-rds-postgresql-upgrade-log-cwl-to-s3'),
            default='siem-rds-postgresql-upgrade-log-cwl-to-s3')
        """

        self.template_options.metadata = {
            'AWS::CloudFormation::Interface': {
                'ParameterGroups': [
                    {'Label': {'default': 'CloudWatch Logs'},
                     'Parameters': [
                        cw_log_group_name_of_postgresql_log.logical_id,
                        # cw_log_group_name_of_postgresql_upgrade_log.logical_id
                    ]},
                    {'Label': {'default': 'Amazon Kinesis Data Firehose conf'},
                     'Parameters': [create_firehose.logical_id,
                                    kdf_buffer_size.logical_id,
                                    kdf_buffer_interval.logical_id,
                                    ]},
                    {'Label': {'default': 'Amazon Kinesis Data Firehose Name'},
                     'Parameters': [
                         kdf_name_of_postgresql_log.logical_id,
                         # kdf_name_of_postgresql_upgrade_log.logical_id
                    ]},
                ]
            }
        }

        # conditions
        kdf_is_required = cdk.CfnCondition(
            self, "KdfIsRequired",
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_equals(
                    create_firehose.value_as_string, 'create_a_new_one')))

        create_kdf_for_postgresql = cdk.CfnCondition(
            self, "CreateKdfForPostgreSQL",
            expression=cdk.Fn.condition_and(
                kdf_is_required,
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        kdf_name_of_postgresql_log.value_as_string, ''))))
        """
        create_kdf_for_postgresql_upgrade = cdk.CfnCondition(
            self, "CreateKdfForPostgreSQLUpgrade",
            expression=cdk.Fn.condition_and(
                kdf_is_required,
                cdk.Fn.condition_not(
                    cdk.Fn.condition_equals(
                        kdf_name_of_postgresql_upgrade_log.value_as_string, ''))))
        """

        use_subscription_filter_for_postgresql = cdk.CfnCondition(
            self, "SubscribeCwlOfPostgreSQL",
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_not(cdk.Fn.condition_equals(
                    kdf_name_of_postgresql_log.value_as_string, '')),
                cdk.Fn.condition_not(cdk.Fn.condition_equals(
                    cw_log_group_name_of_postgresql_log.value_as_string,
                    ''))))
        """
        use_subscription_filter_for_postgresql_upgrade = cdk.CfnCondition(
            self, "SubscribeCwlOfPostgreSQLUpgrade",
            expression=cdk.Fn.condition_and(
                cdk.Fn.condition_not(cdk.Fn.condition_equals(
                    kdf_name_of_postgresql_upgrade_log.value_as_string, '')),
                cdk.Fn.condition_not(cdk.Fn.condition_equals(
                    cw_log_group_name_of_postgresql_upgrade_log.value_as_string,
                    ''))))
        """

        # resource
        # ## KDF
        kdf_postgresql_log_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KdfRDSPostgreSQL",
            delivery_stream_name=kdf_name_of_postgresql_log.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/RDS/PostgreSQL/postgresql/",
                prefix=(f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/RDS/PostgreSQL/'
                        f'postgresql/{cdk.Aws.REGION}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}')))
        kdf_postgresql_log_to_s3.cfn_options.condition = (
            create_kdf_for_postgresql)

        """
        kdf_postgresql_upgrade_log_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KdfRDSPostgreSQLUpgrade",
            delivery_stream_name=kdf_name_of_postgresql_upgrade_log.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/RDS/PostgreSQL/upgrade/",
                prefix=(f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/RDS/PostgreSQL/upgrade/'
                        f'{cdk.Aws.REGION}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}')))
        kdf_postgresql_upgrade_log_to_s3.cfn_options.condition = (
            create_kdf_for_postgresql_upgrade)
        """

        # ##  CWL subscription fileter
        subscription_of_logs = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionPostgreSQL',
            destination_arn='dummy',
            filter_pattern='',
            log_group_name=(
                cw_log_group_name_of_postgresql_log.value_as_string),
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}'))
        subscription_of_logs.cfn_options.condition = (
            use_subscription_filter_for_postgresql)
        subscription_of_logs.add_property_override(
            "DestinationArn",
            cdk.Fn.condition_if(
                create_kdf_for_postgresql.logical_id,
                kdf_postgresql_log_to_s3.attr_arn,
                (f'arn:{PARTITION}:firehose:{cdk.Aws.REGION}:'
                 f'{cdk.Aws.ACCOUNT_ID}:deliverystream/'
                 f'{kdf_name_of_postgresql_log.value_as_string}')
            ),
        )
        """
        subscription_of_upgrade_logs = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionPostgreSQLUpgrade',
            destination_arn=(f'arn:{PARTITION}:firehose:{cdk.Aws.REGION}:'
                             f'{cdk.Aws.ACCOUNT_ID}:deliverystream/'
                             f'{kdf_name_of_postgresql_upgrade_log.value_as_string}'),
            filter_pattern='',
            log_group_name=(
                cw_log_group_name_of_postgresql_upgrade_log.value_as_string),
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}'))
        subscription_of_upgrade_logs.cfn_options.condition = (
            use_subscription_filter_for_postgresql_upgrade)
        """


class LinuxCWLogsExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name-v2')
        role_name_cwl_to_kdf = cdk.Fn.import_value(
            'siem-cwl-to-kdf-role-name-v2')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name-v2')

        kdf_linux_system_logs_name = cdk.CfnParameter(
            self, 'FirehoseNameForLinuxSystemLogs',
            description=('Define new Kinesis Data Firehose Name '
                         'for Linux system logs'),
            default='siem-linux-system-cwl-to-s3')
        kdf_linux_secure_logs_name = cdk.CfnParameter(
            self, 'FirehoseNameForLinuxSecureLogs',
            description=('Define new Kinesis Data Firehose Name '
                         'for Linux secure logs'),
            default='siem-linux-secure-cwl-to-s3')
        kdf_buffer_size = cdk.CfnParameter(
            self, 'KdfBufferSize', type='Number',
            description='Enter a buffer size between 64 - 128 (MiB)',
            default=64, min_value=64, max_value=128)
        kdf_buffer_interval = cdk.CfnParameter(
            self, 'KdfBufferInterval', type='Number',
            description='Enter a buffer interval between 60 - 900 (seconds.)',
            default=60, min_value=60, max_value=900)
        cwl_linux_system_logs_name = cdk.CfnParameter(
            self, 'CwlNameForLinuxSystemLogs',
            description=('Specify CloudWatch Logs group name for '
                         'system logs such as /var/log/messages. '
                         'This field can be left blank'),
            default='/ec2/linux/messages')
        cwl_linux_secure_logs_name = cdk.CfnParameter(
            self, 'CwlNameForLinuxSecureLogs',
            description=('Specify CloudWatch Logs group name for '
                         'secure logs such as /var/log/seure. '
                         'This field can be left blank'),
            default='/ec2/linux/secure')

        self.template_options.metadata = {
            'AWS::CloudFormation::Interface': {
                'ParameterGroups': [
                    {'Label': {'default': 'CloudWatch Logs'},
                     'Parameters': [cwl_linux_system_logs_name.logical_id,
                                    cwl_linux_secure_logs_name.logical_id]},
                    {'Label': {'default': 'Amazon Kinesis Data Firehose'},
                     'Parameters': [kdf_linux_system_logs_name.logical_id,
                                    kdf_linux_secure_logs_name.logical_id,
                                    kdf_buffer_size.logical_id,
                                    kdf_buffer_interval.logical_id]}
                ]
            }
        }

        has_system_logs = cdk.CfnCondition(
            self, "hasSystemLogs",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_equals(
                    cwl_linux_system_logs_name.value_as_string, '')
            )
        )

        has_secure_logs = cdk.CfnCondition(
            self, "hasSecureLogs",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_equals(
                    cwl_linux_secure_logs_name.value_as_string, '')
            )
        )

        kdf_linux_system_logs_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KdfLinuxSystemLogs",
            delivery_stream_name=kdf_linux_system_logs_name.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/Linux/System",
                prefix=(f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/EC2/Linux/System/'
                        f'{cdk.Aws.REGION}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}'),
            )
        )
        kdf_linux_system_logs_to_s3.cfn_options.condition = has_system_logs

        kdf_linux_secure_logs_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KdfLinuxSecureLogs",
            delivery_stream_name=kdf_linux_secure_logs_name.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/Linux/Secure",
                prefix=(f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/EC2/Linux/Secure/'
                        f'{cdk.Aws.REGION}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}'),
            )
        )
        kdf_linux_secure_logs_to_s3.cfn_options.condition = has_secure_logs

        subscription_of_system_logs = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionLinuxSystem',
            destination_arn=kdf_linux_system_logs_to_s3.attr_arn,
            filter_pattern='',
            log_group_name=cwl_linux_system_logs_name.value_as_string,
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )
        subscription_of_system_logs.cfn_options.condition = has_system_logs

        subscription_of_secure_logs = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionLinuxSecure',
            destination_arn=kdf_linux_secure_logs_to_s3.attr_arn,
            filter_pattern='',
            log_group_name=cwl_linux_secure_logs_name.value_as_string,
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )
        subscription_of_secure_logs.cfn_options.condition = has_secure_logs


class ApacheCWLogsExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name-v2')
        role_name_cwl_to_kdf = cdk.Fn.import_value(
            'siem-cwl-to-kdf-role-name-v2')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name-v2')

        web_site_name = cdk.CfnParameter(
            self, 'WebSiteName',
            description=('Define your site name. e.g. www.example.com'),
            allowed_pattern=r'^[0-9a-zA-Z._-]+$',
            default='localsite')
        kdf_apache_access_name = cdk.CfnParameter(
            self, 'KdfApacheAccessName',
            description=('Define new Kinesis Data Firehose Name '
                         'to deliver Apache Access CloudWatch Logs'),
            default='siem-apache-access-cwl-to-s3')
        kdf_apache_error_name = cdk.CfnParameter(
            self, 'KdfApacheErrorName',
            description=('Define new Kinesis Data Firehose Name '
                         'to deliver Apache Error CloudWatch Logs'),
            default='siem-apache-error-cwl-to-s3')
        kdf_buffer_size = cdk.CfnParameter(
            self, 'KdfBufferSize', type='Number',
            description='Enter a buffer size between 64 - 128 (MiB)',
            default=64, min_value=64, max_value=128)
        kdf_buffer_interval = cdk.CfnParameter(
            self, 'KdfBufferInterval', type='Number',
            description='Enter a buffer interval between 60 - 900 (seconds.)',
            default=60, min_value=60, max_value=900)
        cwl_apache_access_name = cdk.CfnParameter(
            self, 'CwlApacheAccessName',
            description=('Specify CloudWatch Logs group name for '
                         'access log. '
                         'This field can be left blank'),
            default='/ec2/apache/access_log')
        cwl_apache_error_name = cdk.CfnParameter(
            self, 'CwlApacheErrorName',
            description=('Specify CloudWatch Logs group name for '
                         'error log. '
                         'This field can be left blank'),
            default='/ec2/apache/error_log')
        cwl_apache_ssl_access_name = cdk.CfnParameter(
            self, 'CwlApacheSslAccessName',
            description=('Specify CloudWatch Logs group name for '
                         'SSL access log. '
                         'This field can be left blank'),
            default='/ec2/apache/ssl_access_log')
        cwl_apache_ssl_error_name = cdk.CfnParameter(
            self, 'CwlApacheSslErrorName',
            description=('Specify CloudWatch Logs group name for '
                         'SSL error log. '
                         'This field can be left blank'),
            default='/ec2/apache/ssl_error_log')

        self.template_options.metadata = {
            'AWS::CloudFormation::Interface': {
                'ParameterGroups': [
                    {'Label': {'default': 'Web Site Name'},
                     'Parameters': [web_site_name.logical_id]},
                    {'Label': {'default': 'CloudWatch Logs'},
                     'Parameters': [cwl_apache_access_name.logical_id,
                                    cwl_apache_error_name.logical_id,
                                    cwl_apache_ssl_access_name.logical_id,
                                    cwl_apache_ssl_error_name.logical_id]},
                    {'Label': {'default': 'Amazon Kinesis Data Firehose'},
                     'Parameters': [kdf_apache_access_name.logical_id,
                                    kdf_apache_error_name.logical_id,
                                    kdf_buffer_size.logical_id,
                                    kdf_buffer_interval.logical_id]}
                ]
            }
        }

        has_access_log = cdk.CfnCondition(
            self, "hasAccessLog",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_equals(
                    cwl_apache_access_name.value_as_string, '')
            )
        )
        has_error_log = cdk.CfnCondition(
            self, "hasErrorLog",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_equals(
                    cwl_apache_error_name.value_as_string, '')
            )
        )
        has_ssl_access_log = cdk.CfnCondition(
            self, "hasSslAccessLog",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_equals(
                    cwl_apache_ssl_access_name.value_as_string, '')
            )
        )
        has_ssl_error_log = cdk.CfnCondition(
            self, "hasSslErrorLog",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_equals(
                    cwl_apache_ssl_error_name.value_as_string, '')
            )
        )

        needs_kdf_access = cdk.CfnCondition(
            self, "needsKdfAccess",
            expression=cdk.Fn.condition_or(
                has_access_log,
                has_ssl_access_log
            )
        )
        needs_kdf_error = cdk.CfnCondition(
            self, "needsKdfError",
            expression=cdk.Fn.condition_or(
                has_error_log,
                has_ssl_error_log
            )
        )

        kdf_apache_access_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KdfApacheAccess",
            delivery_stream_name=kdf_apache_access_name.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/Apache/",
                prefix=(f'AWSLogs/aws-account-id={cdk.Aws.ACCOUNT_ID}'
                        '/service=apache-access'
                        f'/web-site-name={web_site_name.value_as_string}'
                        f'/aws-region={cdk.Aws.REGION}'
                        r'/year=!{timestamp:yyyy}/month=!{timestamp:MM}'
                        r'/day=!{timestamp:dd}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}'),
            )
        )
        kdf_apache_access_to_s3.cfn_options.condition = needs_kdf_access

        kdf_apache_error_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KdfApacheError",
            delivery_stream_name=kdf_apache_error_name.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/",
                prefix=(f'AWSLogs/aws-account-id={cdk.Aws.ACCOUNT_ID}'
                        '/service=apache-error'
                        f'/web-site-name={web_site_name.value_as_string}'
                        f'/aws-region={cdk.Aws.REGION}'
                        r'/year=!{timestamp:yyyy}/month=!{timestamp:MM}'
                        r'/day=!{timestamp:dd}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}'),
            )
        )
        kdf_apache_error_to_s3.cfn_options.condition = needs_kdf_error

        sub_access_log = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionAccess',
            destination_arn=kdf_apache_access_to_s3.attr_arn,
            log_group_name=cwl_apache_access_name.value_as_string,
            filter_pattern='',
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )
        sub_access_log.cfn_options.condition = has_access_log
        sub_error_log = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionError',
            destination_arn=kdf_apache_error_to_s3.attr_arn,
            log_group_name=cwl_apache_error_name.value_as_string,
            filter_pattern='',
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )
        sub_error_log.cfn_options.condition = has_error_log
        sub_ssl_access_log = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionSslAccess',
            destination_arn=kdf_apache_access_to_s3.attr_arn,
            log_group_name=cwl_apache_ssl_access_name.value_as_string,
            filter_pattern='',
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )
        sub_ssl_access_log.cfn_options.condition = has_ssl_access_log
        sub_ssl_error_log = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionSslError',
            destination_arn=kdf_apache_error_to_s3.attr_arn,
            log_group_name=cwl_apache_ssl_error_name.value_as_string,
            filter_pattern='',
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )
        sub_ssl_error_log.cfn_options.condition = has_ssl_error_log


class NginxCWLogsExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name-v2')
        role_name_cwl_to_kdf = cdk.Fn.import_value(
            'siem-cwl-to-kdf-role-name-v2')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name-v2')

        web_site_name = cdk.CfnParameter(
            self, 'WebSiteName',
            description=('Define your site name. e.g. www.example.com'),
            allowed_pattern=r'^[0-9a-zA-Z._-]+$',
            default='localsite')
        kdf_nginx_access_name = cdk.CfnParameter(
            self, 'KdfNginxAccessName',
            description=('Define new Kinesis Data Firehose Name '
                         'to deliver Nginx Access CloudWatch Logs'),
            default='siem-nginx-access-cwl-to-s3')
        kdf_nginx_error_name = cdk.CfnParameter(
            self, 'KdfNginxErrorName',
            description=('Define new Kinesis Data Firehose Name '
                         'to deliver Nginx Error CloudWatch Logs'),
            default='siem-nginx-error-cwl-to-s3')
        kdf_buffer_size = cdk.CfnParameter(
            self, 'KdfBufferSize', type='Number',
            description='Enter a buffer size between 64 - 128 (MiB)',
            default=64, min_value=64, max_value=128)
        kdf_buffer_interval = cdk.CfnParameter(
            self, 'KdfBufferInterval', type='Number',
            description='Enter a buffer interval between 60 - 900 (seconds.)',
            default=60, min_value=60, max_value=900)
        cwl_nginx_access_name = cdk.CfnParameter(
            self, 'CwlNginxAccessName',
            description=('Specify CloudWatch Logs group name for '
                         'access log. '
                         'This field can be left blank'),
            default='/ec2/nginx/access.log')
        cwl_nginx_error_name = cdk.CfnParameter(
            self, 'CwlNginxErrorName',
            description=('Specify CloudWatch Logs group name for '
                         'error log. '
                         'This field can be left blank'),
            default='/ec2/nginx/error.log')
        cwl_nginx_ssl_access_name = cdk.CfnParameter(
            self, 'CwlNginxSslAccessName',
            description=('Specify CloudWatch Logs group name for '
                         'SSL access log. '
                         'This field can be left blank'),
            default='/ec2/nginx/ssl_access.log')
        cwl_nginx_ssl_error_name = cdk.CfnParameter(
            self, 'CwlNginxSslErrorName',
            description=('Specify CloudWatch Logs group name for '
                         'SSL error log. '
                         'This field can be left blank'),
            default='/ec2/nginx/ssl_error.log')

        self.template_options.metadata = {
            'AWS::CloudFormation::Interface': {
                'ParameterGroups': [
                    {'Label': {'default': 'Web Site Name'},
                     'Parameters': [web_site_name.logical_id]},
                    {'Label': {'default': 'CloudWatch Logs'},
                     'Parameters': [cwl_nginx_access_name.logical_id,
                                    cwl_nginx_error_name.logical_id,
                                    cwl_nginx_ssl_access_name.logical_id,
                                    cwl_nginx_ssl_error_name.logical_id]},
                    {'Label': {'default': 'Amazon Kinesis Data Firehose'},
                     'Parameters': [kdf_nginx_access_name.logical_id,
                                    kdf_nginx_error_name.logical_id,
                                    kdf_buffer_size.logical_id,
                                    kdf_buffer_interval.logical_id]}
                ]
            }
        }

        has_access_log = cdk.CfnCondition(
            self, "hasAccessLog",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_equals(
                    cwl_nginx_access_name.value_as_string, '')
            )
        )
        has_error_log = cdk.CfnCondition(
            self, "hasErrorLog",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_equals(
                    cwl_nginx_error_name.value_as_string, '')
            )
        )
        has_ssl_access_log = cdk.CfnCondition(
            self, "hasSslAccessLog",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_equals(
                    cwl_nginx_ssl_access_name.value_as_string, '')
            )
        )
        has_ssl_error_log = cdk.CfnCondition(
            self, "hasSslErrorLog",
            expression=cdk.Fn.condition_not(
                cdk.Fn.condition_equals(
                    cwl_nginx_ssl_error_name.value_as_string, '')
            )
        )

        needs_kdf_access = cdk.CfnCondition(
            self, "needsKdfAccess",
            expression=cdk.Fn.condition_or(
                has_access_log,
                has_ssl_access_log
            )
        )
        needs_kdf_error = cdk.CfnCondition(
            self, "needsKdfError",
            expression=cdk.Fn.condition_or(
                has_error_log,
                has_ssl_error_log
            )
        )

        kdf_nginx_access_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KdfNginxAccess",
            delivery_stream_name=kdf_nginx_access_name.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/Nginx/",
                prefix=(f'AWSLogs/aws-account-id={cdk.Aws.ACCOUNT_ID}'
                        '/service=nginx-access'
                        f'/web-site-name={web_site_name.value_as_string}'
                        f'/aws-region={cdk.Aws.REGION}'
                        r'/year=!{timestamp:yyyy}/month=!{timestamp:MM}'
                        r'/day=!{timestamp:dd}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}'),
            )
        )
        kdf_nginx_access_to_s3.cfn_options.condition = needs_kdf_access

        kdf_nginx_error_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KdfNginxError",
            delivery_stream_name=kdf_nginx_error_name.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/",
                prefix=(f'AWSLogs/aws-account-id={cdk.Aws.ACCOUNT_ID}'
                        '/service=nginx-error'
                        f'/web-site-name={web_site_name.value_as_string}'
                        f'/aws-region={cdk.Aws.REGION}'
                        r'/year=!{timestamp:yyyy}/month=!{timestamp:MM}'
                        r'/day=!{timestamp:dd}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}'),
            )
        )
        kdf_nginx_error_to_s3.cfn_options.condition = needs_kdf_error

        sub_access_log = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionAccess',
            destination_arn=kdf_nginx_access_to_s3.attr_arn,
            log_group_name=cwl_nginx_access_name.value_as_string,
            filter_pattern='',
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )
        sub_access_log.cfn_options.condition = has_access_log
        sub_error_log = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionError',
            destination_arn=kdf_nginx_error_to_s3.attr_arn,
            log_group_name=cwl_nginx_error_name.value_as_string,
            filter_pattern='',
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )
        sub_error_log.cfn_options.condition = has_error_log
        sub_ssl_access_log = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionSslAccess',
            destination_arn=kdf_nginx_access_to_s3.attr_arn,
            log_group_name=cwl_nginx_ssl_access_name.value_as_string,
            filter_pattern='',
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )
        sub_ssl_access_log.cfn_options.condition = has_ssl_access_log
        sub_ssl_error_log = aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscriptionSslError',
            destination_arn=kdf_nginx_error_to_s3.attr_arn,
            log_group_name=cwl_nginx_ssl_error_name.value_as_string,
            filter_pattern='',
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )
        sub_ssl_error_log.cfn_options.condition = has_ssl_error_log


class ClientVpnLogExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name-v2')
        role_name_cwl_to_kdf = cdk.Fn.import_value(
            'siem-cwl-to-kdf-role-name-v2')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name-v2')

        kdf_clientvpn_name = cdk.CfnParameter(
            self, 'KdfClientVpnName',
            description=('Define new Kinesis Data Firehose Name '
                         'to deliver Client VPN CloudWatch Logs'),
            default='siem-clientvpn-to-s3')
        kdf_buffer_size = cdk.CfnParameter(
            self, 'KdfBufferSize', type='Number',
            description='Enter a buffer size between 64 - 128 (MiB)',
            default=64, min_value=64, max_value=128)
        kdf_buffer_interval = cdk.CfnParameter(
            self, 'KdfBufferInterval', type='Number',
            description='Enter a buffer interval between 60 - 900 (seconds.)',
            default=60, min_value=60, max_value=900)
        cwl_clientvpn_name = cdk.CfnParameter(
            self, 'CwlClientVpnName',
            description='Specify Client VPN CloudWatch Logs group name',
            default='/aws/clientvpn')

        self.template_options.metadata = {
            'AWS::CloudFormation::Interface': {
                'ParameterGroups': [
                    {'Label': {'default': 'CloudWatch Logs'},
                     'Parameters': [cwl_clientvpn_name.logical_id]},
                    {'Label': {'default': 'Amazon Kinesis Data Firehose'},
                     'Parameters': [kdf_clientvpn_name.logical_id,
                                    kdf_buffer_size.logical_id,
                                    kdf_buffer_interval.logical_id]}]
            }
        }

        kdf_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "Kdf",
            delivery_stream_name=kdf_clientvpn_name.value_as_string,
            extended_s3_destination_configuration=CDS.ExtendedS3DestinationConfigurationProperty(
                bucket_arn=f'arn:{PARTITION}:s3:::{log_bucket_name}',
                error_output_prefix="ErrorLogs/",
                prefix=(f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/ClientVPN/'
                        f'{cdk.Aws.REGION}/'),
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}'),
            )
        )

        aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscription',
            destination_arn=kdf_to_s3.attr_arn,
            filter_pattern='',
            log_group_name=cwl_clientvpn_name.value_as_string,
            role_arn=(f'arn:{PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )


class CoreLogExporterStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.CfnParameter(
            self, 'siemLogBucketName',
            description=('Define S3 Bucket name which store logs to load SIEM.'
                         ' Replace [111111111111] to your AWS account'),
            allowed_pattern=r'^[0-9a-z\[\].-]+$',
            default='aes-siem-[111111111111]-log')
        role_name_cwl_to_kdf = cdk.CfnParameter(
            self, 'roleNameCwlToKdf',
            description=('Define IAM role name for CloudWatch Logs '
                         'to send data to Kinesis Data Firehose.'),
            default='siem-role-cwl-to-firehose')
        role_name_kdf_to_s3 = cdk.CfnParameter(
            self, 'roleNameKdfToS3',
            description=('Define IAM role name for Kinesis Data Firehose '
                         'to send data to S3.'),
            default='siem-role-firehose-to-s3')

        bucket_arn = f'arn:{PARTITION}:s3:::{log_bucket_name.value_as_string}'

        if region.startswith('cn-'):
            service_principal_logs = f'logs.{cdk.Aws.REGION}.amazonaws.com.cn'
        else:
            service_principal_logs = f'logs.{cdk.Aws.REGION}.amazonaws.com'
        role_cwl_to_kdf = aws_iam.Role(
            self, 'cwlRole',
            role_name=(f'{role_name_cwl_to_kdf.value_as_string}-v2-'
                       f'{cdk.Aws.REGION}'),
            inline_policies={
                'cwl-to-firehose': aws_iam.PolicyDocument(
                    statements=[
                        aws_iam.PolicyStatement(
                            actions=["firehose:*"],
                            resources=[(f'arn:{PARTITION}:firehose:{cdk.Aws.REGION}:'
                                        f'{cdk.Aws.ACCOUNT_ID}:*')],
                            sid='CwlToFirehosePolicyGeneratedBySiemCfn'
                        )
                    ]
                )
            },
            assumed_by=aws_iam.ServicePrincipal(service_principal_logs))

        role_kdf_to_s3 = aws_iam.Role(
            self, 'firehoseRole', path='/service-role/',
            role_name=(f'{role_name_kdf_to_s3.value_as_string}-v2-'
                       f'{cdk.Aws.REGION}'),
            inline_policies={
                'firehose-to-s3': aws_iam.PolicyDocument(
                    statements=[
                        aws_iam.PolicyStatement(
                            sid='FirehoseToS3PolicyGeneratedBySiemCfn',
                            actions=["s3:AbortMultipartUpload",
                                     "s3:GetBucketLocation",
                                     "s3:GetObject",
                                     "s3:ListBucket",
                                     "s3:ListBucketMultipartUploads",
                                     "s3:PutObject"],
                            resources=[f'{bucket_arn}',
                                       f'{bucket_arn}/*'])]),
                'for-logigng': aws_iam.PolicyDocument(
                    statements=[
                        aws_iam.PolicyStatement(
                            sid='LoggingPolicyGeneratedBySiemCfn',
                            actions=["logs:PutLogEvents"],
                            resources=[(f'arn:{PARTITION}:logs:{cdk.Aws.REGION}:'
                                        f'{cdk.Aws.ACCOUNT_ID}:log-group:/aws/'
                                        f'kinesisfirehose/*:log-stream:*')])],
                ),
            },
            assumed_by=aws_iam.ServicePrincipal('firehose.amazonaws.com'))

        ######################################################################
        # output for cross stack
        ######################################################################
        cdk.CfnOutput(self, 'logBucketName',
                      export_name='sime-log-bucket-name-v2',
                      value=log_bucket_name.value_as_string)
        cdk.CfnOutput(self, 'cwlRoleName',
                      export_name='siem-cwl-to-kdf-role-name-v2',
                      value=role_cwl_to_kdf.role_name)
        cdk.CfnOutput(self, 'kdfRoleName',
                      export_name='siem-kdf-to-s3-role-name-v2',
                      value=role_kdf_to_s3.role_name)


class DeploymentSamplesStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here


class ControlTowerIntegrationStack(MyStack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        es_ladder_iam_role_default = (
            "arn:aws:iam::123456789012:role/aes-siem-LambdaEsLoaderServiceRole"
            "XXXXXXXXX-XXXXXXXXXXXX")
        es_loader_iam_role = cdk.CfnParameter(
            self, 'EsLoaderServiceRole',
            allowed_pattern=(
                r'^arn:aws[0-9a-zA-Z:/-]*LambdaEsLoaderServiceRole.*$'),
            default=es_ladder_iam_role_default,
            description=(
                f"Specify Service Role ARN of lambda function "
                f"aes-siem-es-loader in SIEM Account. "
                f"(e.g., {es_ladder_iam_role_default} )"
            ),
        )

        sqs_aes_siem_ct_dlq = aws_sqs.Queue(
            self, 'AesSiemCtDlq', queue_name='aes-siem-ct-dlq',
            encryption=aws_sqs.QueueEncryption.SQS_MANAGED,
            retention_period=cdk.Duration.days(14)
        )

        sqs_aes_siem_ct = aws_sqs.Queue(
            self, 'AesSiemCt',
            queue_name='aes-siem-ct',
            encryption=aws_sqs.QueueEncryption.SQS_MANAGED,
            dead_letter_queue=aws_sqs.DeadLetterQueue(
                max_receive_count=20, queue=sqs_aes_siem_ct_dlq),
            visibility_timeout=cdk.Duration.seconds(600),
            retention_period=cdk.Duration.days(14)
        )

        sqs_aes_siem_ct.add_to_resource_policy(
            statement=aws_iam.PolicyStatement(
                sid="__owner_statement",
                principals=[aws_iam.AccountPrincipal(cdk.Aws.ACCOUNT_ID)],
                actions=["SQS:*"],
                resources=[sqs_aes_siem_ct.queue_arn],
            )
        )

        sqs_aes_siem_ct.add_to_resource_policy(
            statement=aws_iam.PolicyStatement(
                sid="allow-s3-bucket-to-send-message",
                principals=[aws_iam.ServicePrincipal("s3.amazonaws.com")],
                actions=["SQS:SendMessage"],
                resources=[sqs_aes_siem_ct.queue_arn],
                conditions={
                    "StringEquals": {"aws:SourceAccount": [cdk.Aws.ACCOUNT_ID]}
                },
            )
        )

        sqs_aes_siem_ct.add_to_resource_policy(
            statement=aws_iam.PolicyStatement(
                sid="allow-es-loader-to-recieve-message",
                principals=[aws_iam.ArnPrincipal(
                    es_loader_iam_role.value_as_string)],
                actions=[
                    "sqs:ReceiveMessage",
                    "sqs:ChangeMessageVisibility",
                    "sqs:GetQueueUrl",
                    "sqs:DeleteMessage",
                    "sqs:GetQueueAttributes"
                ],
                resources=[sqs_aes_siem_ct.queue_arn],
            )
        )

        policy_access_s3 = aws_iam.PolicyDocument(
            statements=[
                aws_iam.PolicyStatement(
                    actions=['s3:GetObject'],
                    resources=['*']
                ),
                aws_iam.PolicyStatement(
                    actions=['kms:Decrypt'],
                    resources=['*']
                ),
            ]
        )

        aws_iam.Role(
            self, 'RoleForSiem',
            role_name='ct-role-for-siem',
            inline_policies={'access_s3': policy_access_s3},
            assumed_by=aws_iam.ArnPrincipal(
                es_loader_iam_role.value_as_string
            ),
        )
