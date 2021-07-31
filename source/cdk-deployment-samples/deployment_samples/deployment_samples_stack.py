# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from aws_cdk import (
    aws_iam,
    aws_events,
    aws_events_targets,
    aws_kinesisfirehose,
    aws_lambda,
    aws_logs,
    core as cdk
)
from aws_cdk.aws_kinesisfirehose import CfnDeliveryStream as CDS

__version__ = '2.4.0-beta.5'

LAMBDA_GET_WORKSPACES_INVENTORY = '''# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import datetime
import gzip
import json
import os

import boto3

ws_client = boto3.client('workspaces')
s3_resource = boto3.resource('s3')
bucket = s3_resource.Bucket(os.environ['log_bucket_name'])
AWS_ID = str(boto3.client("sts").get_caller_identity()["Account"])
AWS_REGION = os.environ['AWS_DEFAULT_REGION']
paginator = ws_client.get_paginator('describe_workspaces')

def lambda_handler(event, context):
    num = 0
    now = datetime.datetime.now()
    file_name = f'workspaces-inventory-{now.strftime("%Y%m%d_%H%M%S")}.json.gz'
    s3file_name =(
        f'AWSLogs/{AWS_ID}/WorkSpaces/Inventory/{AWS_REGION}/'
        f'{now.strftime("%Y/%m/%d")}/{file_name}')
    f = gzip.open(f'/tmp/{file_name}', 'tw')
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
            'detail': {}}
        jsonobj['detail']['Workspaces'] = response['Workspaces']
        num += len(response['Workspaces'])
        f.write(json.dumps(jsonobj))
        f.flush()
    f.close()
    print(f'Total nummber of WorkSpaces inventory: {num}')
    print(f'Upload path: s3://{bucket}/{s3file_name}')
    bucket.upload_file(f'/tmp/{file_name}', s3file_name)
'''


class FirehoseExporterStack(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 default_firehose_name='siem-XXXXXXXXXXX-to-s3',
                 firehose_compression_format='UNCOMPRESSED',
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name')

        kdf_name = cdk.CfnParameter(
            self, 'FirehoseName',
            description=('New Kinesis Data Firehose Name to deliver log. '
                         'modify XXXXXXXXX'),
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
            description='S3 destination prefix',
            default='AWSLogs/YourAccuntId/LogType/Region/')

        self.kdf_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "Kdf",
            delivery_stream_name=kdf_name.value_as_string,
            s3_destination_configuration=CDS.S3DestinationConfigurationProperty(
                bucket_arn=f'arn:aws:s3:::{log_bucket_name}',
                prefix=s3_desitination_prefix.value_as_string,
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format=firehose_compression_format,
                role_arn=(f'arn:aws:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}')
            )
        )


class CWLNoCompressExporterStack(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name')
        role_name_cwl_to_kdf = cdk.Fn.import_value(
            'siem-cwl-to-kdf-role-name')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name')

        kdf_name = cdk.CfnParameter(
            self, 'KdfName',
            description='New Kinesis Data Firehose Name to deliver AD event',
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
            description='Existing CloudWatch Logs group name',
            default='/aws/XXXXXXXXXXXXXXXXX')
        s3_desitination_prefix = cdk.CfnParameter(
            self, 'S3DestPrefix',
            description='S3 destination prefix',
            default='AWSLogs/YourAccuntId/LogType/Region/')

        kdf_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "Kdf",
            delivery_stream_name=kdf_name.value_as_string,
            s3_destination_configuration=CDS.S3DestinationConfigurationProperty(
                bucket_arn=f'arn:aws:s3:::{log_bucket_name}',
                prefix=s3_desitination_prefix.value_as_string,
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:aws:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}')
            )
        )

        aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscription',
            destination_arn=kdf_to_s3.attr_arn,
            filter_pattern='',
            log_group_name=cwl_loggroup_name.value_as_string,
            role_arn=(f'arn:aws:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )


class ADLogExporterStack(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name')
        role_name_cwl_to_kdf = cdk.Fn.import_value(
            'siem-cwl-to-kdf-role-name')
        role_name_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name')

        kdf_ad_name = cdk.CfnParameter(
            self, 'KdfAdName',
            description='Kinesis Data Firehose Name to deliver AD event',
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
            description='CloudWatch Logs group name',
            default='/aws/directoryservice/d-XXXXXXXXXXXXXXXXX')

        kdf_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KDFForAdEventLog",
            delivery_stream_name=kdf_ad_name.value_as_string,
            s3_destination_configuration=CDS.S3DestinationConfigurationProperty(
                bucket_arn=f'arn:aws:s3:::{log_bucket_name}',
                prefix=f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/DirectoryService/MicrosoftAD/',
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:aws:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{role_name_kdf_to_s3}')
            )
        )

        aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscription',
            destination_arn=kdf_to_s3.attr_arn,
            filter_pattern='',
            log_group_name=cwl_ad_name.value_as_string,
            role_arn=(f'arn:aws:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                      f'{role_name_cwl_to_kdf}')
        )


class WorkSpacesLogExporterStack(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name')
        service_role_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name')

        cwe_frequency = cdk.CfnParameter(
            self, 'cweRulesFrequency', type='Number',
            description=(
                'How often do you get WorkSpaces Inventory? (every minutes)'),
            default=720)
        kdf_workspaces_name = cdk.CfnParameter(
            self, 'KdfWorkSpacesName',
            description=(
                'Kinesis Data Firehose Name to deliver workspaces event'),
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
                            sid='DescribeWorkSpacesPolicyGeneratedBySeimCfn')
                    ]
                ),
                'firehose-to-s3': aws_iam.PolicyDocument(
                    statements=[
                        aws_iam.PolicyStatement(
                            actions=['s3:PutObject'],
                            resources=[f'arn:aws:s3:::{log_bucket_name}/*'],
                            sid='FirehoseToS3PolicyGeneratedBySeimCfn'
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
            runtime=aws_lambda.Runtime.PYTHON_3_8,
            code=aws_lambda.InlineCode(LAMBDA_GET_WORKSPACES_INVENTORY),
            function_name='siem-get-workspaces-inventory',
            description='SIEM: get workspaces inventory',
            handler='index.lambda_handler',
            timeout=cdk.Duration.seconds(300),
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
                bucket_arn=f'arn:aws:s3:::{log_bucket_name}',
                prefix=f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/WorkSpaces/Event/',
                compression_format='GZIP',
                buffering_hints=CDS.BufferingHintsProperty(
                    interval_in_seconds=kdf_buffer_interval.value_as_number,
                    size_in_m_bs=kdf_buffer_size.value_as_number),
                role_arn=(f'arn:aws:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{service_role_kdf_to_s3}')
            )
        )

        pattern = aws_events.EventPattern(
            detail_type=["WorkSpaces Access"], source=['aws.workspaces'])

        aws_events.Rule(
            self, 'eventBridgeRuleWorkSpacesEvent', event_pattern=pattern,
            rule_name='siem-workspaces-event-to-kdf',
            targets=[aws_events_targets.KinesisFirehoseStream(kdf_to_s3)])


class BasicLogExporterStack(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.CfnParameter(
            self, 'siemLogBucketName',
            description='S3 Bucket to put workspaces inventory',
            default='aes-siem-111111111111-log')
        role_name_cwl_to_kdf = cdk.CfnParameter(
            self, 'kdfToS3RoleName',
            description=('role name for CloudWatch Logs to send data to '
                         'Kinsis Data Firehose. Replace YOUR-REGION'),
            default='siem-role-cwl-to-firehose-YOUR-REGION')
        role_name_kdf_to_s3 = cdk.CfnParameter(
            self, 'roleNameKdfToS3',
            description=('role name for Kinesis Data Firehose to send data '
                         'to S3. Replace YOUR-REGION'),
            default='siem-role-firehose-to-s3-YOUR-REGION')

        bucket_arn = f'arn:aws:s3:::{log_bucket_name.value_as_string}'

        role_cwl_to_kdf = aws_iam.Role(
            self, 'cwlRole',
            role_name=role_name_cwl_to_kdf.value_as_string,
            inline_policies={
                'cwl-to-firehose': aws_iam.PolicyDocument(
                    statements=[
                        aws_iam.PolicyStatement(
                            actions=["firehose:*"],
                            resources=[(f'arn:aws:firehose:{cdk.Aws.REGION}:'
                                        f'{cdk.Aws.ACCOUNT_ID}:*')],
                            sid='CwlToFirehosePolicyGeneratedBySeimCfn'
                        )
                    ]
                )
            },
            assumed_by=aws_iam.ServicePrincipal(
                f'logs.{cdk.Aws.REGION}.amazonaws.com'))

        role_kdf_to_s3 = aws_iam.Role(
            self, 'firehoseRole', path='/service-role/',
            role_name=role_name_kdf_to_s3.value_as_string,
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
                            resources=[(f'arn:aws:logs:{cdk.Aws.REGION}:'
                                        f'{cdk.Aws.ACCOUNT_ID}:log-group:/aws/'
                                        f'kinesisfirehose/*:log-stream:*')])],
                ),
            },
            assumed_by=aws_iam.ServicePrincipal('firehose.amazonaws.com'))

        ######################################################################
        # output for cross stack
        ######################################################################
        cdk.CfnOutput(self, 'logBucketName',
                      export_name='sime-log-bucket-name',
                      value=log_bucket_name.value_as_string)
        cdk.CfnOutput(self, 'cwlRoleName',
                      export_name='siem-cwl-to-kdf-role-name',
                      value=role_cwl_to_kdf.role_name)
        cdk.CfnOutput(self, 'kdfRoleName',
                      export_name='siem-kdf-to-s3-role-name',
                      value=role_kdf_to_s3.role_name)


class DeploymentSamplesStack(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here
