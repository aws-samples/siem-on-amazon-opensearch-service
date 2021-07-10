# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
from aws_cdk import (
    aws_cloudformation,
    aws_iam,
    aws_events,
    aws_events_targets,
    aws_kinesisfirehose,
    aws_lambda,
    aws_logs,
    core as cdk
)

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


class ADLogExporterStack(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.Fn.import_value('sime-log-bucket-name')
        service_role_kdf_to_s3 = cdk.Fn.import_value(
            'siem-kdf-to-s3-role-name')

        kdf_ad_name = cdk.CfnParameter(
            self, 'KdfAdName',
            description='Kinesis Data Firehose Name to deliver AD event',
            default='aes-siem-ad-event-to-s3')
        cwl_ad_name = cdk.CfnParameter(
            self, 'CwlAdName',
            description='CloudWatch Logs group name',
            default='/aws/directoryservice/d-XXXXXXXXXXXXXXXXX')

        kdf_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KDFForAdEventLog",
            delivery_stream_name=kdf_ad_name.value_as_string,
            s3_destination_configuration=aws_kinesisfirehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn=f'arn:aws:s3:::{log_bucket_name}',
                prefix=f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/AD/',
                compression_format='UNCOMPRESSED',
                role_arn=(f'arn:aws:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{service_role_kdf_to_s3}')
            )
        )

        service_role_cwl_to_kdf = aws_iam.Role(
            self, 'firehoseServiceRole',
            role_name=f'aes-siem-CWLtoKinesisFirehoseRole-{cdk.Aws.REGION}',
            inline_policies={
                'cwl-to-firehose': aws_iam.PolicyDocument(
                    statements=[
                        aws_iam.PolicyStatement(
                            actions=["firehose:*"],
                            resources=[f"arn:aws:firehose:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:*"],
                            sid='CwlToFirehosePolicyGeneratedBySeimCfn'
                        )
                    ]
                )
            },
            assumed_by=aws_iam.ServicePrincipal(
                f'logs.{cdk.Aws.REGION}.amazonaws.com'))

        aws_logs.CfnSubscriptionFilter(
            self, 'KinesisSubscription',
            destination_arn=kdf_to_s3.attr_arn,
            filter_pattern='',
            log_group_name=cwl_ad_name.value_as_string,
            role_arn=service_role_cwl_to_kdf.role_arn
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

        role_get_workspaces_inventory = aws_iam.Role(
            self, 'getWorkspacesInventoryRole',
            role_name='aes-siem-get-workspaces-inventory-role',
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
            function_name='aes-siem-get-workspaces-inventory',
            description='Amazon ES: get workspaces inventory',
            handler='index.lambda_handler',
            timeout=cdk.Duration.seconds(300),
            role=role_get_workspaces_inventory,
            environment={'log_bucket_name': log_bucket_name}
        )
        rule = aws_events.Rule(
            self, 'eventBridgeRuleWorkSpaceInventory',
            rule_name='aes-siem-workspaces-inventory-to-lambda',
            schedule=aws_events.Schedule.rate(
                cdk.Duration.minutes(cwe_frequency.value_as_number)))
        rule.add_target(aws_events_targets.LambdaFunction(lambda_func))

        kdf_to_s3 = aws_kinesisfirehose.CfnDeliveryStream(
            self, "KDFForWorkSpacesEvent",
            delivery_stream_name='aes-siem-workspaces-event-to-s3',
            s3_destination_configuration=aws_kinesisfirehose.CfnDeliveryStream.S3DestinationConfigurationProperty(
                bucket_arn=f'arn:aws:s3:::{log_bucket_name}',
                prefix=f'AWSLogs/{cdk.Aws.ACCOUNT_ID}/WorkSpaces/Event/',
                compression_format='GZIP',
                role_arn=(f'arn:aws:iam::{cdk.Aws.ACCOUNT_ID}:role/'
                          f'service-role/{service_role_kdf_to_s3}')
            )
        )

        pattern = aws_events.EventPattern(
            detail_type=["WorkSpaces Access"], source=['aws.workspaces'])

        aws_events.Rule(
            self, 'eventBridgeRuleWorkSpacesEvent', event_pattern=pattern,
            rule_name='aes-siem-workspaces-event-to-kdf',
            targets=[aws_events_targets.KinesisFirehoseStream(kdf_to_s3)])


class BasicLogExporterStack(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        log_bucket_name = cdk.CfnParameter(
            self, 'siemLogBucketName',
            description='S3 Bucket to put workspaces inventory',
            default='aes-siem-111111111111-log')

        bucket_arn = f'arn:aws:s3:::{log_bucket_name.value_as_string}'
        service_role_kdf_to_s3 = aws_iam.Role(
            self, 'firehoseServiceRole', path='/service-role/',
            role_name=f'aes-siem-firehose-to-s3-service-role-{cdk.Aws.REGION}',
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
                            resources=[f"arn:aws:logs:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}:log-group:/aws/kinesisfirehose/*:log-stream:*"])],
                ),
            },
            assumed_by=aws_iam.ServicePrincipal('firehose.amazonaws.com'))

        ######################################################################
        # output for cross stack
        ######################################################################
        cdk.CfnOutput(self, 'logBucketName',
                      export_name='sime-log-bucket-name',
                      value=log_bucket_name.value_as_string)
        cdk.CfnOutput(self, 'kdfRoleName',
                      export_name='siem-kdf-to-s3-role-name',
                      value=service_role_kdf_to_s3.role_name)


class DeploymentSamplesStack(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str,
                 **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here
