# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.1'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import aws_cdk as cdk
from aws_cdk import aws_cloudformation, aws_iam, aws_lambda


class ResourceValidator(object):
    def __init__(self, scope, SOLUTION_NAME: str, PARTITION: str,
                 AOS_DOMAIN: str,
                 solution_prefix: str, aos_subnet_ids_raw: list,
                 s3bucket_name_log: str, s3bucket_name_snapshot: str,
                 cfn_parameters_dict: dict, cfn_conditions_dict: dict,
                 same_lambda_func_version, region_mapping):

        self.scope = scope
        self.SOLUTION_NAME = SOLUTION_NAME
        self.PARTITION = PARTITION
        self.AOS_DOMAIN = AOS_DOMAIN
        self.solution_prefix = solution_prefix
        self.aos_subnet_ids_raw = aos_subnet_ids_raw
        self.s3bucket_name_log = s3bucket_name_log
        self.s3bucket_name_snapshot = s3bucket_name_snapshot
        self.same_lambda_func_version = same_lambda_func_version
        self.deployment_target = cfn_parameters_dict['deployment_target']
        self.log_bucket_policy_update = (
            cfn_parameters_dict['log_bucket_policy_update'])
        self.vpce_id = cfn_parameters_dict['vpce_id']
        self.has_lambda_architectures_prop = (
            cfn_conditions_dict['has_lambda_architectures_prop'])
        self.is_global_region = cfn_conditions_dict['is_global_region']
        self.region_mapping = region_mapping

    def validate_for_siem_deployment(self):
        # check VPC Endpoint
        function_name = 'aes-siem-resource-validator'
        lambda_resource_validator = aws_lambda.Function(
            self.scope, 'LambdaResourceValidator',
            function_name=function_name,
            description=(f'{self.SOLUTION_NAME} / resource validator '
                         'for deployment'),
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            code=aws_lambda.Code.from_asset('../lambda/deploy_es'),
            handler='index.resource_validator_handler',
            memory_size=128,
            timeout=cdk.Duration.seconds(30),
            reserved_concurrent_executions=1,
            environment={
                'ACCOUNT_ID': cdk.Aws.ACCOUNT_ID,
                'DEPLOYMENT_TARGET': self.deployment_target.value_as_string,
                'VPCE_ID': self.vpce_id.value_as_string,
                'DOMAIN_OR_COLLECTION_NAME': self.AOS_DOMAIN,
                'SOLUTION_PREFIX': self.solution_prefix,
                'AOS_SUBNET_IDS': ','.join(self.aos_subnet_ids_raw),
                'S3_SNAPSHOT': self.s3bucket_name_snapshot,
                'S3_LOG': self.s3bucket_name_log,
            },
            current_version_options=aws_lambda.VersionOptions(
                removal_policy=cdk.RemovalPolicy.RETAIN,
                description=__version__
            ),
        )
        if not self.same_lambda_func_version(function_name):
            lambda_resource_validator.current_version
        lambda_resource_validator.node.default_child.add_property_override(
            "Architectures",
            cdk.Fn.condition_if(
                self.has_lambda_architectures_prop.logical_id,
                [self.region_mapping.find_in_map(
                    cdk.Aws.REGION, 'LambdaArch')],
                cdk.Aws.NO_VALUE
            )
        )
        # lambda_resource_validator.node.default_child.add_property_override(
        #    "Runtime", cdk.Fn.condition_if(
        #        self.is_global_region.logical_id, 'python3.11', 'python3.10'))

        validator_inline_policy = aws_iam.Policy(
            self.scope, 'aes-siem-policy-for-vpc-validation',
            policy_name='aes-siem-policy-for-vpc-validation',
            statements=[
                aws_iam.PolicyStatement(
                    # for vpc access
                    actions=[
                        "ec2:CreateNetworkInterface",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DescribeVpcEndpointServices",
                        "ec2:DeleteNetworkInterface",
                        "ec2:AssignPrivateIpAddresses",
                        "ec2:UnassignPrivateIpAddresses"
                    ],
                    resources=["*"]
                ),
                aws_iam.PolicyStatement(
                    # for vpc validation
                    actions=[
                        "aoss:BatchGetCollection",
                        "aoss:BatchGetVpcEndpoint",
                        "ec2:DescribeRouteTables",
                        "ec2:DescribeSubnets",
                        "ec2:DescribeVpcEndpoints",
                        "ec2:DescribeVpcs",
                        "es:DescribeVpcEndpoints",
                        "iam:GetRole",
                    ],
                    resources=["*"]
                ),
                aws_iam.PolicyStatement(
                    sid='ToGetBucektPolicy',
                    actions=[
                        "s3:GetBucketPolicy",
                    ],
                    resources=[(f'arn:{self.PARTITION}:s3:::'
                                f'{self.s3bucket_name_log}')]
                ),
                aws_iam.PolicyStatement(
                    sid='ToUploadPolicy',
                    actions=[
                        "s3:PutObject",
                    ],
                    resources=[(f'arn:{self.PARTITION}:s3:::'
                                f'{self.s3bucket_name_snapshot}/*')]
                ),
                aws_iam.PolicyStatement(
                    sid='ToPutParameterPolicy',
                    actions=[
                        "ssm:PutParameter",
                        "ssm:DeleteParameters",
                    ],
                    resources=[
                        (f'arn:{self.PARTITION}:ssm:*:{cdk.Aws.ACCOUNT_ID}'
                            ':parameter/siem/bucketpolicy/*')
                    ]
                )
            ]
        )
        lambda_resource_validator.role.attach_inline_policy(
            validator_inline_policy)

        validated_resource = aws_cloudformation.CfnCustomResource(
            self.scope, 'ExecCustomResourceValidator',
            service_token=lambda_resource_validator.function_arn,)
        validated_resource.add_override(
            'Properties.ConfigVersion', __version__)
        validated_resource.add_override(
            'Properties.vpce', self.vpce_id.value_as_string)
        validated_resource.add_override(
            'Properties.DeploymentTarget',
            self.deployment_target.value_as_string)
        validated_resource.add_override(
            'Properties.BucketPolicyUpdate',
            self.log_bucket_policy_update.value_as_string)
        validated_resource.add_dependency(
            lambda_resource_validator.role.node.default_child)
        validated_resource.add_dependency(
            validator_inline_policy.node.default_child)

        return validated_resource
