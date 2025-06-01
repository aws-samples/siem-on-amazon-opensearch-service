# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.4'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import json

import aws_cdk as cdk
from aws_cdk import (
    aws_cloudformation,
    aws_iam,
    aws_lambda,
    aws_opensearchserverless,
)


class AosDeployment(object):
    def __init__(self, scope, SOLUTION_NAME: str, PARTITION: str,
                 AOS_DOMAIN: str, validated_resource, solution_prefix: str,
                 vpc_type: str, aos_sg_is_associated: bool,
                 aos_subnet_ids_raw: list, same_lambda_func_version,
                 cfn_parameters_dict: dict, cfn_conditions_dict: dict,
                 aes_siem_snapshot_role, s3_snapshot, lambda_metrics_exporter,
                 lambda_es_loader, sg_vpc_aes_siem, sg_vpc_noinbound_aes_siem,
                 region_mapping):

        self.scope = scope
        self.SOLUTION_NAME = SOLUTION_NAME
        self.PARTITION = PARTITION
        self.AOS_DOMAIN = AOS_DOMAIN
        self.validated_resource = validated_resource

        self.solution_prefix = solution_prefix
        self.vpc_type = vpc_type
        self.aos_sg_is_associated = aos_sg_is_associated
        self.aos_subnet_ids_raw = aos_subnet_ids_raw

        self.deployment_target = cfn_parameters_dict['deployment_target']
        self.domain_or_collection_name = (
            cfn_parameters_dict['domain_or_collection_name'])
        self.allow_source_address = cfn_parameters_dict['allow_source_address']
        self.vpce_id = cfn_parameters_dict['vpce_id']

        self.is_serverless = cfn_conditions_dict['is_serverless']
        self.is_in_vpc = cfn_conditions_dict['is_in_vpc']
        self.has_lambda_architectures_prop = (
            cfn_conditions_dict['has_lambda_architectures_prop'])
        self.is_global_region = cfn_conditions_dict['is_global_region']

        self.aes_siem_snapshot_role = aes_siem_snapshot_role
        self.s3_snapshot = s3_snapshot
        self.lambda_metrics_exporter = lambda_metrics_exporter
        self.lambda_es_loader = lambda_es_loader
        self.sg_vpc_aes_siem = sg_vpc_aes_siem
        self.sg_vpc_noinbound_aes_siem = sg_vpc_noinbound_aes_siem

        self.same_lambda_func_version = same_lambda_func_version

        self.region_mapping = region_mapping

    def setup_domain_or_collection(self):
        ######################################################################
        # IAM Policy to deploy OpenSearch Managed Cluster
        ######################################################################
        # policy to export logs to CloudWatch Logs
        loggroup_arn_prefix = (
            f'arn:{self.PARTITION}:logs:{cdk.Aws.REGION}:{cdk.Aws.ACCOUNT_ID}')
        loggroup_aes = f'log-group:/aws/aes/domains/{self.AOS_DOMAIN}/*'
        loggroup_opensearch = (
            f'log-group:/aws/OpenSearchService/domains/{self.AOS_DOMAIN}/*')
        loggroup_lambda = 'log-group:/aws/lambda/aes-siem-*'
        policydoc_create_loggroup = aws_iam.PolicyDocument(
            statements=[
                aws_iam.PolicyStatement(
                    actions=[
                        "logs:PutResourcePolicy",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams",
                    ],
                    resources=[f'{loggroup_arn_prefix}:*', ]
                ),
                aws_iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:PutRetentionPolicy"
                    ],
                    resources=[
                        f"{loggroup_arn_prefix}:{loggroup_aes}",
                        f"{loggroup_arn_prefix}:{loggroup_opensearch}",
                        f"{loggroup_arn_prefix}:{loggroup_lambda}",
                    ],
                )
            ]
        )

        # policy to deploy OpenSearch
        sr_arn = (f"arn:{self.PARTITION}:iam::{cdk.Aws.ACCOUNT_ID}:role/"
                  "aws-service-role/")
        opensearch_deployment_policy = aws_iam.PolicyDocument(
            statements=[
                aws_iam.PolicyStatement(
                    actions=[
                        "ec2:DescribeVpcEndpoints",
                        "es:CreateDomain",
                        "es:DescribeDomain",
                        "es:ESHttp*",
                        "es:UpdateDomainConfig",
                        "iam:GetRole",
                    ],
                    resources=['*']
                ),
                aws_iam.PolicyStatement(
                    actions=['iam:CreateServiceLinkedRole'],
                    resources=[
                        (f"{sr_arn}observability.aoss.amazonaws.com/"
                         "AWSServiceRoleForAmazonOpenSearchServerless"),
                        (f"{sr_arn}opensearchservice.amazonaws.com/"
                         "AWSServiceRoleForAmazonOpenSearchService"),
                        (f"{sr_arn}es.amazonaws.com/"
                         "AWSServiceRoleForAmazonElasticsearchService"),
                    ]
                ),
                aws_iam.PolicyStatement(
                    actions=[
                        "aoss:APIAccessAll",
                        "aoss:DashboardsAccessAll",
                        "aoss:BatchGetCollection",
                        "aoss:BatchGetVpcEndpoint",
                        "aoss:CreateCollection",
                        "aoss:CreateSecurityPolicy",
                        "aoss:GetSecurityPolicy",
                        "aoss:UpdateSecurityPolicy",
                    ],
                    resources=["*"]
                )
            ]
        )

        # policy to use crhelper
        policydoc_crhelper = aws_iam.PolicyDocument(
            statements=[
                aws_iam.PolicyStatement(
                    actions=[
                        "events:DeleteRule",
                        "events:ListRules",
                        "events:PutRule",
                        "events:PutTargets",
                        "events:RemoveTargets",
                        "lambda:AddPermission",
                        "lambda:RemovePermission",
                    ],
                    resources=["*"]
                )
            ]
        )

        # policy to assume role to register snapshot repo
        policydoc_assume_snapshotrole = aws_iam.PolicyDocument(
            statements=[
                aws_iam.PolicyStatement(
                    actions=["iam:PassRole"],
                    resources=[self.aes_siem_snapshot_role.role_arn]
                ),
            ]
        )

        # policy to back up data into snapshot bucket
        policydoc_backup = aws_iam.PolicyDocument(
            statements=[
                aws_iam.PolicyStatement(
                    actions=["s3:ListBucket"],
                    resources=[self.s3_snapshot.bucket_arn]
                ),
                aws_iam.PolicyStatement(
                    actions=["s3:GetObject", "s3:PutObject"],
                    resources=[self.s3_snapshot.bucket_arn + '/*']
                )
            ]
        )

        aes_siem_deploy_role_for_lambda = aws_iam.Role(
            self.scope, 'AesSiemDeployRoleForLambda',
            role_name='aes-siem-deploy-role-for-lambda',
            managed_policies=[
                aws_iam.ManagedPolicy.from_aws_managed_policy_name(
                    'service-role/AWSLambdaBasicExecutionRole'),
            ],
            inline_policies={
                'cwl_loggroup': policydoc_create_loggroup,
                'opensearch_deployment': opensearch_deployment_policy,
                'crhelper': policydoc_crhelper,
                'assume_snapshotrole': policydoc_assume_snapshotrole,
                's3access': policydoc_backup,
            },
            assumed_by=aws_iam.ServicePrincipal('lambda.amazonaws.com')
        )

        ######################################################################
        # setup OpenSearch Serverless security policy
        ######################################################################
        AOSS_COLLECTION = self.domain_or_collection_name.value_as_string

        # https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-genref.html
        aoss_data_policy_for_deployment = [
            {
                "Description": "For SIEM Deployment",
                "Principal": [aes_siem_deploy_role_for_lambda.role_arn],
                "Rules": [
                    {
                        "Resource": [f"collection/{AOSS_COLLECTION}"],
                        "Permission":[
                            "aoss:CreateCollectionItems",
                            "aoss:UpdateCollectionItems"],
                        "ResourceType":"collection"
                    },
                    {
                        "Resource": [f"index/{AOSS_COLLECTION}/*"],
                        "Permission": ["aoss:*"],
                        "ResourceType":"index"
                    }
                ]
            },
            {
                "Description": "For SIEM Deployment2",
                "Principal": [aes_siem_deploy_role_for_lambda.role_arn],
                "Rules": [
                    {
                        "Resource": ["collection/*"],
                        "Permission":["aoss:DescribeCollectionItems"],
                        "ResourceType":"collection"
                    },
                ]
            }
        ]
        cfn_access_policy1 = aws_opensearchserverless.CfnAccessPolicy(
            self.scope, "AossDataAccessPolicyForDeployment",
            description="Created By SIEM Solution. DO NOT EDIT",
            name='siem-data-access-for-deploymet',
            policy=json.dumps(
                aoss_data_policy_for_deployment, separators=(',', ':')),
            type="data"
        )
        cfn_access_policy1.cfn_options.condition = self.is_serverless

        aoss_data_policy_for_loader = [
            {
                "Description": "For SIEM Loader",
                "Principal": [self.lambda_es_loader.role.role_arn],
                "Rules": [
                    {"Resource": [
                        f"index/{AOSS_COLLECTION}/log-*",
                        f"index/{AOSS_COLLECTION}/metrics-*"],
                        "Permission": [
                        "aoss:CreateIndex",
                        "aoss:UpdateIndex",
                        "aoss:ReadDocument",
                        "aoss:WriteDocument"],
                        "ResourceType":"index"}
                ]
            },
            {
                "Description": "For SIEM metrics exporter",
                "Principal": [self.lambda_metrics_exporter.role.role_arn],
                "Rules": [
                    {"Resource": [f"index/{AOSS_COLLECTION}/*"],
                        "Permission": ["aoss:DescribeIndex"],
                        "ResourceType":"index"}
                ]
            }
        ]
        cfn_access_policy2 = aws_opensearchserverless.CfnAccessPolicy(
            self.scope, "AossDataAccessPolicyForLoader",
            description="Created By SIEM Solution. DO NOT EDIT",
            name='siem-data-access-for-loader',
            policy=json.dumps(
                aoss_data_policy_for_loader, separators=(',', ':')),
            type="data"
        )
        cfn_access_policy2.cfn_options.condition = self.is_serverless

        ######################################################################
        # setup deployment script for opensearch
        ######################################################################

        function_name = 'aes-siem-deploy-aes'
        lambda_deploy_es = aws_lambda.Function(
            self.scope, 'LambdaDeployAES',
            function_name=function_name,
            description=f'{self.SOLUTION_NAME} / opensearch domain deployment',
            runtime=aws_lambda.Runtime.PYTHON_3_11,
            code=aws_lambda.Code.from_asset('../lambda/deploy_es'),
            handler='index.aes_domain_handler',
            memory_size=128,
            timeout=cdk.Duration.seconds(300),
            reserved_concurrent_executions=1,
            environment={
                'ACCOUNT_ID': cdk.Aws.ACCOUNT_ID,
                'DEPLOYMENT_TARGET': self.deployment_target.value_as_string,
                'DOMAIN_OR_COLLECTION_NAME': (
                    self.domain_or_collection_name.value_as_string),
                'S3_SNAPSHOT': self.s3_snapshot.bucket_name,
                'SOLUTION_PREFIX': self.solution_prefix,
                'VPCE_ID': self.vpce_id.value_as_string,
                'ROLE_AOS_ADMIN': aes_siem_deploy_role_for_lambda.role_arn,
                'ALLOWED_SOURCE_ADDRESSES': (
                    self.allow_source_address.value_as_string),
            },
            role=aes_siem_deploy_role_for_lambda,
            current_version_options=aws_lambda.VersionOptions(
                removal_policy=cdk.RemovalPolicy.RETAIN,
                description=__version__
            ),
        )
        if not self.same_lambda_func_version(function_name):
            lambda_deploy_es.current_version
        lambda_deploy_es.node.default_child.add_property_override(
            "Architectures",
            cdk.Fn.condition_if(
                self.has_lambda_architectures_prop.logical_id,
                [self.region_mapping.find_in_map(
                    cdk.Aws.REGION, 'LambdaArch')],
                cdk.Aws.NO_VALUE
            )
        )
        # lambda_deploy_es.node.default_child.add_property_override(
        #    "Runtime", cdk.Fn.condition_if(
        #        self.is_global_region.logical_id, 'python3.10', 'python3.9'))

        if self.vpc_type and not self.aos_sg_is_associated:
            lambda_deploy_es.add_environment(
                'AOS_SUBNET_IDS', ','.join(self.aos_subnet_ids_raw))
            if self.sg_vpc_aes_siem:
                lambda_deploy_es.add_environment(
                    'AOS_SECURITY_GROUP_ID',
                    self.sg_vpc_aes_siem.security_group_id)

        # execute lambda_deploy_es to deploy Amaozon OpenSearch Service Domain
        aes_domain = aws_cloudformation.CfnCustomResource(
            self.scope, 'AesSiemDomainDeployedR2',
            service_token=lambda_deploy_es.function_arn,)
        aes_domain.add_override('Properties.ConfigVersion', __version__)
        aes_domain.add_override('Properties.Target',
                                self.deployment_target.value_as_string)
        aes_domain.add_override('Properties.Name',
                                self.domain_or_collection_name.value_as_string)
        aes_domain.add_override('Properties.vpce',
                                self.vpce_id.value_as_string)
        aes_domain.node.add_dependency(aes_siem_deploy_role_for_lambda)

        endpoint = aes_domain.get_att('endpoint').to_string()

        # configure opensearch
        function_name = 'aes-siem-configure-aes'
        lambda_configure_es = aws_lambda.Function(
            self.scope, 'LambdaConfigureAES',
            function_name=function_name,
            description=f'{self.SOLUTION_NAME} / opensearch configuration',
            runtime=aws_lambda.Runtime.PYTHON_3_11,
            code=aws_lambda.Code.from_asset('../lambda/deploy_es'),
            handler='index.aes_config_handler',
            memory_size=128,
            timeout=cdk.Duration.seconds(600),
            reserved_concurrent_executions=1,
            environment={
                'ACCOUNT_ID': cdk.Aws.ACCOUNT_ID,
                'DOMAIN_OR_COLLECTION_NAME': (
                    self.domain_or_collection_name.value_as_string),
                'SOLUTION_PREFIX': self.solution_prefix,
                'ENDPOINT': endpoint,
                'S3_SNAPSHOT': self.s3_snapshot.bucket_name,
                'ROLE_AOS_ADMIN': aes_siem_deploy_role_for_lambda.role_arn,
                'ROLE_ES_LOADER': self.lambda_es_loader.role.role_arn,
                'ROLE_METRICS_EXPORTER': (
                    self.lambda_metrics_exporter.role.role_arn),
                'ROLE_SNAPSHOT': self.aes_siem_snapshot_role.role_arn,
            },
            role=aes_siem_deploy_role_for_lambda,
            initial_policy=[
                aws_iam.PolicyStatement(
                    # for vpc access
                    actions=[
                        "ec2:CreateNetworkInterface",
                        "ec2:DescribeNetworkInterfaces",
                        "ec2:DeleteNetworkInterface",
                        "ec2:AssignPrivateIpAddresses",
                        "ec2:UnassignPrivateIpAddresses"
                    ],
                    resources=['*']
                )
            ],
            current_version_options=aws_lambda.VersionOptions(
                removal_policy=cdk.RemovalPolicy.RETAIN,
                description=__version__
            ),
        )
        if not self.same_lambda_func_version(function_name):
            lambda_configure_es.current_version
        lambda_configure_es.node.default_child.add_property_override(
            "Architectures",
            cdk.Fn.condition_if(
                self.has_lambda_architectures_prop.logical_id,
                [self.region_mapping.find_in_map(
                    cdk.Aws.REGION, 'LambdaArch')],
                cdk.Aws.NO_VALUE
            )
        )
        # lambda_configure_es.node.default_child.add_property_override(
        #    "Runtime", cdk.Fn.condition_if(
        #        self.is_global_region.logical_id, 'python3.10', 'python3.9'))

        lambda_configure_es.node.default_child.add_property_override(
            "VpcConfig.SubnetIds",
            self.validated_resource.get_att('subnets').to_string()
        )
        lambda_configure_es.node.default_child.add_property_override(
            "VpcConfig.SecurityGroupIds",
            cdk.Fn.condition_if(
                self.is_in_vpc.logical_id,
                [self.sg_vpc_noinbound_aes_siem.attr_group_id],
                []
            )
        )
        # lambda_configure_es.node.add_dependency(
        #       self.sg_vpc_noinbound_aes_siem)

        aes_config = aws_cloudformation.CfnCustomResource(
            self.scope, 'AesSiemDomainConfiguredR2',
            service_token=lambda_configure_es.function_arn,)
        aes_config.add_override('Properties.ConfigVersion', __version__)
        aes_config.add_override('Properties.Target',
                                self.deployment_target.value_as_string)
        aes_config.add_override('Properties.Name',
                                self.domain_or_collection_name.value_as_string)
        aes_config.add_dependency(aes_domain)
        aes_config.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

        # output result
        collection_id = cdk.Fn.select(0, cdk.Fn.split('.', endpoint))

        result = {
            'endpoint': endpoint,
            'aoss_type': aes_domain.get_att('aoss_type').to_string(),
            'aos_domain_arn': (
                f'arn:{self.PARTITION}:es:{cdk.Aws.REGION}:'
                f'{cdk.Aws.ACCOUNT_ID}:domain/{self.AOS_DOMAIN}'),
            'collection_arn': (
                f'arn:{self.PARTITION}:aoss:{cdk.Aws.REGION}'
                f':{cdk.Aws.ACCOUNT_ID}:collection/{collection_id}'),
            'kibana_admin_user': aes_domain.get_att('kibanaadmin').to_string(),
            'kibana_admin_pass': aes_domain.get_att('kibanapass').to_string(),
            'deploy_role_arn': aes_siem_deploy_role_for_lambda.role_arn,
        }

        return result
