# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.0-beta.3'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import aws_cdk as cdk
from aws_cdk import (
    aws_cloudformation,
    aws_events,
    aws_events_targets,
    aws_iam,
    aws_lambda,
    aws_logs,
    aws_stepfunctions,
    aws_stepfunctions_tasks,
)


class Enrichment(object):
    def __init__(self, scope, SOLUTION_NAME: str, s3bucket_name_geo: str,
                 same_lambda_func_version, cfn_parameters_dict: dict,
                 cfn_conditions_dict: dict, region_mapping):

        self.scope = scope
        self.SOLUTION_NAME = SOLUTION_NAME
        self.s3bucket_name_geo = s3bucket_name_geo
        self.same_lambda_func_version = same_lambda_func_version

        self.geoip_license_key = cfn_parameters_dict['geoip_license_key']
        self.ioc_download_interval = (
            cfn_parameters_dict['ioc_download_interval'])
        self.enable_tor = cfn_parameters_dict['enable_tor']
        self.otx_api_key = cfn_parameters_dict['otx_api_key']
        self.enable_abuse_ch = cfn_parameters_dict['enable_abuse_ch']

        self.has_lambda_architectures_prop = (
            cfn_conditions_dict['has_lambda_architectures_prop'])
        self.is_global_region = cfn_conditions_dict['is_global_region']
        self.has_geoip_license = cfn_conditions_dict['has_geoip_license']
        self.enable_ioc = cfn_conditions_dict['enable_ioc']

        self.region_mapping = region_mapping

    def setup_geoip(self):
        function_name = 'aes-siem-geoip-downloader'
        lambda_geo = aws_lambda.Function(
            self.scope, 'LambdaGeoipDownloader',
            function_name=function_name,
            description=f'{self.SOLUTION_NAME} / geoip-downloader',
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            code=aws_lambda.Code.from_asset('../lambda/geoip_downloader'),
            handler='index.lambda_handler',
            memory_size=320,
            timeout=cdk.Duration.seconds(300),
            reserved_concurrent_executions=1,
            environment={
                's3bucket_name': self.s3bucket_name_geo,
                'license_key': self.geoip_license_key.value_as_string,
            },
            current_version_options=aws_lambda.VersionOptions(
                removal_policy=cdk.RemovalPolicy.RETAIN,
                description=__version__
            ),
        )
        if not self.same_lambda_func_version(function_name):
            lambda_geo.current_version
        lambda_geo.node.default_child.add_property_override(
            "Architectures",
            cdk.Fn.condition_if(
                self.has_lambda_architectures_prop.logical_id,
                [self.region_mapping.find_in_map(
                    cdk.Aws.REGION, 'LambdaArch')],
                cdk.Aws.NO_VALUE
            )
        )
        # lambda_geo.node.default_child.add_property_override(
        #    "Runtime", cdk.Fn.condition_if(
        #        self.is_global_region.logical_id, 'python3.10', 'python3.9'))

        # Download geoip to S3 once by executing lambda_geo
        get_geodb = aws_cloudformation.CfnCustomResource(
            self.scope, 'ExecLambdaGeoipDownloader',
            service_token=lambda_geo.function_arn,)
        get_geodb.add_override('Properties.License',
                               self.geoip_license_key.value_as_string)
        get_geodb.cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

        # Download geoip every 12 hours
        geoip_rule = aws_events.Rule(
            self.scope, 'EventBridgeRuleLambdaGeoipDownloader',
            enabled=True,
            schedule=aws_events.Schedule.rate(cdk.Duration.hours(12)),
            targets=[aws_events_targets.LambdaFunction(lambda_geo)],
        )
        geoip_rule.node.default_child.add_property_override(
            "State",
            cdk.Fn.condition_if(
                self.has_geoip_license.logical_id, 'ENABLED', 'DISABLED')
        )

        return lambda_geo

    def setup_ioc(self):
        # IOC StepFunctions
        function_name = 'aes-siem-ioc-plan'
        lambda_ioc_plan = aws_lambda.Function(
            self.scope, 'LambdaIocPlan',
            function_name=function_name,
            description=f'{self.SOLUTION_NAME} / ioc-plan',
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            code=aws_lambda.Code.from_asset('../lambda/ioc_database'),
            handler='lambda_function.plan',
            memory_size=128,
            timeout=cdk.Duration.seconds(300),
            reserved_concurrent_executions=1,
            environment={
                'GEOIP_BUCKET': self.s3bucket_name_geo,
                'OTX_API_KEY': self.otx_api_key.value_as_string,
                'TOR': self.enable_tor.value_as_string,
                'ABUSE_CH': self.enable_abuse_ch.value_as_string,
                'LOG_LEVEL': 'INFO'
            },
            current_version_options=aws_lambda.VersionOptions(
                removal_policy=cdk.RemovalPolicy.RETAIN,
                description=__version__
            ),
        )
        if not self.same_lambda_func_version(function_name):
            lambda_ioc_plan.current_version
        lambda_ioc_plan.node.default_child.add_property_override(
            "Architectures",
            cdk.Fn.condition_if(
                self.has_lambda_architectures_prop.logical_id,
                [self.region_mapping.find_in_map(
                    cdk.Aws.REGION, 'LambdaArch')],
                cdk.Aws.NO_VALUE
            )
        )
        # lambda_ioc_plan.node.default_child.add_property_override(
        #    "Runtime", cdk.Fn.condition_if(
        #        self.is_global_region.logical_id, 'python3.10', 'python3.9'))

        function_name = 'aes-siem-ioc-download'
        lambda_ioc_download = aws_lambda.Function(
            self.scope, 'LambdaIocDownload',
            function_name=function_name,
            description=f'{self.SOLUTION_NAME} / ioc-download',
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            code=aws_lambda.Code.from_asset('../lambda/ioc_database'),
            handler='lambda_function.download',
            memory_size=384,
            timeout=cdk.Duration.seconds(900),
            environment={
                'GEOIP_BUCKET': self.s3bucket_name_geo,
                'OTX_API_KEY': self.otx_api_key.value_as_string,
                'LOG_LEVEL': 'INFO'
            },
            initial_policy=[
                aws_iam.PolicyStatement(
                    actions=[
                        "s3:ListAllMyBuckets",
                        "s3:PutFunctionConcurrency",
                    ],
                    resources=["*"],
                )
            ],
            current_version_options=aws_lambda.VersionOptions(
                removal_policy=cdk.RemovalPolicy.RETAIN,
                description=__version__
            ),
        )
        if not self.same_lambda_func_version(function_name):
            lambda_ioc_download.current_version
        lambda_ioc_download.node.default_child.add_property_override(
            "Architectures",
            cdk.Fn.condition_if(
                self.has_lambda_architectures_prop.logical_id,
                [self.region_mapping.find_in_map(
                    cdk.Aws.REGION, 'LambdaArch')],
                cdk.Aws.NO_VALUE
            )
        )
        # lambda_ioc_download.node.default_child.add_property_override(
        #    "Runtime", cdk.Fn.condition_if(
        #        self.is_global_region.logical_id, 'python3.10', 'python3.9'))

        function_name = 'aes-siem-ioc-createdb'
        lambda_ioc_createdb = aws_lambda.Function(
            self.scope, 'LambdaIocCreatedb',
            function_name=function_name,
            description=f'{self.SOLUTION_NAME} / ioc-createdb',
            runtime=aws_lambda.Runtime.PYTHON_3_9,
            code=aws_lambda.Code.from_asset('../lambda/ioc_database'),
            handler='lambda_function.createdb',
            memory_size=1024,
            timeout=cdk.Duration.seconds(900),
            environment={
                'GEOIP_BUCKET': self.s3bucket_name_geo,
                'LOG_LEVEL': 'INFO'
            },
            current_version_options=aws_lambda.VersionOptions(
                removal_policy=cdk.RemovalPolicy.RETAIN,
                description=__version__
            ),
        )
        if not self.same_lambda_func_version(function_name):
            lambda_ioc_createdb.current_version
        lambda_ioc_createdb.node.default_child.add_property_override(
            "Architectures",
            cdk.Fn.condition_if(
                self.has_lambda_architectures_prop.logical_id,
                [self.region_mapping.find_in_map(
                    cdk.Aws.REGION, 'LambdaArch')],
                cdk.Aws.NO_VALUE
            )
        )
        # lambda_ioc_createdb.node.default_child.add_property_override(
        #    "Runtime", cdk.Fn.condition_if(
        #        self.is_global_region.logical_id, 'python3.10', 'python3.9'))

        task_ioc_plan = aws_stepfunctions_tasks.LambdaInvoke(
            self.scope, "IocPlan",
            payload=aws_stepfunctions.TaskInput.from_text(''),
            lambda_function=lambda_ioc_plan,
            output_path="$.Payload"
        )
        ioc_not_found = aws_stepfunctions.Condition.is_not_present(
            "$.mapped[0].ioc")
        skip_download_state = aws_stepfunctions.Pass(
            self.scope, "SkipDownload")
        map_download = aws_stepfunctions.Map(
            self.scope, 'MapDownload',
            items_path=aws_stepfunctions.JsonPath.string_at("$.mapped"),
            parameters={"mapped.$": "$$.Map.Item.Value"},
            max_concurrency=4,
        )
        task_ioc_download = aws_stepfunctions_tasks.LambdaInvoke(
            self.scope, "IocDownload",
            lambda_function=lambda_ioc_download,
            output_path="$.Payload",
            task_timeout=aws_stepfunctions.Timeout.duration(
                cdk.Duration.seconds(899)),
        )
        ignore_timeout_state = aws_stepfunctions.Pass(
            self.scope, "IgnoreTimeout")
        task_ioc_download.add_catch(
            ignore_timeout_state, errors=['States.Timeout',
                                          'States.TaskFailed'],
            result_path='$.catcher')
        task_ioc_createdb = aws_stepfunctions_tasks.LambdaInvoke(
            self.scope, "IocCreatedb",
            lambda_function=lambda_ioc_createdb,
            output_path=None)
        definition = task_ioc_plan.next(aws_stepfunctions.Choice(
            self.scope, "need to download?")
            .when(ioc_not_found, skip_download_state)
            .otherwise(map_download.next(task_ioc_createdb)))
        map_download.iterator(task_ioc_download)
        ioc_state_machine_log_group = aws_logs.LogGroup(
            self.scope, "IocStateMachineLogGroup",
            log_group_name='/aws/vendedlogs/states/aes-siem-ioc-logs',
            retention=aws_logs.RetentionDays.ONE_MONTH,
            removal_policy=cdk.RemovalPolicy.DESTROY)
        ioc_state_machine = aws_stepfunctions.StateMachine(
            self.scope, "IocStateMachine",
            state_machine_name='aes-siem-ioc-state-machine',
            definition_body=(
                aws_stepfunctions.DefinitionBody.from_chainable(definition)),
            timeout=cdk.Duration.minutes(60),
            logs=aws_stepfunctions.LogOptions(
                destination=ioc_state_machine_log_group,
                level=aws_stepfunctions.LogLevel.ALL))

        # Download IOC Database every xxx minutes
        ioc_rule = aws_events.Rule(
            self.scope, 'EventBridgeRuleStepFunctionsIoc',
            schedule=aws_events.Schedule.rate(
                cdk.Duration.minutes(
                    self.ioc_download_interval.value_as_number)),
            targets=[aws_events_targets.SfnStateMachine(ioc_state_machine)],
        )
        ioc_rule.node.default_child.add_property_override(
            "State",
            cdk.Fn.condition_if(
                self.enable_ioc.logical_id, 'ENABLED', 'DISABLED')
        )

        return lambda_ioc_plan, lambda_ioc_download, lambda_ioc_createdb
