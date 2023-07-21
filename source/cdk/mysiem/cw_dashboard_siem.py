# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.10.0'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import aws_cdk as cdk
from aws_cdk import aws_cloudwatch


class CloudWatchDashboardSiem(object):
    def __init__(self, scope, AOS_DOMAIN: str, endpoint: str,
                 cfn_conditions_dict: dict,
                 lambda_es_loader, sqs_aes_siem_splitted_logs,
                 sqs_aes_siem_dlq, total_free_storage_space_remains_low_alarm):

        self.scope = scope
        self.AOS_DOMAIN = AOS_DOMAIN
        self.endpoint = endpoint
        self.is_managed_cluster = cfn_conditions_dict['is_managed_cluster']
        self.is_serverless = cfn_conditions_dict['is_serverless']
        self.lambda_es_loader = lambda_es_loader
        self.sqs_aes_siem_splitted_logs = sqs_aes_siem_splitted_logs
        self.sqs_aes_siem_dlq = sqs_aes_siem_dlq
        self.total_free_storage_space_remains_low_alarm = (
            total_free_storage_space_remains_low_alarm)

    def create_cloudwatch_dashboard(self):
        collection_id = cdk.Fn.select(0, cdk.Fn.split('.', self.endpoint))

        cw_dashboard = aws_cloudwatch.Dashboard(
            self.scope, 'SIEMDashboard', dashboard_name='SIEM')
        cw_dashboard.node.default_child.cfn_options.condition = (
            self.is_managed_cluster)

        cw_dashboard_serverless = aws_cloudwatch.Dashboard(
            self.scope, 'SIEMDashboardServerless',
            dashboard_name='SIEM-Serverless')
        cw_dashboard_serverless.node.default_child.cfn_options.condition = (
            self.is_serverless)

        white_panel_widget = aws_cloudwatch.TextWidget(
            markdown='', height=4, width=12)
        #######################################################################
        # CloudWatch Alarm
        #######################################################################
        cwl_alarm_widget = aws_cloudwatch.TextWidget(
            markdown='# CloudWatch Alarm', height=1, width=24)
        cwl_alarm_freespace_widget = aws_cloudwatch.AlarmWidget(
            title=self.total_free_storage_space_remains_low_alarm.alarm_name,
            alarm=self.total_free_storage_space_remains_low_alarm)

        #######################################################################
        # Lambda Function
        #######################################################################
        esloader_title_widget = aws_cloudwatch.TextWidget(
            markdown=(
                f'# Lambda Function: {self.lambda_es_loader.function_name}'),
            height=1, width=24)
        # invocations
        esloader_invocations_widget = aws_cloudwatch.GraphWidget(
            title='Invocations (Count)',
            height=4, width=12, period=cdk.Duration.seconds(60),
            left=[self.lambda_es_loader.metric_invocations()],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            legend_position=aws_cloudwatch.LegendPosition.HIDDEN)
        # Error count and success rate (%)
        success_rate = aws_cloudwatch.MathExpression(
            expression='100 - 100 * errors / MAX([errors, invocations])',
            using_metrics={
                'errors': self.lambda_es_loader.metric_errors(),
                'invocations': self.lambda_es_loader.metric_invocations()},
            label='Success rate (%)', color='#2ca02c')
        esloader_success_rate_widget = aws_cloudwatch.GraphWidget(
            title="Error count and success rate (%)",
            height=4, width=12, period=cdk.Duration.seconds(60),
            left=[self.lambda_es_loader.metric_errors(
                statistic='sum', color='#d13212', label='Errors (Count)')],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            right=[success_rate],
            right_y_axis=aws_cloudwatch.YAxisProps(max=100, show_units=False))
        # throttles
        esloader_throttles_widget = aws_cloudwatch.GraphWidget(
            title='Throttles (Count)',
            height=4, width=12, period=cdk.Duration.seconds(60),
            left=[self.lambda_es_loader.metric_throttles()],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            legend_position=aws_cloudwatch.LegendPosition.HIDDEN)
        # duration
        esloader_duration_widget = aws_cloudwatch.GraphWidget(
            title='Duration (Milliseconds)',
            height=4, width=12, period=cdk.Duration.seconds(60),
            left=[self.lambda_es_loader.metric_duration(statistic='min'),
                  self.lambda_es_loader.metric_duration(statistic='avg'),
                  self.lambda_es_loader.metric_duration(statistic='max')],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))
        # concurrent exec
        esloader_concurrent_widget = aws_cloudwatch.GraphWidget(
            title='ConcurrentExecutions (Count)',
            height=4, width=12, period=cdk.Duration.seconds(60),
            left=[self.lambda_es_loader.metric_all_concurrent_executions(
                dimensions_map={
                    'FunctionName': self.lambda_es_loader.function_name})],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            legend_position=aws_cloudwatch.LegendPosition.HIDDEN)
        # timeout
        esloader_timeout_widget = aws_cloudwatch.LogQueryWidget(
            title='Longest 5 invocations',
            height=4, width=12,
            log_group_names=[
                f'/aws/lambda/{self.lambda_es_loader.function_name}'],
            view=aws_cloudwatch.LogQueryVisualizationType.TABLE,
            query_string="""fields @timestamp, @duration, @requestId
                | sort @duration desc
                | head 5""")

        #######################################################################
        # OpenSearch Service
        #######################################################################
        aos_title_widget = aws_cloudwatch.TextWidget(
            markdown=f'# OpenSearch Service: {self.AOS_DOMAIN} domain',
            height=1, width=24)
        aos_title_widget_read = aws_cloudwatch.TextWidget(
            markdown='# Read / Search', height=1, width=12)
        aos_title_widget_write = aws_cloudwatch.TextWidget(
            markdown='# Write / Indexing', height=1, width=12)
        # CPUUtilization
        aos_cpu_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='CPUUtilization', statistic="max")
        aos_cpu_widget = aws_cloudwatch.GraphWidget(
            title='Data Node CPUUtilization (Cluster Max Percentage)',
            height=4, width=12,
            left=[aos_cpu_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(max=100, show_units=False),
            legend_position=aws_cloudwatch.LegendPosition.HIDDEN)
        # JVMMemoryPressure
        aos_jvmmem_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='JVMMemoryPressure')
        aos_jvmmem_widget = aws_cloudwatch.GraphWidget(
            title='Data Node JVMMemoryPressure (Cluster Max Percentage)',
            height=4, width=12,
            left=[aos_jvmmem_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(max=100, show_units=False),
            legend_position=aws_cloudwatch.LegendPosition.HIDDEN)
        # EBS
        aos_read_throughput_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='ReadThroughput', statistic="max",
            label='ReadThroughput (Bytes/Second)')
        aos_write_throughput_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='WriteThroughput', statistic="max",
            label='WriteThroughput (Bytes/Second)')
        aos_read_iops_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='ReadIOPS', statistic="max",
            label='ReadIOPS (Count/Second)')
        aos_write_iops_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='WriteIOPS', statistic="max",
            label='WriteIOPS (Count/Second)')
        aos_read_latency_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='Readatency', statistic="max",
            label='ReadLatency (Seconds)')
        aos_read_latency_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='ReadLatency', statistic="max",
            label='ReadLatency (Seconds)')
        aos_write_latency_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='WriteLatency', statistic="max",
            label='WriteLatency (Seconds)')

        aos_disk_queue_depth_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='DiskQueueDepth', statistic="max",
            label='DiskQueueDepth (Count)')

        aos_read_throughput_iops_widget = aws_cloudwatch.GraphWidget(
            title='EBS Read Throughput / IOPS',
            height=4, width=12,
            left=[aos_read_throughput_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            right=[aos_read_iops_metric],
            right_y_axis=aws_cloudwatch.YAxisProps(show_units=False))
        aos_write_throughput_iops_widget = aws_cloudwatch.GraphWidget(
            title='EBS Write Throughput / IOPS',
            height=4, width=12,
            left=[aos_write_throughput_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            right=[aos_write_iops_metric],
            right_y_axis=aws_cloudwatch.YAxisProps(show_units=False))
        aos_read_latency_queue_widget = aws_cloudwatch.GraphWidget(
            title='EBS Read Latency / Disk Queue',
            height=4, width=12,
            left=[aos_read_latency_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            right=[aos_disk_queue_depth_metric],
            right_y_axis=aws_cloudwatch.YAxisProps(show_units=False))
        aos_write_latency_queue_widget = aws_cloudwatch.GraphWidget(
            title='EBS Write Latency / Disk Queue',
            height=4, width=12,
            left=[aos_write_latency_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            right=[aos_disk_queue_depth_metric],
            right_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        aos_cluster_disk_queue_throttle_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='ThroughputThrottle', statistic="max",
            label='Cluster Disk ThroughputThrottle')
        aos_cluster_disk_queue_throttle_widget = aws_cloudwatch.GraphWidget(
            title='Cluster DiskThroughputThrottle',
            height=4, width=12,
            left=[aos_cluster_disk_queue_throttle_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            left_annotations=[
                aws_cloudwatch.HorizontalAnnotation(value=1)])
        # Search / Indexing Rate
        aos_search_rate_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='SearchRate', statistic="avg",
            label='SearchRate (Count)')
        aos_indexing_rate_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='IndexingRate', statistic="avg",
            label='IndexingRate (Count)')
        # Search / Indexing Latency
        aos_search_latency_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='SearchLatency', statistic="avg",
            label='SearchLatency (Milliseconds)')
        aos_indexing_latency_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='IndexingLatency', statistic="avg",
            label='IndexingLatency (Milliseconds)')
        aos_search_widget = aws_cloudwatch.GraphWidget(
            title='Search Rate / Latency (Node Average)',
            height=4, width=12,
            left=[aos_search_rate_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            right=[aos_search_latency_metric],
            right_y_axis=aws_cloudwatch.YAxisProps(show_units=False))
        aos_indexing_widget = aws_cloudwatch.GraphWidget(
            title='Indexing Rate / Latency (Node Average)',
            height=4, width=12,
            left=[aos_indexing_rate_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            right=[aos_indexing_latency_metric],
            right_y_axis=aws_cloudwatch.YAxisProps(show_units=False))
        # Threadpool / Queue
        aos_searchqueue_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='ThreadpoolSearchQueue', statistic="avg")
        aos_searchqueue_widget = aws_cloudwatch.GraphWidget(
            title='ThreadpoolReadQueue (Node Average Count)',
            height=4, width=12,
            left=[aos_searchqueue_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            legend_position=aws_cloudwatch.LegendPosition.HIDDEN,
            left_annotations=[
                aws_cloudwatch.HorizontalAnnotation(value=1000)])

        aos_writequeue_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='ThreadpoolWriteQueue', statistic="avg")
        aos_writequeue_widget = aws_cloudwatch.GraphWidget(
            title='ThreadpoolWriteQueue (Node Average Count)',
            height=4, width=12,
            left=[aos_writequeue_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            legend_position=aws_cloudwatch.LegendPosition.HIDDEN,
            left_annotations=[
                aws_cloudwatch.HorizontalAnnotation(value=10000)])

        aos_shards_active_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='Shards.active', statistic="avg")
        aos_shards_activeprimary_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='Shards.activePrimary', statistic="avg")
        aos_active_shards_widget = aws_cloudwatch.GraphWidget(
            title='Active Shards Count',
            height=4, width=12,
            left=[aos_shards_active_metric, aos_shards_activeprimary_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        #######################################################################
        # ClusterIndexWritesBlocked
        #######################################################################
        aos_cluster_index_writes_blocked_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='ClusterIndexWritesBlocked', statistic="avg")
        aos_cluster_index_writes_blocked_widget = aws_cloudwatch.GraphWidget(
            title='ClusterIndexWritesBlocked (Cluster Max Count)',
            height=4, width=12,
            left=[aos_cluster_index_writes_blocked_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            legend_position=aws_cloudwatch.LegendPosition.HIDDEN)
        # Reject count
        aos_threadpool_search_rejected_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='ThreadpoolSearchRejected',
            statistic="sum"
        )
        aos_threadpool_write_rejected_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='ThreadpoolWriteRejected',
            statistic="sum"
        )
        aos_coordinating_write_rejected_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='CoordinatingWriteRejected',
            statistic="sum"
        )
        aos_primary_write_rejected_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='PrimaryWriteRejected',
            statistic="sum"
        )
        aos_replica_write_rejected_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES',
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='ReplicaWriteRejected',
            statistic="sum"
        )
        rejected_search_count_widget = aws_cloudwatch.GraphWidget(
            title='Threadpool Search Rejected Count (Node Total Count)',
            height=4, width=12,
            left=[aos_threadpool_search_rejected_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))
        rejected_indexing_count_widget = aws_cloudwatch.GraphWidget(
            title='Threadpool Indexing Rejected Count (Node Total Count)',
            height=4, width=12,
            left=[aos_threadpool_write_rejected_metric,
                  aos_coordinating_write_rejected_metric,
                  aos_primary_write_rejected_metric,
                  aos_replica_write_rejected_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))
        # 40x 50x
        aos_4xx_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES', metric_name='4xx', statistic="sum",
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID})
        aos_5xx_metric = aws_cloudwatch.Metric(
            namespace='AWS/ES', metric_name='5xx', statistic="sum",
            dimensions_map={'DomainName': self.AOS_DOMAIN,
                            'ClientId': cdk.Aws.ACCOUNT_ID})
        aos_4xx_5xx_widget = aws_cloudwatch.GraphWidget(
            title='HTTP requests by error response code (Cluster Total Count)',
            height=4, width=12,
            left=[aos_4xx_metric, aos_5xx_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        #######################################################################
        # OpenSearch Serverless
        #######################################################################
        aoss_title_widget = aws_cloudwatch.TextWidget(
            markdown=f'# OpenSearch Serverless: {self.AOS_DOMAIN} collection',
            height=1, width=24)

        """
        # Strage
        aoss_host_storage_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS', metric_name='HotStorageUsed',
            period=cdk.Duration.minutes(1), statistic='sum',
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID}
        )
        aoss_s3_storage_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS', metric_name='StorageUsedInS3',
            period=cdk.Duration.minutes(1), statistic='sum',
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID})

        aoss_storage_widget = aws_cloudwatch.GraphWidget(
            title='Storage Hot / S3 (Bytes)',
            height=4, width=12,
            left=[aoss_host_storage_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            right=[aoss_s3_storage_metric],
            right_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
        )

        # Documents
        aoss_searchable_docs_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS', metric_name='SearchableDocuments',
            period=cdk.Duration.minutes(1), statistic='sum',
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID}
        )
        aoss_deleted_docsx_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS', metric_name='DeletedDocuments',
            period=cdk.Duration.minutes(1), statistic='sum',
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID})
        aoss_docs_widget = aws_cloudwatch.GraphWidget(
            title='SearchableDocuments / DeletedDocuments (Counts)',
            height=4, width=12,
            left=[aoss_searchable_docs_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            right=[aoss_deleted_docsx_metric],
            right_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
        )
        """

        # 2xx, 3xx
        aoss_2xx_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS', metric_name='2xx',
            period=cdk.Duration.minutes(1), statistic='sum',
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID})

        aoss_3xx_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS', metric_name='3xx',
            period=cdk.Duration.minutes(1), statistic='sum',
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID})

        aoss_2xx_3xx_widget = aws_cloudwatch.GraphWidget(
            title='HTTP requests by response code 2xs, 3xx',
            height=4, width=12,
            left=[aoss_2xx_metric, aoss_3xx_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        # 4xx 5xx
        aoss_4xx_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS', metric_name='4xx',
            period=cdk.Duration.minutes(1), statistic='sum',
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID})

        aoss_5xx_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS', metric_name='5xx',
            period=cdk.Duration.minutes(1), statistic='sum',
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID})

        aoss_4xx_5xx_widget = aws_cloudwatch.GraphWidget(
            title='HTTP requests by error response code 4xx, 5xx',
            height=4, width=12,
            left=[aoss_4xx_metric, aoss_5xx_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        # Read / Write
        # Data Rate
        aoss_ingest_data_rate_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS',
            period=cdk.Duration.minutes(1), statistic="sum",
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='IngestionDataRate')

        aoss_ingest_data_rate_widget = aws_cloudwatch.GraphWidget(
            title=('IngestionDataRate: The indexing rate per second to a '
                   'collection (Bytes/s)'),
            height=4, width=12,
            left=[aoss_ingest_data_rate_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        # OCU search, OCU indexing
        aoss_search_ocu_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS',
            period=cdk.Duration.hours(1), statistic="sum",
            dimensions_map={'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='SearchOCU')

        aoss_search_ocu_widget = aws_cloudwatch.GraphWidget(
            title=('SearchOCU: The number of OCUs used to search collection '
                   'data'),
            height=4, width=12,
            left=[aoss_search_ocu_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        aoss_indexing_ocu_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS',
            period=cdk.Duration.hours(1), statistic="sum",
            dimensions_map={'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='IndexingOCU')

        aoss_indexing_ocu_widget = aws_cloudwatch.GraphWidget(
            title=('IndexingOCU: The number of OCUs used to ingest collection '
                   'data'),
            height=4, width=12,
            left=[aoss_indexing_ocu_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        # Request rate
        aoss_search_req_rate_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS',
            period=cdk.Duration.minutes(1), statistic="sum",
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='SearchRequestRate')

        aoss_search_req_rate_widget = aws_cloudwatch.GraphWidget(
            title=('SearchRequestRate: The total number of search requests '
                   '(Counts/min)'),
            height=4, width=12,
            left=[aoss_search_req_rate_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        aoss_ingest_req_rate_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS',
            period=cdk.Duration.minutes(1), statistic="sum",
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='IngestionRequestRate')

        aoss_ingest_req_rate_widget = aws_cloudwatch.GraphWidget(
            title=('IngestionRequestRate: The total number of bulk write '
                   'operations (Counts/min)'),
            height=4, width=12,
            left=[aoss_ingest_req_rate_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        # Request latency
        aoss_search_req_latency_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS',
            period=cdk.Duration.minutes(1), statistic="avg",
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='SearchRequestLatency')

        aoss_search_req_latency_widget = aws_cloudwatch.GraphWidget(
            title=('SearchRequestLatency: The time to complete a search '
                   'operation (milliseconds)'),
            height=4, width=12,
            left=[aoss_search_req_latency_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        aoss_ingest_req_latency_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS',
            period=cdk.Duration.minutes(1), statistic="avg",
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='IngestionRequestLatency')

        aoss_ingest_req_latency_widget = aws_cloudwatch.GraphWidget(
            title=('IngestionRequestLatency: The time to complete bulk write '
                   'operations (milliseconds)'),
            height=4, width=12,
            left=[aoss_ingest_req_latency_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        # Request errors
        aoss_search_req_errors_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS',
            period=cdk.Duration.minutes(1), statistic="sum", color='#d13212',
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='SearchRequestErrors')

        aoss_search_req_errors_widget = aws_cloudwatch.GraphWidget(
            title=('SearchRequestErrors: The total number of query errors '
                   '(Counts/min)'),
            height=4, width=12,
            left=[aoss_search_req_errors_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        aoss_ingest_req_errors_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS',
            period=cdk.Duration.minutes(1), statistic="sum", color='#d13212',
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='IngestionRequestErrors')

        aoss_ingest_req_errors_widget = aws_cloudwatch.GraphWidget(
            title=('IngestionRequestErrors: The total number of bulk indexing '
                   'request errors (counts)'),
            height=4, width=12,
            left=[aoss_ingest_req_errors_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        # Documents
        aoss_ingest_docs_rate_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS',
            period=cdk.Duration.minutes(1), statistic="sum",
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='IngestionDocumentRate')

        aoss_ingest_docs_rate_widget = aws_cloudwatch.GraphWidget(
            title=('IngestionDocumentRate: The rate per second at which '
                   'documents are being ingested to a collection (Counts)'),
            height=4, width=12,
            left=[aoss_ingest_docs_rate_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        aoss_ingest_docs_errors_metric = aws_cloudwatch.Metric(
            namespace='AWS/AOSS',
            period=cdk.Duration.minutes(1), statistic="sum", color='#d13212',
            dimensions_map={'CollectionName': self.AOS_DOMAIN,
                            'CollectionId': collection_id,
                            'ClientId': cdk.Aws.ACCOUNT_ID},
            metric_name='IngestionDocumentErrors')

        aoss_ingest_docs_errors_widget = aws_cloudwatch.GraphWidget(
            title=('IngestionDocumentErrors: The total number of document '
                   'errors during ingestion (counts)'),
            height=4, width=12,
            left=[aoss_ingest_docs_errors_metric],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False))

        #######################################################################
        # SQS
        #######################################################################
        sqs_widget = aws_cloudwatch.TextWidget(
            markdown='# SQS', height=1, width=24)
        sqs_splitted_log_visible_widget = aws_cloudwatch.GraphWidget(
            title=(f'{self.sqs_aes_siem_splitted_logs.queue_name}: '
                   'NumberOfMessagesReceived (Count)'),
            height=4, width=12,
            left=[(self.sqs_aes_siem_splitted_logs.
                   metric_number_of_messages_received(statistic='sum'))],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            legend_position=aws_cloudwatch.LegendPosition.HIDDEN)
        sqs_dlq_visible_widget = aws_cloudwatch.GraphWidget(
            title=(f'{self.sqs_aes_siem_dlq.queue_name}: '
                   'ApproximateNumberOfMessagesVisible (Count)'),
            height=4, width=12,
            left=[(self.sqs_aes_siem_dlq.
                   metric_approximate_number_of_messages_visible())],
            left_y_axis=aws_cloudwatch.YAxisProps(show_units=False),
            legend_position=aws_cloudwatch.LegendPosition.HIDDEN)

        #######################################################################
        # es-loader-error logs
        #######################################################################
        esloader_log_widget = aws_cloudwatch.TextWidget(
            markdown=('# Lambda Function Logs: '
                      f'{self.lambda_es_loader.function_name}'),
            height=1, width=24)
        esloader_log_critical_widget = aws_cloudwatch.LogQueryWidget(
            title='CRITICAL Logs',
            log_group_names=[
                f'/aws/lambda/{self.lambda_es_loader.function_name}'],
            width=24,
            view=aws_cloudwatch.LogQueryVisualizationType.TABLE,
            query_string="""fields @timestamp, message, s3_key
                | filter level == "CRITICAL"
                | sort @timestamp desc
                | limit 100""")
        esloader_log_error_widget = aws_cloudwatch.LogQueryWidget(
            title='ERROR Logs', width=24,
            log_group_names=[
                f'/aws/lambda/{self.lambda_es_loader.function_name}'],
            view=aws_cloudwatch.LogQueryVisualizationType.TABLE,
            query_string="""fields @timestamp, message, s3_key
                | filter level == "ERROR"
                | sort @timestamp desc
                | limit 100""")
        esloader_log_guide_widget = aws_cloudwatch.TextWidget(
            height=3, width=12,
            markdown=(
                '## Sample query\n'
                'To investigate critical/error log '
                'with CloudWatch Logs Insights\n\n'
                '```\n'
                'fields @timestamp, @message\n'
                '| filter s3_key == "copy s3_key and paste here"\n'
                'OR @requestId == "copy function_request_id and paste here"'
                '```'),)
        esloader_log_exception_error_widget = aws_cloudwatch.LogQueryWidget(
            title='Exception Logs',
            width=24,
            log_group_names=[
                f'/aws/lambda/{self.lambda_es_loader.function_name}'],
            view=aws_cloudwatch.LogQueryVisualizationType.TABLE,
            query_string=r"""fields @timestamp, @message
                | filter @message =~ /^\[ERROR]/
                | filter @message not like /No active exception to reraise/
                # exclude raise without Exception
                | sort @timestamp desc
                | limit 100""")

        # Add Widgets to CloudWatch Dashboard
        cw_dashboard.add_widgets(
            # CloudWatch Alarm
            cwl_alarm_widget,
            cwl_alarm_freespace_widget,
            # esloader_title_widget,
            esloader_title_widget,
            esloader_success_rate_widget, esloader_invocations_widget,
            esloader_duration_widget, esloader_throttles_widget,
            esloader_timeout_widget, esloader_concurrent_widget,
            # aos_title_widget,
            aos_title_widget,
            # aos cluster
            aos_cpu_widget, aos_jvmmem_widget,
            aos_4xx_5xx_widget, aos_active_shards_widget,
            aos_cluster_disk_queue_throttle_widget,
            aos_cluster_index_writes_blocked_widget,
            # aos ebs, instance
            aos_title_widget_read, aos_title_widget_write,
            aos_read_throughput_iops_widget, aos_write_throughput_iops_widget,
            aos_read_latency_queue_widget, aos_write_latency_queue_widget,
            aos_search_widget, aos_indexing_widget,
            aos_searchqueue_widget, aos_writequeue_widget,
            rejected_search_count_widget, rejected_indexing_count_widget,
            # sqs_widget
            sqs_widget,
            sqs_splitted_log_visible_widget, sqs_dlq_visible_widget,
            # esloader_log_widget
            esloader_log_widget,
            esloader_log_critical_widget,
            esloader_log_error_widget,
            esloader_log_guide_widget,
            esloader_log_exception_error_widget,
        )

        cw_dashboard_serverless.add_widgets(
            # esloader_title_widget,
            esloader_title_widget,
            esloader_success_rate_widget, esloader_invocations_widget,
            esloader_duration_widget, esloader_throttles_widget,
            esloader_timeout_widget, esloader_concurrent_widget,
            # aoss_title_widget,
            # aoss_searchable_docs_widget,
            # aoss_docs_widget, aoss_storage_widget,
            aoss_title_widget,
            aoss_2xx_3xx_widget, aos_title_widget_write,
            aoss_4xx_5xx_widget, aoss_ingest_data_rate_widget,
            white_panel_widget, aoss_ingest_docs_rate_widget,
            aos_title_widget_read, aoss_ingest_docs_errors_widget,
            aoss_search_ocu_widget, aoss_indexing_ocu_widget,
            aoss_search_req_rate_widget, aoss_ingest_req_rate_widget,
            aoss_search_req_latency_widget, aoss_ingest_req_latency_widget,
            aoss_search_req_errors_widget, aoss_ingest_req_errors_widget,
            # sqs_widget
            sqs_widget,
            sqs_splitted_log_visible_widget, sqs_dlq_visible_widget,
            # esloader_log_widget
            esloader_log_widget,
            esloader_log_critical_widget,
            esloader_log_error_widget,
            esloader_log_guide_widget,
            esloader_log_exception_error_widget,
        )
