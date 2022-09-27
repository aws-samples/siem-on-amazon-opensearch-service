# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

import re

from siem import utils

RE_CLUSTER = re.compile(r'/([\w-]+)-(\w{8}-\w{4}-\w{4}-\w{4}-\w{12}-\w{1})/'
                        r'.*/Broker-(\d+)_')
RE_CONSUMER_LAG = re.compile(
    r'ConsumerLag for groupId=([\w.-]+) topic=([\w.-]+) : SumLag=(\d+) '
    r'MaxLag=(\d+) TimeLag=(\d+)')
# ConsumerLag for groupId=amazon.msk.canary.group.broker-2 topic=canary :
# SumLag=3 MaxLag=1 TimeLag=60 (xxxxxxxxxxxx)


def transform(logdata):
    m_s3 = RE_CLUSTER.search(logdata['@log_s3key'])
    if m_s3:
        logdata['msk_cluster_name'] = m_s3.group(1)
        logdata['msk_broker_id'] = m_s3.group(3)
    m_consumer = RE_CONSUMER_LAG.match(logdata['msk_message'])
    if m_consumer:
        logdata['msk_log_type'] = 'ConsumerLag'
        logdata['msk_group_id'] = m_consumer.group(1)
        logdata['msk_topic'] = m_consumer.group(2)
        logdata['msk_sum_lag'] = m_consumer.group(3)
        logdata['msk_max_lag'] = m_consumer.group(4)
        logdata['msk_time_lag'] = m_consumer.group(5)
    logdata = utils.convert_underscore_field_into_dot_notation('msk', logdata)
    return logdata
