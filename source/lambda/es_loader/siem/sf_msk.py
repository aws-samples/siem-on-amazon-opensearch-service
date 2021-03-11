# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import re

RE_CLUSTER = re.compile(r'/([\w-]+)-(\w{8}-\w{4}-\w{4}-\w{4}-\w{12}-\w{1})/'
                        r'.*/Broker-(\d+)_')
RE_CONSUMER_LAG = re.compile(
    r'ConsumerLag for groupId=([\w.-]+) topic=([\w.-]+) : SumLag=(\d+) '
    r'MaxLag=(\d+) TimeLag=(\d+)')
# ConsumerLag for groupId=amazon.msk.canary.group.broker-2 topic=canary :
# SumLag=3 MaxLag=1 TimeLag=60 (xxxxxxxxxxxx)


def convert_underscore_field_into_dot_notation(prefix, logdata):
    if not prefix:
        return logdata
    if prefix not in logdata:
        logdata[prefix] = dict()
    prefix_underscore = prefix + '_'
    underscore_fields = []
    for field in logdata:
        if field.startswith(prefix_underscore):
            underscore_fields.append(field)
    for underscore_field in underscore_fields:
        new_key = underscore_field.replace(prefix_underscore, '')
        logdata[prefix][new_key] = logdata[underscore_field]
        del logdata[underscore_field]
    return logdata


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
    logdata = convert_underscore_field_into_dot_notation('msk', logdata)
    return logdata
