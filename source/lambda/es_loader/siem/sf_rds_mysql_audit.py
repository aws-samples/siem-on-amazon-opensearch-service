# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'

from siem import utils


def transform(logdata):
    identifier = utils.cluster_instance_identifier(logdata)
    logdata['rds']['cluster_identifier'] = identifier['cluster']
    logdata['rds']['instance_identifier'] = identifier['instance']

    logdata['mysql_timestamp'] = utils.convrt_micro_epoch_to_seconds_epoch(
        logdata['mysql_timestamp'])

    if 'mysql_object' in logdata:
        logdata['rds']['query'] = logdata['mysql_object'].rstrip(';').encode(
            "utf-8").decode("unicode-escape")[1:-1]

    if 'mysql_operation' in logdata:
        if logdata['mysql_operation'] in ('FAILED_CONNECT', ):
            logdata['event']['category'] = 'authentication'
            logdata['event']['type'] = 'start'
            logdata['event']['action'] = 'failed'
        if logdata['mysql_operation'] in ('CONNECT', ):
            logdata['event']['category'] = 'authentication'
            logdata['event']['type'] = 'start'
            logdata['event']['action'] = 'authorized'
        if logdata['mysql_operation'] in ('DISCONNECT', ):
            logdata['event']['category'] = 'authentication'
            logdata['event']['type'] = 'end'
            logdata['event']['action'] = 'disconnected'

    if 'mysql_retcode' in logdata:
        if logdata['mysql_retcode'] == 0:
            logdata['event']['outcome'] = 'success'
        else:
            logdata['event']['outcome'] = 'failure'

    logdata = utils.convert_underscore_field_into_dot_notation(
        'mysql', logdata)

    return logdata
