# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

from siem import utils


def transform(logdata):
    identifier = utils.cluster_instance_identifier(logdata)
    logdata['rds']['cluster_identifier'] = identifier['cluster']
    logdata['rds']['instance_identifier'] = identifier['instance']

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
