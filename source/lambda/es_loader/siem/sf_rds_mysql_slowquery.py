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

# REGEXP
RE_DATABASE = re.compile(r'^use ([^ ]*?);')
RE_QUERY = re.compile(
    r'^(?!(use|set))[\s\S]*', flags=(re.MULTILINE | re.IGNORECASE))


def transform(logdata):
    identifier = utils.cluster_instance_identifier(logdata)
    logdata['rds']['cluster_identifier'] = identifier['cluster']
    logdata['rds']['instance_identifier'] = identifier['instance']
    logdata['rds']['query_time'] = logdata['mysql_query_time']

    m_db = RE_DATABASE.match(logdata['mysql_query'])
    if m_db:
        logdata['rds']['database_name'] = m_db.group(1)

    m_query = RE_QUERY.search(logdata['mysql_query'])
    if m_query:
        logdata['rds']['query'] = m_query.group().rstrip(';')

    logdata = utils.convert_underscore_field_into_dot_notation(
        'mysql', logdata)
    return logdata
