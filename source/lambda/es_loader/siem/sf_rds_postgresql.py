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
RE_AUTH_FAILED = re.compile('authentication failed')
RE_AUTH_SUCCESS = re.compile('connection authorized')
RE_SESSION_TIME = re.compile(
    r'disconnection: session time: (\d+):(\d{2}):([\d.]+)')
RE_STETEMENT = re.compile(r'^statement:\s+(\w+.*)')
RE_DURATION = re.compile(
    r'^duration:\s+(?P<duration>[\d.]+)\s+ms'
    r'(\s*(?P<step>(parse|bind|execute))?.*?:\s+(?P<statement>.*))?')


def extract_slow_log(logdata):
    m_statement = RE_STETEMENT.match(logdata['postgresql']['message'])
    if m_statement:
        logdata['rds']['query'] = m_statement.group(1).rstrip(';')
        logdata['postgresql']['query_step'] = 'execute'
        return logdata
    m_duration = RE_DURATION.match(logdata['postgresql']['message'])
    # duration: 0.117 ms  bind <unnamed>: SELECT 1
    # duration: 0.026 ms
    if m_duration:
        duration_ms = float(m_duration.group('duration'))
        logdata['postgresql']['duration_ms'] = duration_ms
        logdata['rds']['query_time'] = duration_ms / 1000
        query_step = m_duration.group('step')
        if query_step:
            logdata['postgresql']['query_step'] = query_step
            logdata['rds']['query'] = m_duration.group('statement')
        else:
            logdata['postgresql']['query_step'] = 'execute'

    return logdata


def transform(logdata):
    logdata = utils.convert_underscore_field_into_dot_notation(
        'postgresql', logdata)
    identifier = utils.cluster_instance_identifier(logdata)
    logdata['rds']['cluster_identifier'] = identifier['cluster']
    logdata['rds']['instance_identifier'] = identifier['instance']

    if 'log_level' in logdata['postgresql']:
        if logdata['postgresql']['log_level'] in ('STATEMENT', ):
            logdata['rds']['query'] = logdata['postgresql']['message']
            return logdata
        elif logdata['postgresql']['log_level'] in ('FATAL', ):
            m_failed = RE_AUTH_FAILED.search(logdata['postgresql']['message'])
            if m_failed:
                logdata['event']['category'] = 'authentication'
                logdata['event']['type'] = 'start'
                logdata['event']['action'] = 'failed'
                logdata['event']['outcome'] = 'failure'
                return logdata
        elif logdata['postgresql']['log_level'] in ('LOG', ):
            m_success = RE_AUTH_SUCCESS.search(
                logdata['postgresql']['message'])
            if m_success:
                logdata['event']['category'] = 'authentication'
                logdata['event']['type'] = 'start'
                logdata['event']['action'] = 'authorized'
                logdata['event']['outcome'] = 'success'
                return logdata
            m_session = RE_SESSION_TIME.match(logdata['postgresql']['message'])
            if m_session:
                hours = int(m_session.group(1))
                minutes = int(m_session.group(2))
                seconds = float(m_session.group(3))
                m_session_time = seconds
                if hours > 0:
                    m_session_time += hours * 60 * 24
                if minutes > 0:
                    m_session_time += minutes * 60
                logdata['postgresql']['session_time_seconds'] = m_session_time
                return logdata
            logdata = extract_slow_log(logdata)

    return logdata
