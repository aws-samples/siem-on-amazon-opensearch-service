# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def transform(logdata):
    action = logdata.get('audit_category')
    if action in ('GRANTED_PRIVILEGES', 'AUTHENTICATED'):
        logdata['event']['outcome'] = 'success'
    elif action in ('MISSING_PRIVILEGES', 'FAILED_LOGIN'):
        logdata['event']['outcome'] = 'failure'
    else:
        # INDEX_EVENT, OPENDISTRO_SECURITY_INDEX_ATTEMPT
        logdata['event']['outcome'] = 'unknown'

    # logdata.get('audit_rest_request_path') == '/_plugins/_security/authinfo'
    if action in ('FAILED_LOGIN', 'AUTHENTICATED'):
        logdata['event']['category'].append('authentication')

    if not logdata.get('rule', {}).get('name'):
        if 'rule' not in logdata:
            logdata['rule'] = {}
        logdata['rule']['name'] = 'ParsingError'
        if len(logdata['@message']) == 10000:
            if 'error' not in logdata:
                logdata['error'] = {}
            logdata['error']['message'] = (
                'The maximum size of each audit log message is 10,000 '
                'characters. The audit log message exceeds this limit and '
                'is truncated.')

    return logdata
