# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.5.1-beta.2'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def transform(logdata):
    if logdata.get('ClientAddress'):
        logdata['ClientAddress'], port = logdata[
            'ClientAddress'].rsplit(':', 1)
        logdata['source'] = {}
        logdata['source']['ip'] = logdata['ClientAddress']
        logdata['source']['port'] = port
        if 'related' not in logdata:
            logdata['related'] = {}
        logdata['source']['address'] = logdata['ClientAddress']
        logdata['related']['ip'] = [logdata['ClientAddress'], ]

    return logdata
