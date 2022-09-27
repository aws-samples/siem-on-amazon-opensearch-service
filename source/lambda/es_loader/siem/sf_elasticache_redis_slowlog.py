# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def transform(logdata):
    if logdata.get('ClientAddress'):
        ip, port = logdata['ClientAddress'].rsplit(':', 1)
        logdata['source'] = {}
        logdata['source']['ip'] = ip
        logdata['source']['port'] = port
        logdata['source']['address'] = ip
        if 'related' not in logdata:
            logdata['related'] = {}
        logdata['related']['ip'] = [ip, ]

    return logdata
