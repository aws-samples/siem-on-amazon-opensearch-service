# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def transform(logdata):
    try:
        logdata['dns']['question']['name'] = (
            logdata['dns']['question']['name'].rstrip('.'))
    except KeyError:
        pass
    try:
        logdata['dns']['answers']['data'] = (
            logdata['dns']['answers']['data'].rstrip('.'))
    except KeyError:
        pass

    return logdata
