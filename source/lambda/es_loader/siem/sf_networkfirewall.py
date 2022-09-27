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
        # event.proto: TCP, UDP, ICMP
        logdata['network']['transport'] = logdata['event']['proto'].lower()
    except KeyError:
        pass

    if logdata['event']['event_type'] == 'alert':
        logdata['event']['kind'] = 'alert'
        logdata['event']['category'] = 'intrusion_detection'

    return logdata
