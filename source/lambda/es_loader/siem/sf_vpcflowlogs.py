# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
__copyright__ = ('Copyright Amazon.com, Inc. or its affiliates. '
                 'All Rights Reserved.')
__version__ = '2.8.0c'
__license__ = 'MIT-0'
__author__ = 'Akihiro Nakajima'
__url__ = 'https://github.com/aws-samples/siem-on-amazon-opensearch-service'


def transform(logdata):
    action = logdata['event']['action']
    if 'ACCEPT' in action:
        logdata['event']['outcome'] = 'success'
    elif 'REJECT' in action:
        logdata['event']['outcome'] = 'failure'
    else:
        logdata['event']['outcome'] = 'unknown'

    protocol = logdata.get('protocol')
    if protocol == "6":
        logdata['network']['transport'] = 'tcp'
    elif protocol == "17":
        logdata['network']['transport'] = 'udp'
    elif protocol == "1":
        logdata['network']['transport'] = 'icmp'
    elif protocol == "41":
        logdata['network']['transport'] = 'ipv6'
    elif protocol == "8":
        logdata['network']['transport'] = 'egp'
    elif protocol == "33":
        logdata['network']['transport'] = 'dccp'
    elif protocol == "42":
        logdata['network']['transport'] = 'sdrp'
    elif protocol == "47":
        logdata['network']['transport'] = 'gre'
    elif protocol == "132":
        logdata['network']['transport'] = 'sctp'

    try:
        logdata['network']['type'] = logdata['network']['type'].lower()
    except KeyError:
        pass

    return logdata
