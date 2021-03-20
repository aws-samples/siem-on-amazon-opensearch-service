# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

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
