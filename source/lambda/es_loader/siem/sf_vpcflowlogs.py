# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

def transform(logdata):
    action = logdata['event']['action']
    if 'ACCEPT' in action:
        logdata['event']['outcome'] = 'success'
    elif 'REJECT' in action:
        logdata['event']['outcome'] = 'failure'
    else:
        logdata['event']['outcome'] = 'unknown'
    return logdata
