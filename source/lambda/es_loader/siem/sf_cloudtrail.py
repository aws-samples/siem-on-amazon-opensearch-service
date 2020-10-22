# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0


def transform(logdata):
    if 'errorCode' in logdata or 'errorMessage' in logdata:
        logdata['event']['outcome'] = 'failure'
    else:
        logdata['event']['outcome'] = 'success'
    try:
        name = logdata['user']['name']
        if ':' in name:
            logdata['user']['name'] = name.split(':')[-1].split('/')[-1]
    except KeyError:
        pass
    return logdata
