# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

def transform(logdata):
    try:
        logdata['url']['full'] = logdata['request'].split(' ')[1]
    except KeyError:
        pass
    return logdata
