# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

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
