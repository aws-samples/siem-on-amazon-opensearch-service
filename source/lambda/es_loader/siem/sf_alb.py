# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

def transform(logdata):
    logdata['url']['full'] = logdata['request'].split(' ')[1]
    return logdata
