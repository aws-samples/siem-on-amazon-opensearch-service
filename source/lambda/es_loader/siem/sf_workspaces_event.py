# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

def transform(logdata):
    if 'workspaceId' in logdata:
        logdata['WorkspaceId'] = logdata['workspaceId']
        del logdata['workspaceId']
    return logdata
