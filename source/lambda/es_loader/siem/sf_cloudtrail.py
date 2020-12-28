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

    # https://github.com/aws-samples/siem-on-amazon-elasticsearch/issues/33
    try:
        response_cred = logdata['responseElements']['credentials']
    except (KeyError, TypeError):
        response_cred = None
    if isinstance(response_cred, str):
        logdata['responseElements']['credentials'] = {}
        if 'arn:aws:iam' in response_cred:
            logdata['responseElements']['credentials']['iam'] = response_cred
        else:
            logdata['responseElements']['credentials']['value'] = response_cred

    return logdata
