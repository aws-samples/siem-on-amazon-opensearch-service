# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

def transform(logdata):
    headers = logdata['httpRequest']['headers']
    if len(headers) > 0:
        for header in headers:
            if header['name'] == "Host":
                logdata['url']['domain'] = header['value']
            if header['name'] == "User-Agent":
                logdata['user_agent'] = {}
                logdata['user_agent']['original'] = header['value']
            if header['name'] == "Referer":
                logdata['http']['request']['referrer'] = header['value']
    try:
        # WAFv2
        logdata['rule']['ruleset'] = logdata['webaclId'].split('/')[2]
        region_type = logdata['webaclId'].split(':')[5].split('/')[0]
        if region_type == 'global':
            logdata['cloud']['region'] = 'global'
        else:
            logdata['cloud']['region'] = logdata['webaclId'].split(':')[3]
        logdata['cloud']['account'] = {'id': logdata['webaclId'].split(':')[4]}
    except IndexError:
        # WAFv1
        logdata['rule']['ruleset'] = logdata['webaclId']
    logdata['http']['version'] = (logdata['httpRequest']
                                  ['httpVersion'].split('/')[1])
    # action = logdata.get('action')
    # if 'ALLOW' in action:
    #     logdata['event']['outcome'] = 'success'
    # elif 'BLOCK' in action:
    #     logdata['event']['outcome'] = 'failure'
    # else:
    #     logdata['event']['outcome'] = 'unknown'
    return logdata
